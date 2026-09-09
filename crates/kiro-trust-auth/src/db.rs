//! Read-only access to the Kiro CLI database (spec 6.1, 7.2). One
//! constructor, one authorizer, two tables.

use crate::error::AuthError;
use kiro_trust_net::{Region, RuntimeRegion};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, OpenFlags};
use secrecy::SecretString;
use serde_json::Value;
use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TOKEN_KEYS: &[&str] = &["kirocli:odic:token", "kirocli:oidc:token"];
const SOCIAL_KEYS: &[&str] = &["kirocli:social:token"];
const REGISTRATION_KEYS: &[&str] = &[
    "kirocli:odic:device-registration",
    "kirocli:oidc:device-registration",
    "kirocli:odic:device_registration",
    "kirocli:oidc:device_registration",
];

#[derive(Clone)]
pub struct Credentials {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    pub client_id: String,
    pub client_secret: SecretString,
    pub expires_at: SystemTime,
    pub sso_region: Region,
    pub runtime_region: RuntimeRegion,
    pub profile_arn: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Credentials {{ sso_region: {}, runtime_region: {}, expires_at: {:?} }}",
            self.sso_region, self.runtime_region, self.expires_at
        )
    }
}

pub struct KiroDb {
    pub(crate) conn: Connection,
}

fn authorize(ctx: AuthContext<'_>) -> Authorization {
    match ctx.action {
        AuthAction::Select => Authorization::Allow,
        AuthAction::Read {
            table_name: "auth_kv" | "state" | "sqlite_master",
            ..
        } => Authorization::Allow,
        AuthAction::Pragma {
            pragma_name: "query_only",
            ..
        } => Authorization::Allow,
        _ => Authorization::Deny,
    }
}

impl KiroDb {
    pub fn open_read_only(path: &Path) -> Result<Self, AuthError> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn =
            Connection::open_with_flags(path, flags).map_err(|e| AuthError::Open(e.to_string()))?;
        conn.pragma_update(None, "query_only", true)
            .map_err(|e| AuthError::Open(e.to_string()))?;
        conn.authorizer(Some(authorize))
            .map_err(|e| AuthError::Open(e.to_string()))?;
        Ok(KiroDb { conn })
    }

    fn auth_kv(&self, keys: &[&str]) -> Result<Option<String>, AuthError> {
        for key in keys {
            let value: Option<String> = self
                .conn
                .query_row("SELECT value FROM auth_kv WHERE key = ?1", [key], |r| {
                    r.get(0)
                })
                .ok();
            if let Some(v) = value {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    fn state(&self, key: &str) -> Option<String> {
        let raw: Option<String> = self
            .conn
            .query_row("SELECT value FROM state WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .ok();
        raw.map(|v| match serde_json::from_str::<Value>(&v) {
            Ok(Value::String(s)) => s,
            _ => v,
        })
    }

    pub fn read_identity_center(&self) -> Result<Credentials, AuthError> {
        let token_json = match self.auth_kv(TOKEN_KEYS)? {
            Some(t) => t,
            None if self.auth_kv(SOCIAL_KEYS)?.is_some() => {
                return Err(AuthError::Unsupported("social login"));
            }
            None => return Err(AuthError::NoCredentials),
        };
        let token: Value =
            serde_json::from_str(&token_json).map_err(|_| AuthError::BadTokenJson)?;
        let pick = |v: &Value, camel: &str, snake: &str| -> Option<String> {
            v.get(camel)
                .or_else(|| v.get(snake))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        let access = pick(&token, "accessToken", "access_token").ok_or(AuthError::BadTokenJson)?;
        let refresh =
            pick(&token, "refreshToken", "refresh_token").ok_or(AuthError::BadTokenJson)?;
        let expires_at =
            parse_expires_at(token.get("expiresAt").or_else(|| token.get("expires_at")))
                .unwrap_or(UNIX_EPOCH);
        let token_region = pick(&token, "region", "region");

        let reg_json = self
            .auth_kv(REGISTRATION_KEYS)?
            .ok_or(AuthError::MissingDeviceRegistration)?;
        let reg: Value =
            serde_json::from_str(&reg_json).map_err(|_| AuthError::MissingDeviceRegistration)?;
        let client_id =
            pick(&reg, "clientId", "client_id").ok_or(AuthError::MissingDeviceRegistration)?;
        let client_secret = pick(&reg, "clientSecret", "client_secret")
            .ok_or(AuthError::MissingDeviceRegistration)?;

        let state_region = self.state("auth.idc.region");
        let profile_raw = self.state("api.codewhisperer.profile").unwrap_or_default();
        let profile_arn = match serde_json::from_str::<Value>(&profile_raw) {
            Ok(v) if v.get("arn").and_then(Value::as_str).is_some() => {
                v["arn"].as_str().unwrap().to_string()
            }
            _ => profile_raw,
        };

        let sso_region = Region::parse(
            token_region
                .as_deref()
                .or(state_region.as_deref())
                .ok_or(AuthError::NoSsoRegion)?,
        )?;
        let arn_region = profile_arn
            .split(':')
            .nth(3)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let runtime_region = [
            token_region.as_deref(),
            arn_region.as_deref(),
            state_region.as_deref(),
        ]
        .into_iter()
        .flatten()
        .find_map(|c| RuntimeRegion::parse(c).ok())
        .ok_or(AuthError::NoRuntimeRegion)?;

        Ok(Credentials {
            access_token: SecretString::from(access),
            refresh_token: SecretString::from(refresh),
            client_id,
            client_secret: SecretString::from(client_secret),
            expires_at,
            sso_region,
            runtime_region,
            profile_arn,
        })
    }
}

/// Unix seconds as number or numeric string, or RFC 3339 (spec 7.2).
fn parse_expires_at(v: Option<&Value>) -> Option<SystemTime> {
    let secs = match v? {
        Value::Number(n) => n.as_f64()?,
        Value::String(s) => {
            if let Ok(i) = s.parse::<i64>() {
                i as f64
            } else if let Ok(f) = s.parse::<f64>() {
                f
            } else {
                let dt =
                    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                        .ok()?;
                dt.unix_timestamp() as f64
            }
        }
        _ => return None,
    };
    if secs <= 0.0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs_f64(secs))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rusqlite::Connection;
    use secrecy::ExposeSecret;

    /// Build a database with the real schema shape (spec 7.2) and arbitrary
    /// rows. Values here are placeholders, never real credentials.
    pub(crate) fn make_db(
        dir: &std::path::Path,
        auth_kv: &[(&str, &str)],
        state: &[(&str, &str)],
    ) -> std::path::PathBuf {
        let path = dir.join("data.sqlite3");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT);
             CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB);
             CREATE TABLE history (id INTEGER PRIMARY KEY, command TEXT);
             CREATE TABLE conversations (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO history (command) VALUES ('secret shell command');",
        )
        .unwrap();
        for (k, v) in auth_kv {
            conn.execute("INSERT INTO auth_kv (key, value) VALUES (?1, ?2)", (k, v))
                .unwrap();
        }
        for (k, v) in state {
            conn.execute("INSERT INTO state (key, value) VALUES (?1, ?2)", (k, v))
                .unwrap();
        }
        path
    }

    const TOKEN_SNAKE: &str = r#"{"access_token":"placeholder-access","refresh_token":"placeholder-refresh","expires_at":"2026-09-08T14:27:34.854803Z","region":"ap-southeast-1"}"#;
    const TOKEN_CAMEL: &str = r#"{"accessToken":"placeholder-access","refreshToken":"placeholder-refresh","expiresAt":1893456000,"region":"us-east-1"}"#;
    const REG: &str = r#"{"clientId":"placeholder-client","clientSecret":"placeholder-secret"}"#;
    const PROFILE: &str = r#"{"arn":"arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE","profile_name":"KiroProfile-us-east-1"}"#;

    #[test]
    fn reads_identity_center_credentials_in_both_spellings() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_db(
            dir.path(),
            &[
                ("kirocli:odic:token", TOKEN_SNAKE),
                ("kirocli:odic:device-registration", REG),
            ],
            &[
                ("auth.idc.region", "\"ap-southeast-1\""),
                ("api.codewhisperer.profile", PROFILE),
            ],
        );
        let c = KiroDb::open_read_only(&path)
            .unwrap()
            .read_identity_center()
            .unwrap();
        assert_eq!(c.access_token.expose_secret(), "placeholder-access");
        assert_eq!(c.refresh_token.expose_secret(), "placeholder-refresh");
        assert_eq!(c.client_id, "placeholder-client");
        assert_eq!(c.client_secret.expose_secret(), "placeholder-secret");
        assert_eq!(c.sso_region.as_str(), "ap-southeast-1");
        assert_eq!(
            c.runtime_region.as_str(),
            "us-east-1",
            "token region is not served; ARN region wins"
        );
        assert_eq!(
            c.profile_arn,
            "arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE"
        );
        let secs = c
            .expires_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(secs, 1_788_877_654, "RFC 3339 with fractional seconds");

        let dir = tempfile::tempdir().unwrap();
        let path = make_db(
            dir.path(),
            &[
                ("kirocli:oidc:token", TOKEN_CAMEL),
                ("kirocli:oidc:device_registration", REG),
            ],
            &[(
                "api.codewhisperer.profile",
                "arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE",
            )],
        );
        let c = KiroDb::open_read_only(&path)
            .unwrap()
            .read_identity_center()
            .unwrap();
        assert_eq!(c.sso_region.as_str(), "us-east-1");
        assert_eq!(c.runtime_region.as_str(), "us-east-1");
        assert_eq!(
            c.expires_at
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_893_456_000
        );
    }

    #[test]
    fn debug_never_prints_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_db(
            dir.path(),
            &[
                ("kirocli:odic:token", TOKEN_SNAKE),
                ("kirocli:odic:device-registration", REG),
            ],
            &[("api.codewhisperer.profile", PROFILE)],
        );
        let c = KiroDb::open_read_only(&path)
            .unwrap()
            .read_identity_center()
            .unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("placeholder"));
        assert!(!dbg.contains("000000000000"));
        assert!(dbg.contains("ap-southeast-1"));
    }

    #[test]
    fn unsupported_and_incomplete_credentials_fail_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_db(dir.path(), &[("kirocli:social:token", TOKEN_SNAKE)], &[]);
        assert!(matches!(
            KiroDb::open_read_only(&path)
                .unwrap()
                .read_identity_center(),
            Err(AuthError::Unsupported(_))
        ));
        let dir = tempfile::tempdir().unwrap();
        let path = make_db(
            dir.path(),
            &[("kirocli:odic:token", TOKEN_SNAKE)],
            &[("api.codewhisperer.profile", PROFILE)],
        );
        assert!(matches!(
            KiroDb::open_read_only(&path)
                .unwrap()
                .read_identity_center(),
            Err(AuthError::MissingDeviceRegistration)
        ));
        let dir = tempfile::tempdir().unwrap();
        let path = make_db(dir.path(), &[], &[]);
        assert!(matches!(
            KiroDb::open_read_only(&path)
                .unwrap()
                .read_identity_center(),
            Err(AuthError::NoCredentials)
        ));
        let dir = tempfile::tempdir().unwrap();
        let path = make_db(
            dir.path(),
            &[
                ("kirocli:odic:token", TOKEN_SNAKE),
                ("kirocli:odic:device-registration", REG),
            ],
            &[],
        );
        assert!(matches!(
            KiroDb::open_read_only(&path)
                .unwrap()
                .read_identity_center(),
            Err(AuthError::NoRuntimeRegion)
        ));
        assert!(matches!(
            KiroDb::open_read_only(std::path::Path::new("/nonexistent/data.sqlite3")),
            Err(AuthError::Open(_))
        ));
    }

    // spec 8.4 open_writable_is_impossible, only_auth_tables_are_readable
    #[test]
    fn open_writable_is_impossible() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_db(dir.path(), &[("kirocli:odic:token", TOKEN_SNAKE)], &[]);
        let db = KiroDb::open_read_only(&path).unwrap();
        let err = db
            .conn
            .execute("UPDATE auth_kv SET value = 'x'", [])
            .unwrap_err();
        assert!(
            format!("{err}").contains("not authorized") || format!("{err}").contains("readonly"),
            "{err}"
        );
        assert!(db.conn.execute("CREATE TABLE t (x)", []).is_err());
        assert!(
            db.conn
                .execute("INSERT INTO auth_kv (key, value) VALUES ('a', 'b')", [])
                .is_err()
        );
        assert!(db.conn.execute("DELETE FROM auth_kv", []).is_err());
    }

    #[test]
    fn only_auth_tables_are_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = make_db(dir.path(), &[("kirocli:odic:token", TOKEN_SNAKE)], &[]);
        let db = KiroDb::open_read_only(&path).unwrap();
        assert!(db.conn.prepare("SELECT command FROM history").is_err());
        assert!(db.conn.prepare("SELECT value FROM conversations").is_err());
        assert!(db.conn.prepare("SELECT key FROM auth_kv").is_ok());
        assert!(db.conn.prepare("SELECT key FROM state").is_ok());
    }
}
