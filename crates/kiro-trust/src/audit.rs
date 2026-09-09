//! `kiro-trust audit` (spec 4.2, 6.6). Reads the database read-only, never
//! touches the network, never prints an ARN, an account id, or a secret.
//!
//! No network call is made anywhere in this file: the only network-capable
//! type in the dependency graph is `kiro_trust_net::Client`, which this
//! module never constructs or imports, and `KiroDb::read_identity_center`
//! only reads rows already in the database (it never refreshes a token,
//! which is the one path in this workspace that calls the network).

use crate::config::{AuditArgs, parse_listen, resolve_db_path, resolve_token_file};
use kiro_trust_auth::KiroDb;
use kiro_trust_net::{Destination, RuntimeRegion};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;

#[derive(Serialize, Default)]
pub struct CredentialSource {
    pub path: String,
    pub mode: String,
}

#[derive(Serialize, Default)]
pub struct Authentication {
    #[serde(rename = "type")]
    pub kind: String,
    pub sso_region: String,
    pub token_expires: String,
}

#[derive(Serialize, Default)]
pub struct Runtime {
    pub region: String,
    pub source: String,
}

#[derive(Serialize, Default)]
pub struct AuditReport {
    pub version: String,
    pub commit: String,
    pub credential_source: CredentialSource,
    pub authentication: Authentication,
    pub runtime: Runtime,
    pub allowed_outbound: Vec<String>,
    pub tls_roots: String,
    pub http_proxy: String,
    pub redirects: String,
    pub local_listener: String,
    pub local_authentication: String,
    pub telemetry: String,
    pub content_sharing: String,
    pub request_body_logging: String,
    pub dynamic_model_discovery: String,
    pub automatic_updates: String,
    pub build_features: Vec<String>,
    pub problems: Vec<String>,
}

pub fn report(args: &AuditArgs) -> Result<AuditReport, String> {
    let mut problems = Vec::new();
    let listener = match parse_listen(&args.listen) {
        Ok(a) => a.to_string(),
        Err(e) => {
            problems.push(e.to_string());
            args.listen.clone()
        }
    };
    let db_path = resolve_db_path(args.kiro_db.clone()).map_err(|e| e.to_string())?;
    // Resolved but, per spec 6.6, never printed: `local_authentication` is a
    // fixed description of the guarantee, not a report of where this
    // particular run would write a token (audit never writes one). Keeping
    // the call validates that a token directory can be determined at all,
    // the same config-error class `serve` fails on at startup.
    let _token_file = resolve_token_file(args.token_file.clone()).map_err(|e| e.to_string())?;
    let creds = KiroDb::open_read_only(&db_path).and_then(|db| db.read_identity_center());
    let (auth, runtime, outbound) = match &creds {
        Ok(c) => {
            let (region, source) = match args.runtime_region.as_deref().map(RuntimeRegion::parse) {
                Some(Ok(r)) => (r, "from --runtime-region".to_string()),
                Some(Err(e)) => {
                    problems.push(e.to_string());
                    (c.runtime_region.clone(), "from profile".to_string())
                }
                None => (c.runtime_region.clone(), "from profile".to_string()),
            };
            let expires = time::OffsetDateTime::from(c.expires_at)
                .format(&Rfc3339)
                .unwrap_or_else(|_| "unknown".into());
            (
                Authentication {
                    kind: "AWS IAM Identity Center".into(),
                    sso_region: c.sso_region.to_string(),
                    token_expires: format!("{expires} (refresh on demand)"),
                },
                Runtime {
                    region: region.to_string(),
                    source,
                },
                vec![
                    Destination::Oidc {
                        sso_region: c.sso_region.clone(),
                    }
                    .host(),
                    Destination::Runtime { region }.host(),
                ],
            )
        }
        Err(e) => {
            problems.push(format!("credential: {e}"));
            (
                Authentication {
                    kind: "unavailable".into(),
                    sso_region: "-".into(),
                    token_expires: "-".into(),
                },
                Runtime {
                    region: "-".into(),
                    source: "-".into(),
                },
                vec![],
            )
        }
    };
    let mut build_features = Vec::new();
    // `capture` is a feature of this binary crate, so `cfg!` here reports
    // this crate's own compiled features directly (task-20-rulings.md
    // ruling 5).
    if cfg!(feature = "capture") {
        build_features.push("capture".to_string());
    }
    // `test-endpoints` belongs to `kiro-trust-net`, not this crate, so the
    // constant is read from `kiro_trust_net` rather than evaluated with
    // `cfg!` here: a `cfg!(feature = "test-endpoints")` in this crate would
    // check this crate's own (nonexistent) feature of that name, not
    // whether `kiro-trust-net` itself was built with it, and would miss the
    // feature being unified in through `kiro-trust-tests` in a
    // workspace-wide build (task-20-rulings.md ruling 5; CLAUDE.md
    // Architecture rules).
    if kiro_trust_net::TEST_ENDPOINTS_COMPILED {
        build_features.push("test-endpoints".to_string());
    }
    for f in &build_features {
        problems.push(format!("development feature {f} is compiled in"));
    }
    Ok(AuditReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("KIRO_TRUST_COMMIT").to_string(),
        credential_source: CredentialSource {
            path: db_path.display().to_string(),
            mode: "read-only, authorizer enforced".into(),
        },
        authentication: auth,
        runtime,
        allowed_outbound: outbound,
        tls_roots: "webpki-roots (compiled in)".into(),
        http_proxy: "disabled (environment ignored)".into(),
        redirects: "rejected".into(),
        local_listener: listener,
        local_authentication: "required (token file 0600)".into(),
        telemetry: "none".into(),
        content_sharing: if args.share_content {
            "enabled (--share-content)".into()
        } else {
            "opted out (x-amzn-codewhisperer-optout: true)".into()
        },
        request_body_logging: "disabled (no flag exists)".into(),
        dynamic_model_discovery: "disabled".into(),
        automatic_updates: "disabled".into(),
        build_features,
        problems,
    })
}

pub fn render_text(r: &AuditReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("kiro-trust {} ({})\n\n", r.version, r.commit));
    s.push_str(&format!(
        "Credential source\n  Kiro CLI SQLite      {}\n  mode                 {}\n\n",
        r.credential_source.path, r.credential_source.mode
    ));
    s.push_str(&format!(
        "Authentication\n  type                 {}\n  SSO region           {}\n  token expires        {}\n\n",
        r.authentication.kind, r.authentication.sso_region, r.authentication.token_expires
    ));
    s.push_str(&format!(
        "Runtime\n  region               {} ({})\n\n",
        r.runtime.region, r.runtime.source
    ));
    s.push_str("Allowed outbound\n");
    for h in &r.allowed_outbound {
        s.push_str(&format!("  {h}\n"));
    }
    s.push_str(&format!(
        "\nTLS roots              {}\nHTTP proxy             {}\nRedirects              {}\n\n",
        r.tls_roots, r.http_proxy, r.redirects
    ));
    s.push_str(&format!(
        "Local listener         {}\nLocal authentication   {}\n\n",
        r.local_listener, r.local_authentication
    ));
    s.push_str(&format!(
        "Telemetry              {}\nKiro content sharing   {}\nRequest body logging   {}\nDynamic model discovery {}\nAutomatic updates      {}\n\n",
        r.telemetry,
        r.content_sharing,
        r.request_body_logging,
        r.dynamic_model_discovery,
        r.automatic_updates
    ));
    s.push_str(&format!(
        "Build features         {}\n",
        if r.build_features.is_empty() {
            "none".to_string()
        } else {
            r.build_features.join(", ")
        }
    ));
    if !r.problems.is_empty() {
        s.push_str("\nProblems\n");
        for p in &r.problems {
            s.push_str(&format!("  {p}\n"));
        }
    }
    s
}

pub fn exit_code(r: &AuditReport) -> i32 {
    if r.problems.is_empty() { 0 } else { 1 }
}

pub fn run(args: AuditArgs) -> i32 {
    match report(&args) {
        Ok(r) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            } else {
                print!("{}", render_text(&r));
            }
            exit_code(&r)
        }
        Err(e) => {
            eprintln!("kiro-trust audit: {e}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditArgs;
    use std::path::Path;

    /// Placeholder database with the real schema (spec 8.7), for tests only.
    /// Byte-identical to the batch in `xtask/src/main.rs`'s `make-db`
    /// command, duplicated rather than shared because `xtask` must not
    /// depend on this crate (task-20-rulings.md ruling 2) and this crate
    /// must not carry `rusqlite` as a normal dependency (CLAUDE.md:
    /// `KiroDb::open_read_only` is the only opener). Never a real
    /// credential; the SSO region and ARN are the fixture's own
    /// (task-20-rulings.md ruling 1, ruling 4).
    fn make_synthetic_db(path: &Path) -> Result<(), String> {
        let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS auth_kv (key TEXT PRIMARY KEY, value TEXT);
             CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value BLOB);
             DELETE FROM auth_kv; DELETE FROM state;
             INSERT INTO auth_kv VALUES ('kirocli:odic:token', '{\"access_token\":\"placeholder-access\",\"refresh_token\":\"ph-ref\",\"expires_at\":\"2099-01-01T00:00:00Z\",\"region\":\"us-east-1\"}');
             INSERT INTO auth_kv VALUES ('kirocli:odic:device-registration', '{\"clientId\":\"placeholder-client\",\"clientSecret\":\"ph-sec\"}');
             INSERT INTO state VALUES ('auth.idc.region', '\"us-east-1\"');
             INSERT INTO state VALUES ('api.codewhisperer.profile', '{\"arn\":\"arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE\",\"profile_name\":\"KiroProfile-us-east-1\"}');",
        )
        .map_err(|e| e.to_string())
    }

    fn synthetic_db(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("idc.sqlite3");
        make_synthetic_db(&p).unwrap();
        p
    }

    #[test]
    fn report_has_every_line_and_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let db = synthetic_db(dir.path());
        let args = AuditArgs {
            json: false,
            listen: "127.0.0.1:3456".into(),
            kiro_db: Some(db.clone()),
            runtime_region: None,
            token_file: None,
            share_content: false,
        };
        let r = report(&args).unwrap();
        assert_eq!(r.authentication.kind, "AWS IAM Identity Center");
        // task-20-rulings.md ruling 1: us-east-1, not the owner's real
        // ap-southeast-1 SSO region.
        assert_eq!(r.authentication.sso_region, "us-east-1");
        assert_eq!(r.runtime.region, "us-east-1");
        assert_eq!(
            r.allowed_outbound,
            vec!["oidc.us-east-1.amazonaws.com", "runtime.us-east-1.kiro.dev"]
        );
        assert_eq!(r.tls_roots, "webpki-roots (compiled in)");
        assert_eq!(r.http_proxy, "disabled (environment ignored)");
        assert_eq!(r.telemetry, "none");
        assert_eq!(
            r.content_sharing,
            "opted out (x-amzn-codewhisperer-optout: true)"
        );
        assert_eq!(r.request_body_logging, "disabled (no flag exists)");
        // `cargo test -p kiro-trust` alone never compiles a development
        // feature into this crate or into `kiro-trust-net`, so both are
        // empty there. `cargo test --workspace` also builds
        // `kiro-trust-tests`, which depends on `kiro-trust-net` with
        // `test-endpoints` enabled; the new feature resolver unifies that
        // into the copy of `kiro-trust-net` this crate links against too
        // (CLAUDE.md Architecture rules: release builds and the feature
        // check select `-p kiro-trust` alone precisely to avoid this), so
        // `TEST_ENDPOINTS_COMPILED` can legitimately be true here. Compare
        // against that same ground truth instead of hard-coding "empty" so
        // this test holds under both invocations without weakening what it
        // proves: report() must derive build_features/problems from exactly
        // these two compiled-in signals, nothing else.
        let mut expected_features = Vec::new();
        if cfg!(feature = "capture") {
            expected_features.push("capture".to_string());
        }
        if kiro_trust_net::TEST_ENDPOINTS_COMPILED {
            expected_features.push("test-endpoints".to_string());
        }
        assert_eq!(r.build_features, expected_features);
        let expected_problems: Vec<String> = expected_features
            .iter()
            .map(|f| format!("development feature {f} is compiled in"))
            .collect();
        assert_eq!(r.problems, expected_problems);
        let text = render_text(&r);
        let build_features_line = if expected_features.is_empty() {
            "Build features         none".to_string()
        } else {
            format!("Build features         {}", expected_features.join(", "))
        };
        for line in [
            "Credential source".to_string(),
            "mode                 read-only, authorizer enforced".to_string(),
            "Local listener         127.0.0.1:3456".to_string(),
            "Automatic updates      disabled".to_string(),
            build_features_line,
        ] {
            assert!(text.contains(&line), "missing {line:?} in:\n{text}");
        }
        assert!(!text.contains("placeholder"));
        assert!(!text.contains("arn:aws"));
        assert!(!text.contains("000000000000"));
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("placeholder") && !json.contains("arn:aws"));
        assert!(!json.contains("000000000000"));
    }

    #[test]
    fn problems_make_audit_fail() {
        let dir = tempfile::tempdir().unwrap();
        let db = synthetic_db(dir.path());
        let args = AuditArgs {
            json: false,
            listen: "0.0.0.0:3456".into(),
            kiro_db: Some(db),
            runtime_region: None,
            token_file: None,
            share_content: true,
        };
        let r = report(&args).unwrap();
        assert!(
            r.problems.iter().any(|p| p.contains("loopback")),
            "{:?}",
            r.problems
        );
        assert_eq!(r.content_sharing, "enabled (--share-content)");
        assert_eq!(exit_code(&r), 1);
    }

    // task-20-rulings.md ruling 5: `test-endpoints` lives in kiro-trust-net
    // and `capture` is off in ordinary `cargo test -p kiro-trust`, so
    // neither can be turned on from inside this test. Assert on a
    // hand-built report instead, pinning the exit-code contract that
    // `report()` wires up when either constant is true.
    #[test]
    fn a_compiled_in_development_feature_fails_the_audit() {
        let r = AuditReport {
            build_features: vec!["capture".to_string()],
            problems: vec!["development feature capture is compiled in".to_string()],
            ..Default::default()
        };
        assert_eq!(exit_code(&r), 1);
        let text = render_text(&r);
        assert!(text.contains("Build features         capture"));
        assert!(text.contains("development feature capture is compiled in"));
    }
}
