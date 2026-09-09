//! In-memory credential cache with refresh (spec 3.3). Nothing is written
//! back to the database.

use crate::db::{Credentials, KiroDb};
use crate::error::AuthError;
use crate::refresh::refresh;
use kiro_trust_net::{Client, Region, RuntimeRegion};
use secrecy::ExposeSecret;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const VALIDITY_BUFFER: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct Identity {
    pub profile_arn: String,
    pub runtime_region: RuntimeRegion,
    pub sso_region: Region,
    pub expires_at: SystemTime,
}

pub struct TokenSource {
    db_path: PathBuf,
    net: Arc<Client>,
    runtime_override: Option<RuntimeRegion>,
    cached: Mutex<Option<Credentials>>,
    refresh_gate: tokio::sync::Mutex<()>,
    validity_buffer: Duration,
}

impl TokenSource {
    pub fn new(
        db_path: PathBuf,
        net: Arc<Client>,
        runtime_override: Option<RuntimeRegion>,
    ) -> Self {
        TokenSource {
            db_path,
            net,
            runtime_override,
            cached: Mutex::new(None),
            refresh_gate: tokio::sync::Mutex::new(()),
            validity_buffer: VALIDITY_BUFFER,
        }
    }

    /// Override the validity buffer (default 300s). A buffer longer than
    /// any real token lifetime forces the OIDC refresh path on every call;
    /// used by the live tier's `forced_refresh_succeeds` test (spec 8.6) to
    /// force a real OIDC refresh deliberately rather than waiting for a
    /// credential to actually near expiry. kiro-trust never persists a
    /// refreshed token: the Kiro CLI's credential database is opened
    /// read-only (spec 6.1), so a rotated refresh token reached through
    /// this override lives only in this process's memory and is gone when
    /// it exits (spec 12, "Refresh token rotation").
    pub fn with_validity_buffer(mut self, d: Duration) -> Self {
        self.validity_buffer = d;
        self
    }

    fn valid(&self, c: &Credentials) -> bool {
        c.expires_at > SystemTime::now() + self.validity_buffer
    }

    fn cached_valid(&self) -> Option<Credentials> {
        self.cached
            .lock()
            .unwrap()
            .as_ref()
            .filter(|c| self.valid(c))
            .cloned()
    }

    async fn current(&self) -> Result<Credentials, AuthError> {
        if let Some(c) = self.cached_valid() {
            return Ok(c);
        }
        let _gate = self.refresh_gate.lock().await;
        if let Some(c) = self.cached_valid() {
            return Ok(c);
        }
        let mut creds = KiroDb::open_read_only(&self.db_path)?.read_identity_center()?;
        if let Some(r) = &self.runtime_override {
            creds.runtime_region = r.clone();
        }
        if !self.valid(&creds) {
            tracing::info!(sso_region = %creds.sso_region, "credential expired, refreshing through AWS OIDC");
            creds = refresh(&self.net, &creds).await?;
            tracing::info!("credential refreshed");
        }
        *self.cached.lock().unwrap() = Some(creds.clone());
        Ok(creds)
    }

    /// Run `f` with the bearer token. The only sanctioned exposure point.
    pub async fn with_token<R>(&self, f: impl FnOnce(&str) -> R) -> Result<R, AuthError> {
        let c = self.current().await?;
        Ok(f(c.access_token.expose_secret()))
    }

    pub async fn identity(&self) -> Result<Identity, AuthError> {
        let c = self.current().await?;
        Ok(Identity {
            profile_arn: c.profile_arn,
            runtime_region: c.runtime_region,
            sso_region: c.sso_region,
            expires_at: c.expires_at,
        })
    }

    /// Drop the cache so the next call re-reads the database and refreshes
    /// if needed (used after an upstream 403).
    pub async fn invalidate(&self) {
        *self.cached.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiro_trust_net::Policy;
    use secrecy::SecretString;

    /// Synthetic credentials for the validity-buffer decision only; no
    /// field but `expires_at` matters to `valid()`. Values are
    /// placeholders, never real credentials.
    fn credentials(expires_at: SystemTime) -> Credentials {
        Credentials {
            access_token: SecretString::from("placeholder-access".to_string()),
            refresh_token: SecretString::from("placeholder-refresh".to_string()),
            client_id: "placeholder-client".to_string(),
            client_secret: SecretString::from("placeholder-secret".to_string()),
            expires_at,
            sso_region: Region::parse("ap-southeast-1").unwrap(),
            runtime_region: RuntimeRegion::parse("us-east-1").unwrap(),
            profile_arn: "arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE".to_string(),
        }
    }

    /// A `TokenSource` that never opens its database or performs network
    /// I/O in these tests: only `valid()` and `validity_buffer` are
    /// exercised, and `Client::new` builds a client without connecting to
    /// anything (the same pattern `crates/kiro-trust-tests/tests/live.rs`
    /// uses to build its own offline-safe `app()`).
    fn token_source() -> TokenSource {
        let net = Arc::new(Client::new(Policy::production()).unwrap());
        TokenSource::new(
            PathBuf::from("/nonexistent/does-not-matter.sqlite3"),
            net,
            None,
        )
    }

    // Important 8: nothing pinned the 300-second default before this test.
    #[test]
    fn default_validity_buffer_is_300_seconds() {
        assert_eq!(token_source().validity_buffer, Duration::from_secs(300));
    }

    #[test]
    fn a_credential_expiring_inside_the_default_buffer_is_invalid() {
        let ts = token_source();
        let c = credentials(SystemTime::now() + Duration::from_secs(299));
        assert!(!ts.valid(&c));
    }

    #[test]
    fn a_credential_expiring_well_past_the_default_buffer_is_valid() {
        let ts = token_source();
        let c = credentials(SystemTime::now() + Duration::from_secs(3600));
        assert!(ts.valid(&c));
    }

    // Important 8: proves the override actually reaches the expiry
    // decision, not only that the setter stores it.
    #[test]
    fn with_validity_buffer_overrides_the_expiry_decision() {
        let long_buffer = Duration::from_secs(400 * 24 * 3600);
        let ts = token_source().with_validity_buffer(long_buffer);
        assert_eq!(ts.validity_buffer, long_buffer);
        // A credential that is valid under the default 300s buffer is
        // forced invalid once the override is longer than any real token
        // lifetime: this is exactly how the live tier's
        // `forced_refresh_succeeds` test (spec 8.6) forces the OIDC
        // refresh path.
        let c = credentials(SystemTime::now() + Duration::from_secs(3600));
        assert!(!ts.valid(&c));
    }
}
