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
    /// used by the live tier's `forced_refresh_succeeds` test (spec 8.6).
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
