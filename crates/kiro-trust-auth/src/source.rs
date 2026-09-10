//! In-memory credential cache with refresh (spec 3.3). Nothing is written
//! back to the database.

use crate::db::{Credentials, KiroDb};
use crate::error::AuthError;
use crate::refresh::refresh;
use kiro_trust_net::{Client, Region, RuntimeRegion};
use secrecy::ExposeSecret;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VALIDITY_BUFFER: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct Identity {
    pub profile_arn: String,
    pub runtime_region: RuntimeRegion,
    pub sso_region: Region,
    pub expires_at: SystemTime,
}

/// The cached credential plus whether this process minted it itself via an
/// OIDC exchange, as opposed to reading it straight from the database. The
/// forced-cycle bound (spec 3.3, `invalidate()` paragraph) needs this: a
/// credential this process already refreshed is never refreshed again just
/// because it was rejected once.
#[derive(Clone)]
struct Cached {
    creds: Credentials,
    minted_by_refresh: bool,
}

pub struct TokenSource {
    db_path: PathBuf,
    net: Arc<Client>,
    runtime_override: Option<RuntimeRegion>,
    cached: Mutex<Option<Cached>>,
    refresh_gate: tokio::sync::Mutex<()>,
    validity_buffer: Duration,
    /// Set by `invalidate()`, consumed by the next `current()` cycle (spec
    /// 3.3, the `invalidate()` paragraph). Read outside `refresh_gate` as a
    /// best-effort fast-path skip, then authoritatively swapped to `false`
    /// once inside the gate, so exactly one cycle is "forced".
    forced: AtomicBool,
    /// `expires_at` values of seeds a refresh has spent (rule 3's
    /// burned-seed marker): never chained from again in this process.
    /// `UNIX_EPOCH` (the unparsable-`expiresAt` sentinel, spec 3.3/7.2) is
    /// never inserted here, since it cannot identify one credential;
    /// `burned_unparsable` covers that case instead.
    burned: Mutex<HashSet<SystemTime>>,
    /// One-way latch: set once any `UNIX_EPOCH`-tagged seed is spent, and
    /// never cleared. `expires_at` cannot distinguish one unparsable row
    /// from another, so this is coarser than `burned` by design — it stops
    /// an unparsable row from being replayed without limit, at the cost of
    /// also refusing a later, unrelated login that also fails to parse
    /// (spec 3.3).
    burned_unparsable: AtomicBool,
}

/// Rule 3's burn decision, finalized once a 200 status either did or did not
/// arrive: a successful exchange and any post-200 failure both burn, since
/// both mean the OIDC endpoint already committed the rotation; nothing
/// before a 200, and no non-200 status, ever does (spec 3.3). `Drop` runs
/// this exactly once whether `refresh()` ran to completion or the caller's
/// future was cancelled mid-flight, so a dropped request past a 200 still
/// burns and one before it never does.
struct BurnGuard<'a> {
    source: &'a TokenSource,
    expires_at: SystemTime,
    unparsable: bool,
    past_200: &'a AtomicBool,
}

impl Drop for BurnGuard<'_> {
    fn drop(&mut self) {
        if !self.past_200.load(Ordering::SeqCst) {
            return;
        }
        if self.unparsable {
            self.source.burned_unparsable.store(true, Ordering::SeqCst);
        } else {
            self.source.burned.lock().unwrap().insert(self.expires_at);
        }
    }
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
            forced: AtomicBool::new(false),
            burned: Mutex::new(HashSet::new()),
            burned_unparsable: AtomicBool::new(false),
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
            .filter(|c| self.valid(&c.creds))
            .map(|c| c.creds.clone())
    }

    fn set_cached(&self, creds: Credentials, minted_by_refresh: bool) {
        *self.cached.lock().unwrap() = Some(Cached {
            creds,
            minted_by_refresh,
        });
    }

    /// The top-of-cycle database read every cycle starts with (spec 3.3).
    fn read_db(&self) -> Result<Credentials, AuthError> {
        let mut creds = KiroDb::open_read_only(&self.db_path)?.read_identity_center()?;
        if let Some(r) = &self.runtime_override {
            creds.runtime_region = r.clone();
        }
        Ok(creds)
    }

    /// Rule 2: chain from whichever credential holds the later `expires_at`.
    /// Once this process has refreshed at least once, that is normally the
    /// cached one, since rule 1 would already have claimed a database write
    /// fresher than it.
    fn chain_seed(cached: Option<&Credentials>, db: &Credentials) -> Credentials {
        match cached {
            Some(c) if c.expires_at >= db.expires_at => c.clone(),
            _ => db.clone(),
        }
    }

    /// Rule 3's burned-seed marker: a seed already known to have been spent
    /// is never sent again. Returns `None` without touching the network
    /// when `seed` is already burned. Private, with exactly the two call
    /// sites below, both already holding `refresh_gate`: the already-burned
    /// check and the guard's construction are not atomic with each other,
    /// so a caller without the gate could race another cycle between them.
    async fn try_refresh(&self, seed: &Credentials) -> Option<Result<Credentials, AuthError>> {
        let unparsable = seed.expires_at == UNIX_EPOCH;
        if unparsable {
            if self.burned_unparsable.load(Ordering::SeqCst) {
                return None;
            }
        } else if self.burned.lock().unwrap().contains(&seed.expires_at) {
            return None;
        }
        let past_200 = AtomicBool::new(false);
        let _guard = BurnGuard {
            source: self,
            expires_at: seed.expires_at,
            unparsable,
            past_200: &past_200,
        };
        let result = refresh(&self.net, seed, &past_200).await;
        // The classification this whole mechanism rests on: a 200 arrived
        // if and only if the result is a success or a post-200 failure.
        // `refresh.rs` and `BurnGuard` must agree on this by construction;
        // this only catches a future edit that quietly breaks it.
        debug_assert_eq!(
            past_200.load(Ordering::SeqCst),
            matches!(result, Ok(_) | Err(AuthError::RefreshIncomplete(_)))
        );
        Some(result)
    }

    async fn current(&self) -> Result<Credentials, AuthError> {
        if !self.forced.load(Ordering::SeqCst)
            && let Some(c) = self.cached_valid()
        {
            return Ok(c);
        }
        let _gate = self.refresh_gate.lock().await;
        let forced = self.forced.swap(false, Ordering::SeqCst);
        if !forced && let Some(c) = self.cached_valid() {
            return Ok(c);
        }

        let db_creds = self.read_db()?;
        // "The value the database held at the top of this cycle" (rule 3):
        // the baseline a later re-read is compared against.
        let seed_expires_at = db_creds.expires_at;
        let cached = self.cached.lock().unwrap().clone();

        // Rule 1, unchanged whether this cycle is forced or not: the
        // database wins only when it is valid and *strictly* newer than
        // whatever is cached, never merely different. Once this process has
        // refreshed, the cached expiry differs from an untouched database
        // row as a matter of course, so "different" would hand the cycle
        // back to a credential whose refresh token this process already
        // exchanged (spec 3.3).
        let db_is_newer = cached
            .as_ref()
            .map(|c| db_creds.expires_at > c.creds.expires_at)
            .unwrap_or(true);
        if self.valid(&db_creds) && db_is_newer {
            self.set_cached(db_creds.clone(), false);
            return Ok(db_creds);
        }

        if forced && let Some(c) = &cached {
            // invalidate() paragraph's bound: never refresh a credential
            // this process itself minted by refresh, while it is still
            // valid. It was rejected minutes after being issued, another
            // exchange from the same grant would be rejected the same way,
            // and every exchange may rotate the owner's token; serve it
            // again and let the 403 reach the client. Once it is past its
            // own expiry the bound no longer applies: re-serving an expired
            // credential would only guarantee a second 403 where a refresh
            // could have worked.
            if c.minted_by_refresh && self.valid(&c.creds) {
                return Ok(c.creds.clone());
            }
        }

        // Rule 2: chain from the newest token held.
        let seed = Self::chain_seed(cached.as_ref().map(|c| &c.creds), &db_creds);
        tracing::info!(sso_region = %seed.sso_region, "refreshing the Kiro credential through AWS OIDC");
        match self.try_refresh(&seed).await {
            None => Err(AuthError::ReauthRequired(
                "the refresh token was already exchanged in this session".into(),
            )),
            Some(Ok(new_creds)) => {
                self.set_cached(new_creds.clone(), true);
                tracing::info!("credential refreshed");
                Ok(new_creds)
            }
            Some(Err(first_err)) => {
                // Rule 3: never re-send an exchanged token. Retry once, and
                // only when a fresh database read shows the Kiro CLI wrote a
                // new credential since `seed_expires_at` was read above.
                // `UNIX_EPOCH` (an unparsable `expiresAt`) never proves that,
                // so a seed read as `UNIX_EPOCH` always reads as unchanged; a
                // database read failure here is treated the same way, since
                // there is nothing newer to retry with either way.
                let newer = self
                    .read_db()
                    .ok()
                    .filter(|c| seed_expires_at != UNIX_EPOCH && c.expires_at != seed_expires_at);
                match newer {
                    Some(newer) => match self.try_refresh(&newer).await {
                        None => Err(AuthError::ReauthRequired(first_err.to_string())),
                        Some(Ok(new_creds)) => {
                            self.set_cached(new_creds.clone(), true);
                            tracing::info!(
                                "credential refreshed after a newer Kiro CLI login was found"
                            );
                            Ok(new_creds)
                        }
                        Some(Err(e)) => Err(AuthError::ReauthRequired(e.to_string())),
                    },
                    None => Err(AuthError::ReauthRequired(first_err.to_string())),
                }
            }
        }
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

    /// Force the next cycle to re-check the database (used after an
    /// upstream 403). Spec 3.3: this marks the next cycle forced rather
    /// than dropping the cached credential, so the chain's newest refresh
    /// token survives the 403 and rule 3 still holds.
    pub async fn invalidate(&self) {
        self.forced.store(true, Ordering::SeqCst);
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
