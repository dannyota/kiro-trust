use kiro_trust_auth::{AuthError, TokenSource};
use kiro_trust_net::{Client, Policy};
use rusqlite::Connection;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as TokioTcpListener;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn write_token(c: &Connection, expires_at: &str, refresh_token: &str, access_token: &str) {
    let token = format!(
        r#"{{"access_token":"{access_token}","refresh_token":"{refresh_token}","expires_at":"{expires_at}","region":"ap-southeast-1"}}"#
    );
    c.execute(
        "INSERT OR REPLACE INTO auth_kv VALUES ('kirocli:odic:token', ?1)",
        [token],
    )
    .unwrap();
}

fn make_db_with(dir: &Path, expires_at: &str, refresh_token: &str, access_token: &str) -> PathBuf {
    let p = dir.join("data.sqlite3");
    let c = Connection::open(&p).unwrap();
    c.execute_batch("CREATE TABLE auth_kv (key TEXT PRIMARY KEY, value TEXT); CREATE TABLE state (key TEXT PRIMARY KEY, value BLOB);").unwrap();
    write_token(&c, expires_at, refresh_token, access_token);
    c.execute("INSERT INTO auth_kv VALUES ('kirocli:odic:device-registration', '{\"clientId\":\"cid\",\"clientSecret\":\"csec\"}')", []).unwrap();
    c.execute("INSERT INTO state VALUES ('api.codewhisperer.profile', '{\"arn\":\"arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE\"}')", []).unwrap();
    p
}

fn make_db(dir: &Path, expires_at: &str) -> PathBuf {
    make_db_with(dir, expires_at, "old-refresh", "old-access")
}

/// Rewrites the token record mid-test, simulating a Kiro CLI login or
/// refresh landing in the database while a `TokenSource` holds it open
/// read-only.
fn rewrite_token(db: &Path, expires_at: &str, refresh_token: &str, access_token: &str) {
    let c = Connection::open(db).unwrap();
    write_token(&c, expires_at, refresh_token, access_token);
}

async fn source(server: &MockServer, db: PathBuf) -> TokenSource {
    let net = Arc::new(Client::new(Policy::loopback_plain_http(server.address().port())).unwrap());
    TokenSource::new(db, net, None)
}

#[tokio::test]
async fn valid_token_is_served_without_refresh() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = source(&server, make_db(dir.path(), "2099-01-01T00:00:00Z")).await;
    let t = src.with_token(|t| t.to_string()).await.unwrap();
    assert_eq!(t, "old-access");
    let id = src.identity().await.unwrap();
    assert_eq!(id.runtime_region.as_str(), "us-east-1");
    assert_eq!(id.sso_region.as_str(), "ap-southeast-1");
}

#[tokio::test]
async fn expired_token_is_refreshed_once_for_concurrent_callers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(header("content-type", "application/json"))
        .and(body_partial_json(serde_json::json!({"grantType": "refresh_token", "clientId": "cid", "clientSecret": "csec", "refreshToken": "old-refresh"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"accessToken": "new-access", "refreshToken": "new-refresh", "expiresIn": 3600})))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = Arc::new(source(&server, make_db(dir.path(), "2020-01-01T00:00:00Z")).await);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = src.clone();
        handles.push(tokio::spawn(async move {
            s.with_token(|t| t.to_string()).await.unwrap()
        }));
    }
    for h in handles {
        assert_eq!(h.await.unwrap(), "new-access");
    }
    // Cached now: the mock's expect(1) is verified on drop.
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "new-access"
    );
}

#[tokio::test]
async fn refresh_failure_is_an_error_and_invalidate_forces_reread() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_string("{\"error\":\"invalid_grant\"}"))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let db = make_db(dir.path(), "2020-01-01T00:00:00Z");
    let src = source(&server, db.clone()).await;
    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    // Rule 3 (spec 3.3): the database has not changed since this cycle's
    // top-of-cycle read, so there is nothing to retry with; the failure is
    // wrapped rather than surfaced raw.
    assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");
    assert!(
        format!("{err}").contains("log in to Kiro CLI again"),
        "{err}"
    );
    assert!(
        !format!("{err}").contains("invalid_grant"),
        "response bodies are never surfaced"
    );

    // A fresh login lands in the database; invalidate picks it up without refresh.
    rewrite_token(&db, "2099-01-01T00:00:00Z", "r", "relogin");
    src.invalidate().await;
    assert_eq!(src.with_token(|t| t.to_string()).await.unwrap(), "relogin");
}

#[tokio::test]
async fn absurd_expires_in_is_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"accessToken": "a", "expiresIn": 9223372036854775807i64}),
        ))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = source(&server, make_db(dir.path(), "2020-01-01T00:00:00Z")).await;
    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    // Rule 3: an unchanged database means no retry, so this is wrapped too.
    assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"accessToken": "a", "expiresIn": 0})),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let src = source(&server, make_db(dir.path(), "2020-01-01T00:00:00Z")).await;
    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");
}

/// Rule 2 (spec 3.3): once this process has refreshed, the next cycle
/// chains from the refresh token it received, never from the database's
/// original. `with_validity_buffer` forces every call down the refresh
/// path (2h, comfortably longer than the 1h `expiresIn` every mock below
/// returns), so a second call cannot be satisfied from cache alone.
///
/// There is deliberately no second, `.expect(0)` mock guarding
/// `orig-refresh`: wiremock resolves a request against the first mock whose
/// matcher fits, in mount order, so a second mock matching the same body
/// would never even see a request the first one already claims. The first
/// mock's own `.expect(1)` already fails if `orig-refresh` is ever sent
/// twice, which is the only way a decorative second mock could fire.
#[tokio::test]
async fn second_refresh_cycle_chains_from_the_first_not_the_database() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "orig-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain1-access", "refreshToken": "chain1-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "chain1-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain2-access", "refreshToken": "chain2-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );
    let src = source(&server, db)
        .await
        .with_validity_buffer(Duration::from_secs(7200));

    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain1-access"
    );
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain2-access"
    );
}

/// Rule 1 (spec 3.3): a database credential written after the chain
/// started wins over the cached one, and drops it. `invalidate()` is used
/// afterward purely as the mechanism to force one more cycle: the winning
/// database credential is deliberately far in the future, so it would
/// otherwise be served from cache forever, and there would be no way to
/// observe which refresh token seeds the next chain.
#[tokio::test]
async fn fresher_database_credential_replaces_the_cached_chain() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "orig-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain1-access", "refreshToken": "chain1-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "db-refresh-2"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "db-chained-access", "refreshToken": "db-chained-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );
    let src = source(&server, db.clone())
        .await
        .with_validity_buffer(Duration::from_secs(7200));

    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain1-access"
    );

    // The Kiro CLI logs in again: a database write, with its own refresh
    // token, that outright supersedes the in-memory chain.
    rewrite_token(&db, "2099-01-01T00:00:00Z", "db-refresh-2", "db-access-2");
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "db-access-2"
    );

    // Force one more cycle. The database is unchanged since the read
    // above, so this falls through to rule 2, whose seed is now the
    // replaced cache: proof `chain1-refresh` was really dropped and
    // `db-refresh-2` is what the chain continues from.
    src.invalidate().await;
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "db-chained-access"
    );
}

/// Rule 3 (spec 3.3), first half: a refresh using the chained token fails,
/// and the database has not changed since this cycle started, so the call
/// errors rather than retry with anything already exchanged.
#[tokio::test]
async fn chained_refresh_failure_with_unchanged_database_is_an_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "orig-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain1-access", "refreshToken": "chain1-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "chain1-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(400).set_body_string("{\"error\":\"invalid_grant\"}"))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );
    let src = source(&server, db)
        .await
        .with_validity_buffer(Duration::from_secs(7200));

    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain1-access"
    );

    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");
    assert!(
        format!("{err}").contains("log in to Kiro CLI again"),
        "{err}"
    );
    assert!(
        !format!("{err}").contains("invalid_grant"),
        "response bodies are never surfaced"
    );
    // No third call happens at all: both mocks' own expect(1) already
    // proves `orig-refresh` and `chain1-refresh` were each sent exactly
    // once, verified when `server` drops at the end of this test.
}

/// A `wiremock::Respond` that rewrites the database as a side effect of
/// answering the request, so the write lands at exactly the moment rule 3's
/// retry logic needs it to have already happened, with no sleep and no
/// race window to size (FIX 9).
struct RewriteThenFail {
    db: PathBuf,
    expires_at: &'static str,
    refresh_token: &'static str,
    access_token: &'static str,
}
impl wiremock::Respond for RewriteThenFail {
    fn respond(&self, _req: &wiremock::Request) -> ResponseTemplate {
        rewrite_token(
            &self.db,
            self.expires_at,
            self.refresh_token,
            self.access_token,
        );
        ResponseTemplate::new(400)
    }
}

/// Rule 3 (spec 3.3), second half: a refresh using the chained token
/// fails, but the Kiro CLI has written a new credential in the meantime,
/// so the retry uses the database's new refresh token.
#[tokio::test]
async fn chained_refresh_failure_retries_with_a_changed_database() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "orig-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain1-access", "refreshToken": "chain1-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );

    // Mounted after the mock above so it is checked first (spec 3.3's
    // rule-2 attempt matches `chain1-refresh`); rewrites the database to a
    // new row, with a new refresh token, the instant this request arrives.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "chain1-refresh"}),
        ))
        .respond_with(RewriteThenFail {
            db: db.clone(),
            expires_at: "2020-06-01T00:00:00Z",
            refresh_token: "db-refresh-3",
            access_token: "unused",
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "db-refresh-3"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "recovered-access", "refreshToken": "recovered-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let src = source(&server, db)
        .await
        .with_validity_buffer(Duration::from_secs(7200));

    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain1-access"
    );
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "recovered-access"
    );
}

/// `invalidate()` clause's bound (spec 3.3, FIX 2): a forced cycle never
/// refreshes a credential this process minted by refresh. Attempt 1 exchanges
/// `orig-refresh` for `chain1-access`; the 403 that follows must be answered
/// by re-serving `chain1-access` again, with zero further OIDC requests, not
/// by spending `chain1-refresh` on a second exchange that would only be
/// rejected the same way.
#[tokio::test]
async fn invalidate_never_refreshes_a_self_minted_credential() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "orig-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain1-access", "refreshToken": "chain1-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    // No further /token traffic is expected at all: a mock matching a
    // resend of `chain1-refresh` would fail its own expect(0) if the bound
    // did not hold.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "chain1-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );
    // The default 300s buffer, not a forcing one: `chain1-access`'s 3600s
    // `expiresIn` must be valid at invalidate() time (FIX 2's bound is
    // gated on `valid()`), which a forcing buffer bigger than any
    // `expiresIn` would defeat by construction.
    let src = source(&server, db).await;

    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain1-access"
    );

    // Simulates the runtime 403 that follows: `chain1-access` was minted by
    // this process minutes ago and is still valid, so the forced cycle must
    // not refresh it again, only re-serve it.
    src.invalidate().await;
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain1-access"
    );
}

/// Rule 1's strict comparison (spec 3.3, FIX 1): a database row that is
/// individually valid still loses to a fresher cached chain, so the process
/// keeps chaining from the cache rather than switching to the database's
/// older, still-unexchanged refresh token. Every other forced-cycle test
/// uses a database row expired since 2020, which never exercises this
/// branch since it always fails `valid()` outright; this one keeps the
/// database row genuinely valid, just older, to prove `>` decides it, not
/// `valid()` alone.
#[tokio::test]
async fn forced_cycle_never_prefers_a_valid_but_older_database_row() {
    let server = MockServer::start().await;
    // Both dates are decades past this test's 7200s buffer, so both are
    // individually "valid"; 2099 is later than 2098, which is the only
    // property rule 1's strict comparison is allowed to act on.
    let d0_expires_at = "2099-01-01T00:00:00Z";
    let d1_expires_at = "2098-01-01T00:00:00Z";
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "d0-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "d0-chained-access", "refreshToken": "d0-chained-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    // `d1-refresh` belongs to a database row that is individually valid
    // (well beyond the 7200s buffer below) but older than the cached D0: it
    // must never reach the wire.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "d1-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(dir.path(), d0_expires_at, "d0-refresh", "d0-access");
    let src = source(&server, db.clone())
        .await
        .with_validity_buffer(Duration::from_secs(7200));

    // D0 is valid (2099 is far past the 7200s buffer) and nothing is cached
    // yet, so rule 1 serves it directly and caches it with
    // `minted_by_refresh = false`: the forced-cycle bound (FIX 2) must not
    // apply to what follows.
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "d0-access"
    );

    // The Kiro CLI writes D1: individually valid (2098 is also far past the
    // buffer) but older than D0 (2098 < 2099).
    rewrite_token(&db, d1_expires_at, "d1-refresh", "d1-access");
    src.invalidate().await;

    // A naive `valid(db)` check (the pre-fix rule 1) would serve D1 outright.
    // The strict `>` comparison keeps chaining from D0 instead.
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "d0-chained-access"
    );
}

/// Rule 3's burned-seed marker (spec 3.3, FIX 4): a refresh that fails after
/// the OIDC endpoint already returned 200 has spent the refresh token even
/// though nothing usable came back. A later, separate `current()` call must
/// not re-send it, and must not even touch the network to find that out.
#[tokio::test]
async fn refresh_failure_after_a_200_burns_the_seed_for_later_cycles() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "old-refresh"}),
        ))
        // A 200 the OIDC endpoint genuinely sent, but whose body this
        // process cannot use: the exchange still happened server-side.
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db(dir.path(), "2020-01-01T00:00:00Z");
    let src = source(&server, db).await;

    let err1 = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err1, AuthError::ReauthRequired(_)), "{err1}");

    // A second, independent cycle: nothing is cached (the first attempt
    // never produced a credential to cache), and the database is
    // unchanged, so rule 2 would pick the exact same seed again. The
    // mock's own `.expect(1)` proves this call made no network request at
    // all.
    let err2 = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err2, AuthError::ReauthRequired(_)), "{err2}");
}

/// Spec 3.3/7.2: an unparsable `expiresAt` reads as `UNIX_EPOCH`, a sentinel
/// rather than a time, so it never proves two reads are "the same"
/// credential. A database row that is unparsable both before and after a
/// Kiro CLI write must not be read as unchanged in a way that lets rule 2
/// hand the chain back to an already-exchanged, unparsable-expiry row.
#[tokio::test]
async fn unparsable_expiry_on_both_sides_of_a_write_never_reads_as_unchanged() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "epoch-refresh-1"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "post-epoch-access", "refreshToken": "post-epoch-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "post-epoch-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain2-access", "refreshToken": "chain2-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    // Neither `epoch-refresh-1` (already exchanged) nor `epoch-refresh-2`
    // (a second unparsable row this process never tried) may reach the
    // wire once a real cached chain exists.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "epoch-refresh-1"}),
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "epoch-refresh-2"}),
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(dir.path(), "not-a-timestamp", "epoch-refresh-1", "unused");
    let src = source(&server, db.clone())
        .await
        .with_validity_buffer(Duration::from_secs(7200));

    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "post-epoch-access"
    );

    // A second Kiro CLI login that also fails to parse: still `UNIX_EPOCH`,
    // but a different underlying credential.
    rewrite_token(&db, "not-a-timestamp", "epoch-refresh-2", "unused");
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain2-access"
    );
}

/// A `wiremock::Respond` that rewrites the database to a genuinely new row
/// as a side effect of failing the request, so rule 3's "did the database
/// change" check has a real change sitting behind it and only `UNIX_EPOCH`
/// stands between that change and a retry.
struct RewriteToRealRowThenFail {
    db: PathBuf,
}
impl wiremock::Respond for RewriteToRealRowThenFail {
    fn respond(&self, _req: &wiremock::Request) -> ResponseTemplate {
        rewrite_token(
            &self.db,
            "2099-01-01T00:00:00Z",
            "post-epoch-cli-write",
            "unused",
        );
        ResponseTemplate::new(500)
    }
}

/// Rule 3 (spec 3.3): "a seed read as `UNIX_EPOCH` always reads as
/// unchanged", even when the database demonstrably did change underneath
/// it. Without that guard, `c.expires_at != seed_expires_at` alone would
/// see `UNIX_EPOCH` (the seed) against a real 2099 timestamp (the rewrite
/// below) as "different" and wrongly retry with a token this process never
/// tried before but also has no way to trust the provenance of.
#[tokio::test]
async fn unparsable_seed_never_qualifies_a_rule_3_retry() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "not-a-timestamp",
        "epoch-refresh-fail",
        "unused",
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "epoch-refresh-fail"}),
        ))
        .respond_with(RewriteToRealRowThenFail { db: db.clone() })
        .expect(1)
        .mount(&server)
        .await;
    // Never reached: rule 3 must not retry once the seed is `UNIX_EPOCH`,
    // no matter what the database now holds.
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "post-epoch-cli-write"}),
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let src = source(&server, db).await;
    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");
}

/// A responder that fails the first request and succeeds on every one
/// after, used to prove a seed a `RefreshRejected` or pre-response failure
/// left usable really does get sent again.
struct FailOnceThenSucceed(AtomicU32);
impl wiremock::Respond for FailOnceThenSucceed {
    fn respond(&self, _req: &wiremock::Request) -> ResponseTemplate {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            ResponseTemplate::new(503)
        } else {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accessToken": "recovered-access", "refreshToken": "recovered-refresh", "expiresIn": 3600
            }))
        }
    }
}

/// Rule 3's narrowed burn rule (spec 3.3): a non-200 status is never a burn
/// signal, whatever the status is — 503 is neither the old 400/401
/// exception nor a 200, so this pins the general case rather than a
/// grandfathered special one. The mock's `.expect(2)` on a matcher pinned
/// to `orig-refresh` proves the same, never-burned token is what a later
/// cycle actually sends.
#[tokio::test]
async fn non_200_status_never_burns_the_seed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "orig-refresh"}),
        ))
        .respond_with(FailOnceThenSucceed(AtomicU32::new(0)))
        .expect(2)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );
    let src = source(&server, db).await;

    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");

    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "recovered-access"
    );
}

/// Rule 3's narrowed burn rule (spec 3.3): a failure before any response
/// status arrived — here, nothing is listening on the port at all, so
/// `net.post()` fails at the transport layer — is never a burn signal
/// either. A `TokenSource` cannot switch targets mid-life, so the sequence
/// is: point it at a port with no listener, observe the failure, then bind
/// a real server on that exact port and observe the same refresh token
/// succeed on retry, proving nothing about the seed was consumed by the
/// first attempt.
#[tokio::test]
async fn pre_response_failure_never_burns_the_seed() {
    // Rebinding the exact port just dropped is inherently racy: anything
    // else on the machine, including a concurrent `MockServer::start()` in
    // this same binary under `--test-threads=6`, can take it first. Retry
    // the whole sequence on a fresh port rather than let that race fail the
    // test on a cause unrelated to the code under test (FIX F).
    const ATTEMPTS: u32 = 5;
    for attempt in 1..=ATTEMPTS {
        let port = {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };

        let dir = tempfile::tempdir().unwrap();
        let db = make_db_with(
            dir.path(),
            "2020-01-01T00:00:00Z",
            "closed-port-refresh",
            "old-access",
        );
        let net = Arc::new(Client::new(Policy::loopback_plain_http(port)).unwrap());
        let src = TokenSource::new(db, net, None);

        // Nothing is listening on `port` yet: the send itself fails, well
        // before any response status could arrive.
        let err = src.with_token(|t| t.to_string()).await.unwrap_err();
        assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");

        let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) else {
            assert!(
                attempt < ATTEMPTS,
                "could not reclaim a closed port after {ATTEMPTS} attempts"
            );
            continue;
        };

        // Now something is: the same `closed-port-refresh` must still be usable.
        let server = MockServer::builder().listener(listener).start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_partial_json(
                serde_json::json!({"refreshToken": "closed-port-refresh"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accessToken": "reconnected-access", "refreshToken": "reconnected-refresh", "expiresIn": 3600
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            src.with_token(|t| t.to_string()).await.unwrap(),
            "reconnected-access"
        );
        return;
    }
}

/// FIX A (spec 3.3 rule 3): a successful exchange still burns its seed —
/// it is the one seed known for certain to be spent. Reproduces the
/// coordinator's exact scenario: database row `D` (valid until 2099, so
/// decades of remaining lifetime) is served under rule 1 and cached
/// un-refreshed; a forced cycle exchanges `D`'s refresh token for `C1`,
/// whose granted lifetime (1800s) is far shorter than `D`'s remaining one;
/// `D` then legitimately out-ages `C1` again and rule 1 re-serves `D`
/// (which sends nothing, since rule 1 only ever serves a stored access
/// token). A further forced cycle, finding nothing newer than `D`, must not
/// fall back to `D`'s refresh token a second time: the mock's own
/// `.expect(1)` proves it never reaches the wire twice, and the final call
/// errors rather than silently resending it.
#[tokio::test]
async fn successful_exchange_still_burns_the_database_row_it_spent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "R_db"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "c1-access", "refreshToken": "c1-refresh", "expiresIn": 1800
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(dir.path(), "2099-01-01T00:00:00Z", "R_db", "d-access");
    let src = source(&server, db).await;

    // Rule 1: nothing cached yet, `D` is valid, served directly.
    assert_eq!(src.with_token(|t| t.to_string()).await.unwrap(), "d-access");

    // A 403 forces a cycle. `D` is unchanged, so rule 1 does not re-fire
    // (not strictly newer than itself); the bound does not apply (`D` was
    // not minted by refresh); rule 2 exchanges `D`'s own refresh token.
    src.invalidate().await;
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "c1-access"
    );

    // Another 403. `D` (2099) is now genuinely newer than `C1` (1800s from
    // a few instructions ago), so rule 1 legitimately re-serves `D` —
    // sending nothing, just returning the stored access token.
    src.invalidate().await;
    assert_eq!(src.with_token(|t| t.to_string()).await.unwrap(), "d-access");

    // A fourth 403. `D` is unchanged and cached again, so rule 2 would pick
    // `R_db` once more. Under the pre-fix code this re-sent it; under the
    // fix it is still burned from the exchange two cycles ago.
    src.invalidate().await;
    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");
}

/// A responder that delays its first response far longer than any
/// reasonable test scheduling jitter, then answers every later request
/// immediately: used to force a genuine in-flight cancellation before a
/// response arrives, deterministically rather than by timing a real
/// network race.
struct DelayThenSucceed(AtomicU32);
impl wiremock::Respond for DelayThenSucceed {
    fn respond(&self, _req: &wiremock::Request) -> ResponseTemplate {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(60))
                .set_body_json(serde_json::json!({
                    "accessToken": "never-seen-access", "refreshToken": "never-seen-refresh", "expiresIn": 3600
                }))
        } else {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accessToken": "recovered-access", "refreshToken": "recovered-refresh", "expiresIn": 3600
            }))
        }
    }
}

/// FIX B (spec 3.3 rule 3's cancellation paragraph): a refresh cancelled
/// before any response arrives must leave the seed usable. The first
/// request is answered only after a 60s delay — five orders of magnitude
/// longer than the 50ms this test waits before aborting the task driving
/// it — so the abort is guaranteed to land while `refresh()` is still
/// waiting on `net.post()`, well before any response status could exist,
/// not a race against how fast the mock happens to answer. Awaiting the
/// aborted `JoinHandle` afterward synchronizes with the cancellation (and
/// therefore the `BurnGuard`'s drop) actually completing before the test
/// proceeds, so the second call below is not itself timing-dependent.
#[tokio::test]
async fn refresh_cancelled_before_any_response_leaves_the_seed_usable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "orig-refresh"}),
        ))
        .respond_with(DelayThenSucceed(AtomicU32::new(0)))
        .expect(2)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );
    let src = Arc::new(source(&server, db).await);

    let s = src.clone();
    let cancelled = tokio::spawn(async move { s.with_token(|t| t.to_string()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    cancelled.abort();
    let _ = cancelled.await;

    // `orig-refresh` was never exchanged (the cancelled request's response
    // never arrived): a fresh cycle must send it again and succeed.
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "recovered-access"
    );
}

/// FIX C (spec 3.3's `expires_at` paragraph): an unparsable (`UNIX_EPOCH`)
/// seed spent by a post-200 failure is never resent by a later, independent
/// cycle — the same property `refresh_failure_after_a_200_burns_the_seed_for_later_cycles`
/// pins for a normal seed, exercised here for the sentinel case. Distinct
/// from `unparsable_expiry_on_both_sides_of_a_write_never_reads_as_unchanged`
/// and `unparsable_seed_never_qualifies_a_rule_3_retry` above, which pin
/// rule 3's retry gate, not the burn itself.
#[tokio::test]
async fn unparsable_seed_spent_past_a_200_is_never_resent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "epoch-fail-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "not-a-timestamp",
        "epoch-fail-refresh",
        "unused",
    );
    let src = source(&server, db).await;

    let err1 = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err1, AuthError::ReauthRequired(_)), "{err1}");

    // A second, independent cycle: nothing is cached, the database is
    // unchanged, so rule 2 picks the same `UNIX_EPOCH` seed again. The
    // mock's `.expect(1)` proves this call made no network request at all.
    let err2 = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err2, AuthError::ReauthRequired(_)), "{err2}");
}

/// FIX D (spec 3.3, the `invalidate()` bound): the bound applies only
/// "while that credential is still valid". `with_validity_buffer` makes
/// `chain1-access` (1h `expiresIn`) count as expired the instant it is
/// minted (2h buffer), so the forced cycle after a 403 must refresh it
/// rather than re-serve the same, already-expired credential.
#[tokio::test]
async fn forced_cycle_refreshes_an_expired_self_minted_credential() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "orig-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain1-access", "refreshToken": "chain1-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_partial_json(
            serde_json::json!({"refreshToken": "chain1-refresh"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "accessToken": "chain2-access", "refreshToken": "chain2-refresh", "expiresIn": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );
    let src = source(&server, db)
        .await
        .with_validity_buffer(Duration::from_secs(7200));

    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain1-access"
    );

    // `chain1-access` is self-minted but already counts as expired under
    // this buffer: the bound (FIX D) must not re-serve it.
    src.invalidate().await;
    assert_eq!(
        src.with_token(|t| t.to_string()).await.unwrap(),
        "chain2-access"
    );
}

/// The one edge in the burn classification `refresh_cancelled_before_any_response_leaves_the_seed_usable`
/// cannot reach: wiremock's `set_delay` withholds the whole response
/// (status included), so it can only simulate a cancellation *before* the
/// status line arrives, never one *after* it while the body is still
/// pending. A raw listener can: it sends a status line and a
/// `content-length` header promising a body it then never sends, flushed
/// before it stalls forever on `std::future::pending`. `net.post()`
/// resolves as soon as headers are parsed (spec 3.2), so by the time the
/// caller is aborted, `refresh()` has already run past `refresh.rs`'s
/// `past_200.store(true, ...)` and is blocked on `resp.bytes_limited()`.
/// Determinism does not rest on the abort's timing: the listener never
/// completes the body on its own, so any abort that lands at all — even
/// one delayed well past the response — still lands after the status was
/// parsed, since there is nothing else the connection could be doing.
/// Counting accepted connections proves the second `with_token()` call
/// makes no network attempt at all once the seed is burned.
#[tokio::test]
async fn refresh_cancelled_after_a_200_status_burns_the_seed() {
    let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));

    let accepted = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                // However much of the request arrives is enough; only the
                // response side of this exchange matters to the test.
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\n")
                    .await;
                let _ = stream.flush().await;
                // No body ever follows: `resp.bytes_limited()` blocks here
                // for as long as the connection stays open.
                std::future::pending::<()>().await;
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let db = make_db_with(
        dir.path(),
        "2020-01-01T00:00:00Z",
        "orig-refresh",
        "old-access",
    );
    let net = Arc::new(Client::new(Policy::loopback_plain_http(port)).unwrap());
    let src = Arc::new(TokenSource::new(db, net, None));

    let s = src.clone();
    let cancelled = tokio::spawn(async move { s.with_token(|t| t.to_string()).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    cancelled.abort();
    let _ = cancelled.await;

    let err = src.with_token(|t| t.to_string()).await.unwrap_err();
    assert!(matches!(err, AuthError::ReauthRequired(_)), "{err}");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "a burned seed must never reach the network a second time"
    );
}
