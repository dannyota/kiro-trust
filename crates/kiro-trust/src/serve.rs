//! `kiro-trust serve` (spec 4.1).

use crate::config::ServeConfig;
use crate::listener::{ConnectionInfo, GuardedListener, HEADER_READ_TIMEOUT, MAX_CONNECTIONS};
use crate::server::{AppState, MAX_CONCURRENT, build_router};
use crate::token;
use kiro_trust_auth::{KiroDb, TokenSource};
use kiro_trust_kiro::KiroClient;
use kiro_trust_net::{Client, Policy};
use std::sync::Arc;
use std::time::Duration;

/// The outbound policy this command serves with: the production policy, plus
/// the parsed `--extra-ca` anchors when one was configured (spec 4.1, 6.2).
///
/// A free function rather than two lines inline so a test can assert on the
/// policy itself. Mutating the inline version to parse the CA and discard it
/// left the entire workspace suite green while the shipped proxy silently
/// stopped honoring `--extra-ca` (v020-ca-wiring-review.md, finding 2), the
/// same defect class already found one layer down in `Client::new`.
fn build_policy(extra_ca: Option<kiro_trust_net::ExtraCa>) -> Policy {
    match extra_ca {
        Some(ca) => Policy::production().with_extra_ca(ca),
        None => Policy::production(),
    }
}

pub async fn run(mut cfg: ServeConfig) -> Result<(), String> {
    // Fail fast on the credential before binding anything.
    let creds = KiroDb::open_read_only(&cfg.db_path)
        .and_then(|db| db.read_identity_center())
        .map_err(|e| e.to_string())?;
    let runtime_region = cfg
        .runtime_region
        .clone()
        .unwrap_or_else(|| creds.runtime_region.clone());
    drop(creds);

    let net = Arc::new(Client::new(build_policy(cfg.extra_ca.take())).map_err(|e| e.to_string())?);
    let tokens = Arc::new(TokenSource::new(
        cfg.db_path.clone(),
        net.clone(),
        cfg.runtime_region.clone(),
    ));
    let upstream = Arc::new(KiroClient::new(net, tokens.clone(), cfg.share_content));

    #[cfg(feature = "capture")]
    let capture = match &cfg.capture_dir {
        Some(dir) => {
            let handle = crate::server::capture::Capture::new(dir)
                .map_err(|e| format!("cannot create capture directory {}: {e}", dir.display()))?;
            eprintln!(
                "kiro-trust: capture enabled, writing prompts and responses to {}",
                dir.display()
            );
            Some(Arc::new(handle))
        }
        None => None,
    };

    let (local_token, wrote_file) = match cfg.explicit_token.clone() {
        Some(t) => (t, false),
        None => {
            let t = token::generate();
            token::write_token_file(&cfg.token_file, &t).map_err(|e| {
                format!("cannot write token file {}: {e}", cfg.token_file.display())
            })?;
            (t, true)
        }
    };
    // Never a constant: the salt derives Kiro conversation ids from the
    // Claude Code session id (spec 5.3) and must not be predictable.
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| {
        // The token file was already written; leaving it behind on this
        // early failure would strand a stale token, so clean it up too.
        if wrote_file {
            let _ = token::remove_token_file(&cfg.token_file);
        }
        format!("cannot obtain operating system randomness: {e}")
    })?;
    let state = Arc::new(AppState {
        tokens,
        upstream,
        local_token,
        limiter: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT)),
        usage: Arc::new(crate::server::usage::UsageSummary::new()),
        conversation_salt: salt,
        #[cfg(feature = "capture")]
        capture,
    });

    let listener = match tokio::net::TcpListener::bind(cfg.listen).await {
        Ok(l) => l,
        Err(e) => {
            if wrote_file {
                let _ = token::remove_token_file(&cfg.token_file);
            }
            return Err(format!("cannot bind {}: {e}", cfg.listen));
        }
    };
    eprintln!(
        "kiro-trust listening on http://{} (runtime region {runtime_region}); token file {}",
        cfg.listen,
        if wrote_file {
            cfg.token_file.display().to_string()
        } else {
            "not written (KIRO_TRUST_TOKEN set)".into()
        }
    );
    eprintln!("run: eval \"$(kiro-trust env)\"");

    let token_file = cfg.token_file.clone();
    let shutdown = async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
        }
        tracing::info!("shutdown requested, draining for up to 10s");
        // Delete the token file the instant the signal arrives, so no new
        // client can read a valid token during the drain that follows.
        // `axum::serve`'s graceful shutdown stops accepting new connections
        // only once this future returns, which happens right after the
        // deadline task below is spawned; existing connections then get up
        // to 10 s to finish before that task force-exits regardless
        // (spec 4.1).
        if wrote_file {
            let _ = token::remove_token_file(&token_file);
        }
        tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            tracing::warn!("drain deadline reached, exiting");
            // The deadline is a policy bound, not a failure: a streaming
            // response can outlive the drain window, so exit 0 per spec 4.1
            // and 4.5. The warn line above distinguishes this path. Known
            // and accepted: an axum::serve error inside the window is masked.
            std::process::exit(0);
        });
    };
    let result = axum::serve(
        GuardedListener::new(listener, MAX_CONNECTIONS, HEADER_READ_TIMEOUT),
        build_router(state).into_make_service_with_connect_info::<ConnectionInfo>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .map_err(|e| e.to_string());
    // The shutdown future above already removes the file on a graceful
    // signal; this second removal is the harmless idempotent path for
    // whichever way `serve` actually returns (spec 6.3).
    if wrote_file {
        let _ = token::remove_token_file(&cfg.token_file);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Cli, Command, ServeConfig, read_extra_ca};
    use clap::Parser;

    /// The regression test for v020-ca-wiring-review.md finding 2: mutating
    /// `run` to parse the CA and discard it left every other test green while
    /// the shipped proxy stopped honoring `--extra-ca`. `Policy`'s `Debug`
    /// renders `ExtraCa`'s certificate count and never its bytes, which is
    /// exactly enough to tell an installed anchor from a dropped one.
    #[test]
    fn build_policy_installs_a_configured_extra_ca_and_omits_it_otherwise() {
        let rendered = format!("{:?}", build_policy(None));
        assert!(
            rendered.contains("extra_ca: None"),
            "no configured CA must leave the policy without one: {rendered}"
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ca.crt");
        std::fs::write(
            &path,
            include_str!("../../../tests/fixtures/ca/test-ca.crt"),
        )
        .unwrap();
        let ca = read_extra_ca(Some(&path)).unwrap().expect("valid test CA");
        let rendered = format!("{:?}", build_policy(Some(ca)));
        assert!(
            rendered.contains("certificate_count: 1"),
            "a configured CA must reach the policy: {rendered}"
        );
        assert!(
            !rendered.contains("BEGIN CERTIFICATE"),
            "the policy must never render certificate bytes: {rendered}"
        );
    }

    // spec 4.1: fail fast on the credential before binding anything, and
    // never leave a token file behind when that happens. A nonexistent
    // database path is enough to make `open_read_only` fail without
    // needing a real (or even syntactically valid) database.
    #[tokio::test]
    async fn missing_credentials_fail_before_writing_a_token_file() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("no-such-data.sqlite3");
        let token_file = dir.path().join("run").join("token");
        let cli = Cli::try_parse_from([
            "kiro-trust",
            "serve",
            "--kiro-db",
            db_path.to_str().unwrap(),
            "--token-file",
            token_file.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        let cfg = ServeConfig::from_args(args).unwrap();
        let err = run(cfg).await.unwrap_err();
        assert!(!err.is_empty());
        assert!(
            !token_file.exists(),
            "no token file on a credential failure"
        );
    }
}
