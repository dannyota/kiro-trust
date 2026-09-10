//! Kiro runtime protocol client (spec 3.4).

mod client;
mod error;
pub mod headers;

pub use client::{AttemptProgress, KiroClient, RetryDelay, Upstream, UpstreamStream, retry_after};
pub use error::{UpstreamError, UpstreamErrorKind, classify_throttle};

// NOTICE distribution (final-fix-2.md Important 1; Apache-2.0 section 4(d)):
// this crate transcribes the Kiro runtime client, its retry backoff, and
// upstream error classification from kirocc (see NOTICE), so it needs its
// own copy since `cargo package` never reaches outside the crate directory.
// This test guards the copy at `crates/kiro-trust-kiro/NOTICE` against
// drifting from the workspace-root original.
#[cfg(test)]
mod notice_sync {
    #[test]
    fn crate_notice_matches_workspace_notice() {
        assert_eq!(
            include_str!("../NOTICE"),
            include_str!("../../../NOTICE"),
            "crates/kiro-trust-kiro/NOTICE has drifted from the workspace-root \
             NOTICE; keep them byte-identical"
        );
    }
}
