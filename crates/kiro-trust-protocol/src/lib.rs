//! Pure protocol types and translation for kiro-trust. No I/O, no network,
//! no SQLite, no async runtime (spec 3.1).

pub mod anthropic;
pub mod catalog;
pub mod estimate;
pub mod eventstream;
pub mod kiro;
pub mod sanitize;
pub mod sse;
pub mod translate;

// NOTICE distribution (final-fix-2.md Important 1; Apache-2.0 section 4(d)):
// `cargo package` only ever includes files inside a crate's own directory,
// so the workspace-root `NOTICE` cannot reach crates.io by reference. This
// crate holds most of the kirocc-derived translation code, so it carries a
// byte-identical copy at `crates/kiro-trust-protocol/NOTICE`; this test is
// the guard against that copy drifting from the original.
#[cfg(test)]
mod notice_sync {
    #[test]
    fn crate_notice_matches_workspace_notice() {
        assert_eq!(
            include_str!("../NOTICE"),
            include_str!("../../../NOTICE"),
            "crates/kiro-trust-protocol/NOTICE has drifted from the \
             workspace-root NOTICE; keep them byte-identical"
        );
    }
}
