//! See docs/specs/kiro-trust-design.md.

pub mod audit;
pub mod config;
pub mod env_cmd;
pub mod exec_cmd;
pub mod listener;
pub mod logging;
pub mod serve;
pub mod server;
pub mod token;

use clap::Parser;
use config::{Cli, Command};

/// Parse the CLI, dispatch, and return the process exit code (spec 4.5):
/// `0` success, `1` runtime failure, `2` usage or configuration error.
pub fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => {
            let cfg = match config::ServeConfig::from_args(args) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("kiro-trust: {e}");
                    return 2;
                }
            };
            if let Err(e) = logging::init(&cfg.log_level) {
                eprintln!("kiro-trust: {e}");
                return 2;
            }
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("kiro-trust: cannot start async runtime: {e}");
                    return 1;
                }
            };
            match rt.block_on(serve::run(cfg)) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("kiro-trust: {e}");
                    1
                }
            }
        }
        Command::Audit(args) => audit::run(args),
        Command::Env(args) => env_cmd::run(args),
        Command::Exec(args) => exec_cmd::run(args),
    }
}

// NOTICE distribution (final-fix-2.md Important 1; Apache-2.0 section 4(d)):
// `server::models::get_models` builds the `GET /v1/models` envelope
// transcribed from kirocc `internal/server/handlers.go` (see NOTICE), so
// this crate needs its own copy since `cargo package` never reaches outside
// the crate directory. This test guards the copy at `crates/kiro-trust/NOTICE`
// against drifting from the workspace-root original.
#[cfg(test)]
mod notice_sync {
    #[test]
    fn crate_notice_matches_workspace_notice() {
        assert_eq!(
            include_str!("../NOTICE"),
            include_str!("../../../NOTICE"),
            "crates/kiro-trust/NOTICE has drifted from the workspace-root \
             NOTICE; keep them byte-identical"
        );
    }
}
