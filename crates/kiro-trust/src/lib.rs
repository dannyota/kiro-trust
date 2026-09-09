//! See docs/specs/kiro-trust-design.md.

pub mod audit;
pub mod config;
pub mod env_cmd;
pub mod logging;
pub mod serve;
pub mod server;
pub mod token;

use clap::Parser;
use config::{Cli, Command};

/// Parse the CLI, dispatch, and return the process exit code (spec 4.4):
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
    }
}
