//! Flags, environment, and validation (spec 4). Precedence: flag, env, default.

use clap::{Args, Parser, Subcommand};
use kiro_trust_net::{RegionError, RuntimeRegion};
use secrecy::SecretString;
use std::net::SocketAddr;
use std::path::PathBuf;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:3456";

#[derive(Parser, Debug)]
#[command(
    name = "kiro-trust",
    version,
    about = "Security-first local trust proxy for Claude Code and Kiro"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the loopback proxy.
    Serve(ServeArgs),
    /// Print the effective security configuration.
    Audit(AuditArgs),
    /// Print the exports Claude Code needs.
    Env(EnvArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    #[arg(long, env = "KIRO_TRUST_LISTEN", default_value = DEFAULT_LISTEN)]
    pub listen: String,
    #[arg(long, env = "KIRO_TRUST_DB")]
    pub kiro_db: Option<PathBuf>,
    #[arg(long, env = "KIRO_TRUST_RUNTIME_REGION")]
    pub runtime_region: Option<String>,
    #[arg(long, env = "KIRO_TRUST_TOKEN_FILE")]
    pub token_file: Option<PathBuf>,
    // spec 6.4: only these four levels are accepted, from either the flag
    // or `KIRO_TRUST_LOG`, so an unrecognized value is a usage error (exit
    // 2) rather than a silent fallback, and `logging::filter` never has to
    // treat a value wider than these as trusted input.
    #[arg(
        long,
        env = "KIRO_TRUST_LOG",
        default_value = "info",
        value_parser = ["error", "warn", "info", "debug"]
    )]
    pub log_level: String,
    /// Send x-amzn-codewhisperer-optout: false (spec 7.4).
    #[arg(long, env = "KIRO_TRUST_SHARE_CONTENT", default_value_t = false)]
    pub share_content: bool,
    #[cfg(feature = "capture")]
    #[arg(long)]
    pub capture_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct AuditArgs {
    #[arg(long)]
    pub json: bool,
    #[arg(long, env = "KIRO_TRUST_LISTEN", default_value = DEFAULT_LISTEN)]
    pub listen: String,
    #[arg(long, env = "KIRO_TRUST_DB")]
    pub kiro_db: Option<PathBuf>,
    #[arg(long, env = "KIRO_TRUST_RUNTIME_REGION")]
    pub runtime_region: Option<String>,
    #[arg(long, env = "KIRO_TRUST_TOKEN_FILE")]
    pub token_file: Option<PathBuf>,
    #[arg(long, env = "KIRO_TRUST_SHARE_CONTENT", default_value_t = false)]
    pub share_content: bool,
}

#[derive(Args, Debug, Clone)]
pub struct EnvArgs {
    #[arg(long, env = "KIRO_TRUST_LISTEN", default_value = DEFAULT_LISTEN)]
    pub listen: String,
    #[arg(long, env = "KIRO_TRUST_TOKEN_FILE")]
    pub token_file: Option<PathBuf>,
    #[arg(long, default_value = "sh", value_parser = ["sh", "fish"])]
    pub shell: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "--listen {0} is not a loopback address; kiro-trust binds 127.0.0.0/8 or ::1 only (spec 6.3)"
    )]
    NotLoopback(SocketAddr),
    #[error("--listen {0:?} is not a socket address like 127.0.0.1:3456")]
    BadListen(String),
    #[error("{0}")]
    Region(#[from] RegionError),
    #[error("cannot determine the Kiro CLI database path; pass --kiro-db")]
    NoDbPath,
    #[error("cannot determine a runtime directory for the token file; pass --token-file")]
    NoTokenDir,
}

pub struct ServeConfig {
    pub listen: SocketAddr,
    pub db_path: PathBuf,
    pub runtime_region: Option<RuntimeRegion>,
    pub token_file: PathBuf,
    pub explicit_token: Option<SecretString>,
    pub log_level: String,
    pub share_content: bool,
    pub capture_dir: Option<PathBuf>,
}

pub fn parse_listen(s: &str) -> Result<SocketAddr, ConfigError> {
    let addr: SocketAddr = s
        .parse()
        .map_err(|_| ConfigError::BadListen(s.to_string()))?;
    validate_loopback(addr)?;
    Ok(addr)
}

pub fn validate_loopback(addr: SocketAddr) -> Result<(), ConfigError> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(ConfigError::NotLoopback(addr))
    }
}

/// Linux: $XDG_RUNTIME_DIR/kiro-trust/token, else ~/.local/state/kiro-trust/token;
/// macOS and Windows: the user's local data dir (spec 6.3).
pub fn default_token_file() -> Option<PathBuf> {
    let base = directories::BaseDirs::new()?;
    let dir = base
        .runtime_dir()
        .map(|d| d.to_path_buf())
        .or_else(|| base.state_dir().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| base.data_local_dir().to_path_buf());
    Some(dir.join("kiro-trust").join("token"))
}

pub fn resolve_db_path(explicit: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    explicit
        .or_else(kiro_trust_auth::default_db_path)
        .ok_or(ConfigError::NoDbPath)
}

pub fn resolve_token_file(explicit: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    explicit
        .or_else(default_token_file)
        .ok_or(ConfigError::NoTokenDir)
}

impl ServeConfig {
    pub fn from_args(args: ServeArgs) -> Result<Self, ConfigError> {
        let listen = parse_listen(&args.listen)?;
        let runtime_region = args
            .runtime_region
            .as_deref()
            .map(RuntimeRegion::parse)
            .transpose()?;
        // Read the explicit token outside clap so it never appears in --help
        // output or argument lists.
        let explicit_token = std::env::var("KIRO_TRUST_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .map(SecretString::from);
        #[cfg(feature = "capture")]
        let capture_dir = args.capture_dir.clone();
        #[cfg(not(feature = "capture"))]
        let capture_dir = None;
        Ok(ServeConfig {
            listen,
            db_path: resolve_db_path(args.kiro_db)?,
            runtime_region,
            token_file: resolve_token_file(args.token_file)?,
            explicit_token,
            log_level: args.log_level,
            share_content: args.share_content,
            capture_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // spec 6.3 non_loopback_bind_fails
    #[test]
    fn only_loopback_addresses_are_accepted() {
        for ok in ["127.0.0.1:3456", "127.1.2.3:1", "[::1]:3456"] {
            assert!(validate_loopback(ok.parse().unwrap()).is_ok(), "{ok}");
        }
        for bad in [
            "0.0.0.0:3456",
            "192.168.1.10:3456",
            "[::]:3456",
            "10.0.0.1:80",
        ] {
            assert!(
                matches!(
                    validate_loopback(bad.parse().unwrap()),
                    Err(ConfigError::NotLoopback(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn serve_config_applies_defaults_and_validates() {
        let cli =
            Cli::try_parse_from(["kiro-trust", "serve", "--kiro-db", "/tmp/x.sqlite3"]).unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        let cfg = ServeConfig::from_args(args).unwrap();
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:3456");
        assert_eq!(cfg.db_path, PathBuf::from("/tmp/x.sqlite3"));
        assert!(cfg.runtime_region.is_none());
        assert!(!cfg.share_content);
        assert_eq!(cfg.log_level, "info");
        assert!(cfg.token_file.ends_with("kiro-trust/token"));

        let cli = Cli::try_parse_from(["kiro-trust", "serve", "--listen", "0.0.0.0:3456"]).unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        assert!(matches!(
            ServeConfig::from_args(args),
            Err(ConfigError::NotLoopback(_))
        ));

        let cli =
            Cli::try_parse_from(["kiro-trust", "serve", "--runtime-region", "ap-southeast-1"])
                .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        assert!(matches!(
            ServeConfig::from_args(args),
            Err(ConfigError::Region(_))
        ));

        let cli = Cli::try_parse_from([
            "kiro-trust",
            "serve",
            "--runtime-region",
            "eu-central-1",
            "--share-content",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        let cfg = ServeConfig::from_args(args).unwrap();
        assert_eq!(cfg.runtime_region.unwrap().as_str(), "eu-central-1");
        assert!(cfg.share_content);
    }

    // Important 1 (task-19-fix-1): an unrecognized --log-level is a usage
    // error, not a silent fallback, and it never reaches `logging::filter`.
    #[test]
    fn an_invalid_log_level_flag_is_rejected_with_a_usage_error() {
        let err = Cli::try_parse_from(["kiro-trust", "serve", "--log-level", "trace"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);

        for level in ["error", "warn", "info", "debug"] {
            assert!(
                Cli::try_parse_from(["kiro-trust", "serve", "--log-level", level]).is_ok(),
                "{level} should be accepted"
            );
        }
    }

    #[test]
    fn subcommands_parse() {
        assert!(matches!(
            Cli::try_parse_from(["kiro-trust", "audit", "--json"])
                .unwrap()
                .command,
            Command::Audit(AuditArgs { json: true, .. })
        ));
        assert!(matches!(
            Cli::try_parse_from(["kiro-trust", "env", "--shell", "fish"])
                .unwrap()
                .command,
            Command::Env(_)
        ));
        assert!(
            Cli::try_parse_from(["kiro-trust", "serve", "--debug-body"]).is_err(),
            "no body logging flag exists"
        );
    }
}
