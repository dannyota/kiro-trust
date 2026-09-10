//! Flags, environment, and validation (spec 4). Precedence: flag, env, default.

use clap::{Args, Parser, Subcommand};
use kiro_trust_net::{ExtraCa, RegionError, RuntimeRegion};
use secrecy::SecretString;
use std::ffi::OsString;
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
    /// Run a command with the exports set in its environment (spec 4.4).
    Exec(ExecArgs),
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
    /// Additional PEM trust anchor, added to the compiled roots, never
    /// replacing them (spec 6.2, 4.1).
    #[arg(long, env = "KIRO_TRUST_EXTRA_CA")]
    pub extra_ca: Option<PathBuf>,
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
    /// Additional PEM trust anchor, added to the compiled roots, never
    /// replacing them (spec 6.2, 4.1). `audit` validates this file with no
    /// network access (spec 4.2, 6.6).
    #[arg(long, env = "KIRO_TRUST_EXTRA_CA")]
    pub extra_ca: Option<PathBuf>,
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

#[derive(Args, Debug, Clone)]
pub struct ExecArgs {
    #[arg(long, env = "KIRO_TRUST_LISTEN", default_value = DEFAULT_LISTEN)]
    pub listen: String,
    #[arg(long, env = "KIRO_TRUST_TOKEN_FILE")]
    pub token_file: Option<PathBuf>,
    /// `<cmd> [args...]`, everything after `--`. `trailing_var_arg` plus
    /// `allow_hyphen_values` (spec 4.4) means clap never interprets an
    /// argument here as one of its own flags, and `required = true` makes
    /// zero arguments a usage error (exit 2) rather than a silent no-op.
    /// `OsString`, not `String`: the child's argv must carry whatever bytes
    /// the caller passed, not just what is valid UTF-8.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub cmd: Vec<OsString>,
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
    /// A missing, unreadable, malformed, invalid-DER, or empty `--extra-ca`
    /// file (spec 4.1, 6.2). Names the path, exactly as given on the flag or
    /// through `KIRO_TRUST_EXTRA_CA`, but never certificate bytes: `reason`
    /// is `NetError::ExtraCa`'s fixed class when the file was read but
    /// failed to parse, or a plain I/O description when the file could not
    /// even be opened. Neither source ever carries certificate content.
    #[error("--extra-ca {path}: {reason}")]
    ExtraCa { path: PathBuf, reason: String },
}

pub struct ServeConfig {
    pub listen: SocketAddr,
    pub db_path: PathBuf,
    pub runtime_region: Option<RuntimeRegion>,
    pub token_file: PathBuf,
    pub explicit_token: Option<SecretString>,
    pub log_level: String,
    pub share_content: bool,
    pub extra_ca_path: Option<PathBuf>,
    pub extra_ca: Option<ExtraCa>,
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

/// Reads and parses `--extra-ca`'s file (spec 4.1, 6.2). `None` when the
/// flag was not given: the default policy stays byte-for-byte the same as
/// before this flag existed. A missing, unreadable, malformed, invalid-DER,
/// or empty file is `ConfigError::ExtraCa`, naming `path` but never the
/// file's bytes: an I/O failure is described by `std::io::Error`'s own
/// `Display`, which never echoes file content, and a parse failure is
/// `ExtraCaError`'s fixed reason class from `kiro-trust-net`, which by
/// construction (see `policy.rs`) never carries certificate bytes either.
pub fn read_extra_ca(path: Option<&PathBuf>) -> Result<Option<ExtraCa>, ConfigError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = std::fs::read(path).map_err(|e| ConfigError::ExtraCa {
        path: path.clone(),
        reason: e.to_string(),
    })?;
    let ca = ExtraCa::from_pem(&bytes).map_err(|e| ConfigError::ExtraCa {
        path: path.clone(),
        reason: e.to_string(),
    })?;
    Ok(Some(ca))
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
        // spec 4.1's startup order: `--extra-ca` is read and parsed here, as
        // part of config validation, which `serve::run` performs before it
        // opens the database, writes the token file, or binds the listener.
        // A bad file therefore fails before anything else has a side
        // effect to unwind.
        let extra_ca = read_extra_ca(args.extra_ca.as_ref())?;
        Ok(ServeConfig {
            listen,
            db_path: resolve_db_path(args.kiro_db)?,
            runtime_region,
            token_file: resolve_token_file(args.token_file)?,
            explicit_token,
            log_level: args.log_level,
            share_content: args.share_content,
            extra_ca_path: args.extra_ca,
            extra_ca,
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

    // spec 4.4: `exec -- <cmd> [args...]` preserves argument boundaries and
    // never treats a leading `-` in a child argument as one of clap's own
    // flags, and no command at all is a usage error (exit 2).
    #[test]
    fn exec_preserves_argument_boundaries_and_requires_a_command() {
        let cli = Cli::try_parse_from([
            "kiro-trust",
            "exec",
            "--",
            "echo",
            "two words",
            "-x",
            "--flag",
        ])
        .unwrap();
        let Command::Exec(args) = cli.command else {
            panic!()
        };
        assert_eq!(
            args.cmd,
            vec![
                OsString::from("echo"),
                OsString::from("two words"),
                OsString::from("-x"),
                OsString::from("--flag"),
            ]
        );

        let err = Cli::try_parse_from(["kiro-trust", "exec"]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn exec_accepts_listen_and_token_file_before_the_double_dash() {
        let cli = Cli::try_parse_from([
            "kiro-trust",
            "exec",
            "--listen",
            "127.0.0.1:9999",
            "--token-file",
            "/tmp/tok",
            "--",
            "true",
        ])
        .unwrap();
        let Command::Exec(args) = cli.command else {
            panic!()
        };
        assert_eq!(args.listen, "127.0.0.1:9999");
        assert_eq!(args.token_file, Some(PathBuf::from("/tmp/tok")));
        assert_eq!(args.cmd, vec![OsString::from("true")]);
    }

    // The shared test CA fixture: one self-signed P-256 CA certificate, public
    // part only, no private key (spec 6.2 validates `--extra-ca` against real
    // CA material, not just PEM framing). `include_str!` rather than a copied
    // literal so the four call sites across three crates cannot drift apart,
    // and so a rename breaks the build instead of one test at a time. See
    // `tests/fixtures/ca/README.md`.
    const TEST_CA_PEM: &str = include_str!("../../../tests/fixtures/ca/test-ca.crt");

    fn write_temp(dir: &std::path::Path, name: &str, contents: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    // spec 4.1: flag, then default (absent) precedence for --extra-ca on
    // ServeArgs. The env case (and flag-wins-over-env) is a subprocess test
    // in tests/extra_ca_env.rs: clap's `env` attribute reads real process
    // environment, and mutating that in-process here would race every
    // other test in this binary that runs concurrently (all `cargo test`
    // tests in one crate share one process and, by default, many threads),
    // exactly the hazard tests/log_level_env.rs's module doc already
    // documents for KIRO_TRUST_LOG.
    #[test]
    fn serve_extra_ca_flag_and_default() {
        let cli = Cli::try_parse_from(["kiro-trust", "serve"]).unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        assert_eq!(args.extra_ca, None, "absent by default");

        let cli =
            Cli::try_parse_from(["kiro-trust", "serve", "--extra-ca", "/flag/path.pem"]).unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        assert_eq!(args.extra_ca, Some(PathBuf::from("/flag/path.pem")));
    }

    #[test]
    fn audit_extra_ca_flag_and_default() {
        let cli = Cli::try_parse_from(["kiro-trust", "audit"]).unwrap();
        let Command::Audit(args) = cli.command else {
            panic!()
        };
        assert_eq!(args.extra_ca, None, "absent by default");

        let cli =
            Cli::try_parse_from(["kiro-trust", "audit", "--extra-ca", "/flag/audit.pem"]).unwrap();
        let Command::Audit(args) = cli.command else {
            panic!()
        };
        assert_eq!(args.extra_ca, Some(PathBuf::from("/flag/audit.pem")));
    }

    #[test]
    fn read_extra_ca_is_none_when_no_path_is_given() {
        assert!(read_extra_ca(None).unwrap().is_none());
    }

    #[test]
    fn read_extra_ca_rejects_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.pem");
        let err = read_extra_ca(Some(&path)).unwrap_err();
        let ConfigError::ExtraCa {
            path: err_path,
            reason,
        } = &err
        else {
            panic!("expected ConfigError::ExtraCa, got {err:?}");
        };
        assert_eq!(err_path, &path);
        // The io::Error text names the path already (that's expected and
        // fine: it is a path, not certificate content), but must never
        // contain anything that looks like PEM or DER payload.
        assert!(!reason.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn read_extra_ca_rejects_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(dir.path(), "empty.pem", b"");
        let err = read_extra_ca(Some(&path)).unwrap_err();
        let ConfigError::ExtraCa { reason, .. } = &err else {
            panic!("expected ConfigError::ExtraCa, got {err:?}");
        };
        assert!(reason.contains("no certificate") || reason.contains("extra CA rejected"));
    }

    #[test]
    fn read_extra_ca_rejects_a_malformed_pem_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(
            dir.path(),
            "malformed.pem",
            b"-----BEGIN CERTIFICATE-----\nnot valid base64!!!\n-----END CERTIFICATE-----\n",
        );
        let err = read_extra_ca(Some(&path)).unwrap_err();
        let ConfigError::ExtraCa { path: p, .. } = &err else {
            panic!("expected ConfigError::ExtraCa, got {err:?}");
        };
        assert_eq!(p, &path);
    }

    #[test]
    fn read_extra_ca_rejects_valid_pem_framing_with_invalid_der() {
        let dir = tempfile::tempdir().unwrap();
        // Valid base64, so the PEM layer accepts it, but the decoded bytes
        // are not a certificate: this proves the trust-anchor validation
        // actually runs, not just PEM/base64 framing (mirrors
        // kiro-trust-net's own `valid_pem_framing_with_garbage_der_is_rejected`).
        let garbage_der =
            b"not a certificate, just some bytes padded out to look substantial 1234567890";
        let body = base64_encode(garbage_der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
        let path = write_temp(dir.path(), "garbage-der.pem", pem.as_bytes());
        let err = read_extra_ca(Some(&path)).unwrap_err();
        let ConfigError::ExtraCa { reason, .. } = &err else {
            panic!("expected ConfigError::ExtraCa, got {err:?}");
        };
        assert!(reason.contains("trust anchor") || reason.contains("extra CA rejected"));
    }

    #[test]
    fn read_extra_ca_accepts_a_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(dir.path(), "valid.pem", TEST_CA_PEM.as_bytes());
        let ca = read_extra_ca(Some(&path)).unwrap();
        assert!(ca.is_some());
    }

    // Certificate bytes and the file path never enter the error's rendered
    // text in a way that would leak content: the error names the path (a
    // path is not a secret) but the PEM body itself must never appear.
    #[test]
    fn extra_ca_errors_never_carry_certificate_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(dir.path(), "malformed.pem", TEST_CA_PEM.as_bytes());
        // Corrupt the body so it fails, then check the rendered error.
        let mut corrupted = TEST_CA_PEM.as_bytes().to_vec();
        corrupted[100] = b'!';
        std::fs::write(&path, &corrupted).unwrap();
        if let Err(err) = read_extra_ca(Some(&path)) {
            let rendered = err.to_string();
            // The PEM body's base64 line must never appear verbatim.
            for line in TEST_CA_PEM.lines() {
                if !line.starts_with("-----") && line.len() > 8 {
                    assert!(
                        !rendered.contains(line),
                        "error text leaked a certificate body line: {rendered}"
                    );
                }
            }
        }
    }

    /// Minimal base64 encoder, mirroring kiro-trust-net's own test helper,
    /// so this one fixture does not need a base64 crate dependency.
    fn base64_encode(input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
            out.push(if chunk.len() > 1 {
                CHARS[((n >> 6) & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                CHARS[(n & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    // spec 4.1: from_args reads and parses --extra-ca as part of config
    // validation, before serve::run does anything with side effects.
    #[test]
    fn serve_config_from_args_reads_and_parses_extra_ca() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(dir.path(), "valid.pem", TEST_CA_PEM.as_bytes());
        let cli = Cli::try_parse_from([
            "kiro-trust",
            "serve",
            "--kiro-db",
            "/tmp/x.sqlite3",
            "--extra-ca",
            path.to_str().unwrap(),
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        let cfg = ServeConfig::from_args(args).unwrap();
        assert_eq!(cfg.extra_ca_path, Some(path));
        assert!(cfg.extra_ca.is_some());
    }

    #[test]
    fn serve_config_from_args_fails_on_a_bad_extra_ca_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.pem");
        let cli = Cli::try_parse_from([
            "kiro-trust",
            "serve",
            "--kiro-db",
            "/tmp/x.sqlite3",
            "--extra-ca",
            path.to_str().unwrap(),
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        let result = ServeConfig::from_args(args);
        match result {
            Err(ConfigError::ExtraCa { .. }) => {}
            Ok(_) => panic!("expected ConfigError::ExtraCa, got Ok"),
            Err(other) => panic!("expected ConfigError::ExtraCa, got {other}"),
        }
    }

    #[test]
    fn serve_config_from_args_extra_ca_is_none_by_default() {
        let cli =
            Cli::try_parse_from(["kiro-trust", "serve", "--kiro-db", "/tmp/x.sqlite3"]).unwrap();
        let Command::Serve(args) = cli.command else {
            panic!()
        };
        let cfg = ServeConfig::from_args(args).unwrap();
        assert!(cfg.extra_ca_path.is_none());
        assert!(cfg.extra_ca.is_none());
    }
}
