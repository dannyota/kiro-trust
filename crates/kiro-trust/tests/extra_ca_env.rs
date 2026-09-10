//! `--extra-ca`/`KIRO_TRUST_EXTRA_CA` flag/env/default precedence for both
//! `serve` and `audit` (spec 4.1, 4.2, 6.2, 6.6), and that no home directory
//! or certificate byte reaches process output at any step.
//!
//! Every case here spawns the real binary and sets the environment
//! variable only on that child `Command`, never in this test binary's own
//! process: an in-process `std::env::set_var("KIRO_TRUST_EXTRA_CA", ...)`
//! would race every other test in this crate that constructs a `ServeArgs`
//! or `AuditArgs` concurrently (all tests in one crate share one process
//! and, by default, many threads), which is exactly why
//! `tests/log_level_env.rs` uses the same `Command::env` pattern for
//! `KIRO_TRUST_LOG` instead of an in-process mutation.

use std::process::Command;

/// The shared test CA fixture: one self-signed P-256 CA certificate, public
/// part only, no private key (spec 6.2 validates `--extra-ca` against real CA
/// material, not just PEM framing). `include_str!` rather than a copied
/// literal so the four call sites across three crates cannot drift apart, and
/// so a rename breaks the build instead of one test at a time. See
/// `tests/fixtures/ca/README.md`.
const TEST_CA_PEM: &str = include_str!("../../../tests/fixtures/ca/test-ca.crt");

// spec 4.1: a missing/malformed --extra-ca file (whether from the flag or
// KIRO_TRUST_EXTRA_CA) is a configuration error that exits 2, before the
// database is opened, the token file is written, or anything binds. A
// nonexistent --kiro-db and --listen 127.0.0.1:0 are passed anyway so this
// test can never touch the real Kiro credential database or bind a real
// port if the startup order ever regresses.
#[test]
fn serve_extra_ca_env_is_used_when_the_flag_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("unused.sqlite3");
    let missing_ca = dir.path().join("no-such-ca.pem");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("serve")
        .arg("--kiro-db")
        .arg(&db_path)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .env("KIRO_TRUST_EXTRA_CA", &missing_ca)
        .output()
        .expect("spawn kiro-trust");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&missing_ca.display().to_string()),
        "expected the env-supplied path in the error, got:\n{stderr}"
    );
}

// spec 4.1: the flag wins over the environment variable, the same
// precedence every other ServeArgs field documents.
#[test]
fn serve_extra_ca_flag_wins_over_env() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("unused.sqlite3");
    let env_missing_ca = dir.path().join("env-no-such-ca.pem");
    let flag_missing_ca = dir.path().join("flag-no-such-ca.pem");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("serve")
        .arg("--kiro-db")
        .arg(&db_path)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--extra-ca")
        .arg(&flag_missing_ca)
        .env("KIRO_TRUST_EXTRA_CA", &env_missing_ca)
        .output()
        .expect("spawn kiro-trust");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&flag_missing_ca.display().to_string()),
        "expected the flag path (not the env path) in the error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains(&env_missing_ca.display().to_string()),
        "the env path must not appear once the flag overrides it, got:\n{stderr}"
    );
}

// spec 4.1: with neither flag nor env set, --extra-ca is absent and serve
// proceeds past config validation (it still fails shortly after, on the
// nonexistent database, but that is a different, later failure than a
// ConfigError::ExtraCa).
#[test]
fn serve_extra_ca_absent_by_default_does_not_produce_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("still-missing.sqlite3");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("serve")
        .arg("--kiro-db")
        .arg(&db_path)
        .arg("--listen")
        .arg("127.0.0.1:0")
        .env_remove("KIRO_TRUST_EXTRA_CA")
        .output()
        .expect("spawn kiro-trust");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("--extra-ca"),
        "no --extra-ca error should appear when the flag/env are both absent, got:\n{stderr}"
    );
}

// spec 6.6: `audit` reads KIRO_TRUST_EXTRA_CA the same way `serve` does,
// and shows the configured path (abbreviated, never the certificate
// bytes) in its text output when the file is valid.
#[test]
fn audit_extra_ca_env_is_shown_in_text_output() {
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("valid-ca.pem");
    std::fs::write(&ca_path, TEST_CA_PEM).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("audit")
        .arg("--kiro-db")
        .arg(kiro_test_db_path())
        .env("KIRO_TRUST_EXTRA_CA", &ca_path)
        .output()
        .expect("spawn kiro-trust");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("Extra CA               {}", ca_path.display())),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!stdout.contains("BEGIN CERTIFICATE"));
}

// spec 6.6: the flag wins over the environment variable for `audit` too.
#[test]
fn audit_extra_ca_flag_wins_over_env() {
    let dir = tempfile::tempdir().unwrap();
    let env_ca = dir.path().join("env-ca.pem");
    let flag_ca = dir.path().join("flag-ca.pem");
    std::fs::write(&env_ca, TEST_CA_PEM).unwrap();
    std::fs::write(&flag_ca, TEST_CA_PEM).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("audit")
        .arg("--kiro-db")
        .arg(kiro_test_db_path())
        .arg("--extra-ca")
        .arg(&flag_ca)
        .env("KIRO_TRUST_EXTRA_CA", &env_ca)
        .output()
        .expect("spawn kiro-trust");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&flag_ca.display().to_string()));
    assert!(!stdout.contains(&env_ca.display().to_string()));
}

// spec 4.2, 6.6: with neither flag nor env set, `audit` prints `none`.
#[test]
fn audit_extra_ca_absent_by_default_prints_none() {
    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("audit")
        .arg("--kiro-db")
        .arg(kiro_test_db_path())
        .env_remove("KIRO_TRUST_EXTRA_CA")
        .output()
        .expect("spawn kiro-trust");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Extra CA               none"), "{stdout}");
}

/// The workspace's committed synthetic database fixture (spec 8.7),
/// resolved from this crate's manifest directory so the test works
/// regardless of the process's current directory.
fn kiro_test_db_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/db/idc.sqlite3")
}
