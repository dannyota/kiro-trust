//! `KIRO_TRUST_LOG` is validated the same way as `--log-level` (spec 4.5,
//! 6.4): an unrecognized value is a usage error, exit code 2, never a silent
//! fallback. This runs the real binary as a subprocess and asserts on its
//! actual exit status, rather than a `clap::Error::exit_code()` observed
//! in-process, so it proves what the shipped binary does.
//!
//! Setting the variable on `Command` only ever touches the child process's
//! environment, never this test binary's own, so unlike an in-process
//! `std::env::set_var` this needs no lock and no `unsafe` block: nothing
//! else in this process (or any concurrently running test, in this crate or
//! another) can observe or race the mutation.

use std::process::Command;

#[test]
fn an_invalid_kiro_trust_log_env_value_exits_2_with_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    // Never opened: clap validates `--log-level`/`KIRO_TRUST_LOG` while
    // parsing arguments, before `ServeConfig::from_args` resolves this path
    // or `serve::run` opens it. Passed anyway so this test can never reach
    // the real Kiro credential database if that ordering ever changes.
    let db_path = dir.path().join("unused.sqlite3");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("serve")
        .arg("--kiro-db")
        .arg(&db_path)
        // Never bound for the same reason as `db_path` above; passed so
        // this test can never bind a real port either.
        .arg("--listen")
        .arg("127.0.0.1:0")
        // A real tracing level ("trace") that this project deliberately
        // does not accept (spec 6.4), so this pins the actual policy
        // rather than rejecting obvious garbage.
        .env("KIRO_TRUST_LOG", "trace")
        .output()
        .expect("spawn kiro-trust");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Proves *why* it exited 2: the log-level value was rejected, not some
    // unrelated usage error that would also exit 2.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--log-level") && stderr.contains("trace"),
        "expected a --log-level usage error naming the rejected value, got:\n{stderr}"
    );
}
