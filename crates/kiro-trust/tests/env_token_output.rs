//! `kiro-trust env` prints the token to stdout only, and never on a failure
//! path (spec 4.3; task-20-rulings.md ruling 3). Run as subprocesses, like
//! `log_level_env.rs`, so this proves what the shipped binary actually
//! writes to each stream rather than something observed in-process.

use kiro_trust::token;
use secrecy::ExposeSecret;
use std::process::Command;

#[test]
fn missing_token_file_prints_nothing_to_stdout_and_no_token_anywhere() {
    let dir = tempfile::tempdir().unwrap();
    // Never created: the failure path this test targets.
    let token_file = dir.path().join("token");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("env")
        .arg("--token-file")
        .arg(&token_file)
        .output()
        .expect("spawn kiro-trust");

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a failure path must print nothing to stdout, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no token file at"),
        "expected the no-token-file message, got:\n{stderr}"
    );
}

#[test]
fn existing_token_file_prints_the_token_to_stdout_only() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    let local_token = token::generate();
    token::write_token_file(&token_file, &local_token).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("env")
        .arg("--token-file")
        .arg(&token_file)
        .arg("--listen")
        .arg("127.0.0.1:3456")
        .output()
        .expect("spawn kiro-trust");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(&format!(
            "export ANTHROPIC_AUTH_TOKEN={}",
            local_token.expose_secret()
        )),
        "expected the token export on stdout, got:\n{stdout}"
    );
    assert!(
        stderr.is_empty(),
        "expected empty stderr on success, got:\n{stderr}"
    );
    assert!(
        !stderr.contains(local_token.expose_secret()),
        "the token must never reach stderr"
    );
}
