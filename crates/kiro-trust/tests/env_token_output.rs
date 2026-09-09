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
        stderr.contains("cannot read token file"),
        "expected the cannot-read-token-file message, got:\n{stderr}"
    );
}

#[test]
fn existing_token_file_prints_the_token_single_quoted_on_exactly_two_lines() {
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
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected exactly two lines, got:\n{stdout}");
    assert_eq!(
        lines[0],
        "export ANTHROPIC_BASE_URL='http://127.0.0.1:3456'"
    );
    assert_eq!(
        lines[1],
        format!(
            "export ANTHROPIC_AUTH_TOKEN='{}'",
            local_token.expose_secret()
        ),
        "expected the token single-quoted on stdout, got:\n{stdout}"
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

// task-20-fix-1.md Critical 1: the reviewer's exact reproduction against the
// release binary. A token file containing a newline must never reach stdout
// unquoted, because the documented usage is `eval "$(kiro-trust env)"`.
#[test]
fn a_token_file_containing_a_newline_is_rejected_without_executing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "abc\nID=$(id -u)\n").unwrap();

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
        "a malformed token file must print nothing to stdout, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("id -u") && !stderr.contains("abc"),
        "the malformed token file's content must never appear in the error, got:\n{stderr}"
    );
}

// task-20-fix-1.md Critical 1 test list: a token containing a `;`, a
// backtick, a `$(`, or a single quote is rejected by the shape check, each
// spliced into an otherwise well-formed 43-character value.
#[test]
fn tokens_shaped_with_shell_metacharacters_are_rejected() {
    for bad in [";", "`", "$(", "'"] {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        let mut content = "A".repeat(43);
        content.replace_range(20..20 + bad.len(), bad);
        std::fs::write(&token_file, &content).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
            .arg("env")
            .arg("--token-file")
            .arg(&token_file)
            .output()
            .expect("spawn kiro-trust");

        assert_eq!(
            output.status.code(),
            Some(1),
            "{bad:?}: stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "{bad:?}: must print nothing to stdout, got: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains(&content),
            "{bad:?}: the malformed token must never appear in the error, got:\n{stderr}"
        );
    }
}
