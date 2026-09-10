//! The explicit discovery command keeps configuration and authentication
//! failures bounded, even when caller-provided paths contain terminal control
//! bytes or are very long.

use std::process::Command;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kiro-trust"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("KIRO_TRUST_") {
            command.env_remove(name);
        }
    }
    command.arg("models").arg("discover");
    command
}

fn assert_fixed_config_error(output: std::process::Output, raw_path: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(stderr, "kiro-trust: discovery configuration invalid\n");
    assert!(!stderr.contains(raw_path));
}

#[test]
fn discovery_configuration_errors_are_fixed_for_text_and_json() {
    let directory = tempfile::tempdir().unwrap();
    let missing_with_escape = directory.path().join("missing-\x1b[2J.pem");
    let missing_with_newline = directory.path().join("missing-\nname.pem");
    let overlong_missing = directory
        .path()
        .join(format!("{}.pem", "x".repeat(16 * 1024)));
    let malformed = directory.path().join("malformed-safe-name.pem");
    std::fs::write(&malformed, "not a PEM\n").unwrap();

    for json in [false, true] {
        for path in [
            &missing_with_escape,
            &missing_with_newline,
            &overlong_missing,
            &malformed,
        ] {
            let mut child = command();
            child
                .arg("--kiro-db")
                .arg(directory.path().join("missing.sqlite3"));
            child.arg("--extra-ca").arg(path);
            if json {
                child.arg("--json");
            }
            assert_fixed_config_error(child.output().unwrap(), &path.display().to_string());
        }
    }
}

#[test]
fn discovery_authentication_error_never_echoes_a_db_path() {
    let directory = tempfile::tempdir().unwrap();
    let raw_name = format!("db-\x1b[2J-{}.sqlite3", "x".repeat(128));
    let missing = directory.path().join(&raw_name);

    for json in [false, true] {
        let mut child = command();
        child.arg("--kiro-db").arg(&missing);
        if json {
            child.arg("--json");
        }
        let output = child.output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert_eq!(stderr, "kiro-trust: authentication failed\n");
        assert!(!stderr.contains(&missing.display().to_string()));
    }
}
