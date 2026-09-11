//! `doctor` is an offline diagnostic unless the caller explicitly requests a
//! fixed loopback health probe. Every case starts the real binary with only
//! the relevant `KIRO_TRUST_*` environment, so it cannot touch a developer's
//! credential database, token file, or listener.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture_db() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/db/idc.sqlite3")
}

fn command(dir: &Path) -> Command {
    command_for(&fixture_db(), &dir.join("token"), "127.0.0.1:9")
}

fn base_command(db: &Path, token: &Path, listen: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kiro-trust"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("KIRO_TRUST_") {
            command.env_remove(name);
        }
    }
    command
        .arg("doctor")
        .arg("--kiro-db")
        .arg(db)
        .arg("--token-file")
        .arg(token)
        .arg("--listen")
        .arg(listen);
    command
}

fn command_for(db: &Path, token: &Path, listen: &str) -> Command {
    let mut command = base_command(db, token, listen);
    command.arg("--json");
    command
}

fn path_command(position: &str, path: &Path, base: &Path, json: bool) -> Command {
    let mut command = match position {
        "database" => base_command(path, base, "127.0.0.1:9"),
        "token_file" => base_command(&fixture_db(), path, "127.0.0.1:9"),
        "extra_ca" => {
            let mut command = base_command(&fixture_db(), base, "127.0.0.1:9");
            command.arg("--extra-ca").arg(path);
            command
        }
        _ => unreachable!(),
    };
    if json {
        command.arg("--json");
    }
    command
}

fn report(output: Output) -> serde_json::Value {
    assert!(
        output.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("doctor report JSON")
}

fn check<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|check| check["name"] == name)
        .unwrap_or_else(|| panic!("missing {name} check: {report}"))
}

fn assert_check(report: &serde_json::Value, name: &str, status: &str, detail: &str) {
    let actual = check(report, name);
    assert_eq!(actual["status"], status, "{name}");
    assert_eq!(actual["detail"], detail, "{name}");
}

#[test]
fn doctor_missing_token_warns() {
    let dir = tempfile::tempdir().unwrap();
    let output = command(dir.path()).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report = report(output);
    let checks = report["checks"].as_array().expect("checks array");
    assert_eq!(checks.len(), 5);
    assert_eq!(
        checks
            .iter()
            .map(|check| check["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "configuration",
            "database",
            "credential_expiry",
            "local_token",
            "listener",
        ]
    );
    assert_check(&report, "configuration", "ok", "valid");
    assert_check(&report, "database", "ok", "read_only");
    assert_check(&report, "credential_expiry", "ok", "valid");
    assert_check(&report, "local_token", "warning", "token_file_missing");
    assert_check(&report, "listener", "skipped", "network_disabled");
}

#[test]
fn doctor_invalid_configuration_skips_only_the_dependent_listener_check() {
    let dir = tempfile::tempdir().unwrap();
    let output = command_for(&fixture_db(), &dir.path().join("token"), "0.0.0.0:3456")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report = report(output);
    assert_check(&report, "configuration", "error", "invalid_configuration");
    assert_check(&report, "database", "ok", "read_only");
    assert_check(&report, "local_token", "warning", "token_file_missing");
    assert_check(&report, "listener", "skipped", "invalid_configuration");
}

#[test]
fn doctor_unavailable_database_skips_credential_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.sqlite3");
    let output = command_for(&missing, &dir.path().join("token"), "127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report = report(output);
    assert_check(&report, "database", "error", "database_unavailable");
    assert_check(
        &report,
        "credential_expiry",
        "skipped",
        "credential_unavailable",
    );
}

#[test]
fn doctor_invalid_credential_errors_without_refreshing() {
    let dir = tempfile::tempdir().unwrap();
    let db = copied_db(dir.path(), "2099-01-01T00:00:00Z");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE auth_kv SET value = '{}' WHERE key = 'kirocli:odic:token'",
        [],
    )
    .unwrap();
    let output = command_for(&db, &dir.path().join("token"), "127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report = report(output);
    assert_check(&report, "database", "error", "credential_invalid");
    assert_check(
        &report,
        "credential_expiry",
        "skipped",
        "credential_unavailable",
    );
}

#[test]
fn doctor_unreadable_metadata_errors() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    // Windows reserves `<` in a file name, producing a metadata error.
    let token = dir.path().join("token<");
    #[cfg(not(windows))]
    let token = {
        let ancestor = dir.path().join("not-a-directory");
        std::fs::write(&ancestor, b"x").unwrap();
        ancestor.join("token")
    };
    let error = std::fs::symlink_metadata(&token).expect_err("fixture metadata must fail");
    assert_ne!(
        error.kind(),
        std::io::ErrorKind::NotFound,
        "fixture metadata must fail for a reason other than a missing token file: {error}"
    );
    let output = command_for(&fixture_db(), &token, "127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = report(output);
    assert_check(&report, "local_token", "error", "token_metadata_unreadable");
}

#[cfg(unix)]
#[test]
fn doctor_symlink_errors() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    let token = dir.path().join("token");
    std::fs::write(&target, b"not read").unwrap();
    symlink(&target, &token).unwrap();
    let output = command(dir.path()).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report = report(output);
    assert_check(&report, "local_token", "error", "unsafe_token_file");
}

fn copied_db(dir: &Path, expiry: &str) -> PathBuf {
    let db = dir.join("idc.sqlite3");
    std::fs::copy(fixture_db(), &db).unwrap();
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE auth_kv SET value = json_set(value, '$.expires_at', ?1) WHERE key = 'kirocli:odic:token'",
        [expiry],
    )
    .unwrap();
    db
}

#[test]
fn doctor_expired_warns() {
    let dir = tempfile::tempdir().unwrap();
    let db = copied_db(dir.path(), "1970-01-01T00:00:00Z");
    let output = command_for(&db, &dir.path().join("token"), "127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report = report(output);
    assert_check(&report, "credential_expiry", "warning", "expired");
}

#[test]
fn doctor_near_expiry_warns() {
    let dir = tempfile::tempdir().unwrap();
    let expiry = time::OffsetDateTime::now_utc() + time::Duration::minutes(4);
    let db = copied_db(
        dir.path(),
        &expiry
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    );
    let output = command_for(&db, &dir.path().join("token"), "127.0.0.1:9")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report = report(output);
    assert_check(&report, "credential_expiry", "warning", "refresh_required");
}

#[cfg(unix)]
#[test]
fn doctor_unix_private_file() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, b"deliberately invalid token contents").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let private = command(dir.path()).output().unwrap();
    assert_eq!(private.status.code(), Some(0));
    let private_report = report(private);
    assert_check(&private_report, "local_token", "ok", "private_file");

    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    let public = command(dir.path()).output().unwrap();
    assert_eq!(public.status.code(), Some(1));
    let public_report = report(public);
    assert_check(&public_report, "local_token", "error", "unsafe_token_file");
}

#[cfg(windows)]
#[test]
fn doctor_windows_acl_warning() {
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, b"deliberately invalid token contents").unwrap();
    let output = command(dir.path()).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report = report(output);
    assert_check(&report, "local_token", "warning", "acl_not_verified");
}

#[test]
fn doctor_network_failure_errors() {
    let dir = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let output = command_for(
        &fixture_db(),
        &dir.path().join("token"),
        &format!("127.0.0.1:{port}"),
    )
    .arg("--network")
    .output()
    .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = report(output);
    assert_check(&report, "listener", "error", "health_probe_failed");
}

#[test]
fn doctor_explicit_token_is_presence_only() {
    let dir = tempfile::tempdir().unwrap();
    let output = command(dir.path())
        .env(
            "KIRO_TRUST_TOKEN",
            "invalid token content that must remain unread",
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report = report(output);
    assert_check(&report, "local_token", "ok", "explicit_token_configured");
}

#[test]
fn doctor_text_paths_escape_control_characters() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("safe");
    for control in ['\n', '\t', '\r', '\u{1b}'] {
        let unsafe_path = PathBuf::from(format!("{}{}path", base.display(), control));
        for position in ["database", "token_file", "extra_ca"] {
            let json = report(
                path_command(position, &unsafe_path, &base, true)
                    .output()
                    .unwrap(),
            );
            let semantic_path = match position {
                "database" => json["paths"]["database"].as_str().unwrap(),
                "token_file" => json["paths"]["token_file"].as_str().unwrap(),
                "extra_ca" => json["paths"]["extra_ca"].as_str().unwrap(),
                _ => unreachable!(),
            };
            assert!(semantic_path.contains(control), "{position} {control:?}");
            let escaped_control = match control {
                '\n' => "\\n",
                '\t' => "\\t",
                '\r' => "\\r",
                '\u{1b}' => "\\u{1b}",
                _ => unreachable!(),
            };
            let escaped = semantic_path.replace(control, escaped_control);
            let output = path_command(position, &unsafe_path, &base, false)
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            let label = match position {
                "database" => "DATABASE",
                "token_file" => "TOKEN FILE",
                "extra_ca" => "EXTRA CA",
                _ => unreachable!(),
            };
            assert!(
                stdout.contains(&format!("{label}\t{escaped}\n")),
                "{position} {control:?}: {stdout:?}"
            );
            assert!(
                !stdout.contains(semantic_path),
                "{position} {control:?} was emitted verbatim: {stdout:?}"
            );
        }
    }
}
