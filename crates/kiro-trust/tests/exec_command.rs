//! `kiro-trust exec -- <cmd> [args...]` (spec 4.4). Run as subprocesses, like
//! `env_token_output.rs`, so this proves what the shipped binary actually
//! does to argv, the child's environment, and each output stream, rather
//! than something observed in-process.
//!
//! The "child" most of these tests launch is this very test binary,
//! re-invoked through `std::env::current_exe()` and gated by
//! `KIRO_TRUST_EXEC_TEST_HELPER`. That keeps every test here free of any
//! platform-specific external command (no `/bin/echo`, no `cmd.exe`): the
//! helper is a `#[test]` in this file that, when the marker environment
//! variable is set, reads its own argv and selected environment variables,
//! prints what the test needs to see, and calls `std::process::exit`
//! immediately so it never falls through into being treated as a normal
//! test by the harness that ran it. Without the marker set, it is an
//! ordinary passing test, so a plain `cargo test` run of this file is
//! unaffected.

use kiro_trust::token;
use secrecy::ExposeSecret;
use std::process::Command;

const HELPER_MARKER: &str = "KIRO_TRUST_EXEC_TEST_HELPER";

/// The path to this test binary, suitable for use as `kiro-trust exec`'s
/// child command.
fn helper_exe() -> std::path::PathBuf {
    std::env::current_exe().expect("current test binary path")
}

/// Args that make `helper_exe()` run as the argv/env echo helper below
/// instead of as a normal test binary: `--exact <name> --nocapture` selects
/// only the helper test and disables libtest's output capture (needed
/// because the helper calls `process::exit` before the harness would ever
/// print anything itself), and `--` starts the payload the helper echoes.
fn helper_args() -> Vec<&'static str> {
    vec!["--exact", "helper_echoes_argv_and_env", "--nocapture", "--"]
}

/// The helper test itself. Prints one `ARG:<value>` line per argument after
/// `--`, then one `ENV:<name>=<value>` line for each of `ANTHROPIC_BASE_URL`,
/// `ANTHROPIC_AUTH_TOKEN`, and `KIRO_TRUST_EXEC_TEST_UNRELATED` that is set,
/// then exits with the code named by `KIRO_TRUST_EXEC_TEST_EXIT_CODE`
/// (default 0). Never runs this body when the marker is unset, so a normal
/// `cargo test` invocation of this file just sees it pass trivially.
#[test]
fn helper_echoes_argv_and_env() {
    if std::env::var(HELPER_MARKER).is_err() {
        return;
    }
    // Everything after the harness's own `--` separator.
    let mut saw_dashdash = false;
    for arg in std::env::args() {
        if saw_dashdash {
            println!("ARG:{arg}");
        } else if arg == "--" {
            saw_dashdash = true;
        }
    }
    for name in [
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
        "KIRO_TRUST_EXEC_TEST_UNRELATED",
    ] {
        if let Ok(v) = std::env::var(name) {
            println!("ENV:{name}={v}");
        }
    }
    println!("PID:{}", std::process::id());
    if let Ok(ms) = std::env::var("KIRO_TRUST_EXEC_TEST_SLEEP_MS")
        && let Ok(ms) = ms.parse::<u64>()
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    let code = std::env::var("KIRO_TRUST_EXEC_TEST_EXIT_CODE")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0);
    std::process::exit(code);
}

/// Writes a valid token file and returns its directory (kept alive by the
/// caller) and path.
fn write_valid_token(dir: &std::path::Path) -> (std::path::PathBuf, secrecy::SecretString) {
    let path = dir.join("token");
    let t = token::generate();
    token::write_token_file(&path, &t).unwrap();
    (path, t)
}

fn run_exec(token_file: &std::path::Path, exec_args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--token-file")
        .arg(token_file)
        .arg("--listen")
        .arg("127.0.0.1:3456")
        // The child in these tests is the helper below; it only acts as a
        // helper (rather than passing trivially) when it sees this set in
        // its environment, which `exec` must preserve from `kiro-trust`'s
        // own environment through to the child (spec 4.4).
        .env(HELPER_MARKER, "1")
        .arg("--")
        .args(exec_args)
        .output()
        .expect("spawn kiro-trust")
}

#[test]
fn preserves_spaces_and_shell_metacharacters_as_literal_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let (token_file, _token) = write_valid_token(dir.path());

    let helper = helper_exe();
    let helper = helper.to_str().unwrap();
    let mut args: Vec<&str> = vec![helper];
    args.extend(helper_args());
    // Arguments a shell would treat specially if `exec` ever ran one: a
    // space, a semicolon, a backtick, a `$(...)` substitution, and a
    // single-quoted-looking string. `exec` must hand each to the child as
    // one literal argv entry, unchanged, because it never invokes a shell.
    let literal_args = [
        "two words",
        "a;b",
        "a`b`c",
        "$(echo hi)",
        "'quoted'",
        "-x",
        "--looks-like-a-flag",
    ];
    args.extend(literal_args);

    let output = run_exec(&token_file, &args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let seen: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("ARG:"))
        .collect();
    assert_eq!(
        seen, literal_args,
        "argument boundaries must be preserved exactly, got:\n{stdout}"
    );
}

#[test]
fn sets_the_two_child_env_vars_and_preserves_unrelated_env() {
    let dir = tempfile::tempdir().unwrap();
    let (token_file, local_token) = write_valid_token(dir.path());

    let helper = helper_exe();
    let helper = helper.to_str().unwrap();
    let mut args: Vec<&str> = vec![helper];
    args.extend(helper_args());
    args.push("noop");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--token-file")
        .arg(&token_file)
        .arg("--listen")
        .arg("127.0.0.1:3456")
        // An unrelated variable that must reach the child unchanged,
        // proving "nothing else changed" (spec 4.4).
        .env("KIRO_TRUST_EXEC_TEST_UNRELATED", "still-here")
        .env(HELPER_MARKER, "1")
        .arg("--")
        .args(&args)
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
    assert!(
        stdout.contains("ENV:ANTHROPIC_BASE_URL=http://127.0.0.1:3456"),
        "expected ANTHROPIC_BASE_URL in the child, got:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "ENV:ANTHROPIC_AUTH_TOKEN={}",
            local_token.expose_secret()
        )),
        "expected ANTHROPIC_AUTH_TOKEN in the child"
    );
    assert!(
        stdout.contains("ENV:KIRO_TRUST_EXEC_TEST_UNRELATED=still-here"),
        "an unrelated environment variable must be preserved, got:\n{stdout}"
    );
}

#[test]
fn no_command_is_a_usage_error_exit_2() {
    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .output()
        .expect("spawn kiro-trust");
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Also with a bare `--` and nothing after it.
    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--")
        .output()
        .expect("spawn kiro-trust");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn forwards_the_childs_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let (token_file, _token) = write_valid_token(dir.path());

    let helper = helper_exe();
    let helper = helper.to_str().unwrap();
    let mut args: Vec<&str> = vec![helper];
    args.extend(helper_args());
    args.push("noop");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--token-file")
        .arg(&token_file)
        .arg("--listen")
        .arg("127.0.0.1:3456")
        .env("KIRO_TRUST_EXEC_TEST_EXIT_CODE", "17")
        .env(HELPER_MARKER, "1")
        .arg("--")
        .args(&args)
        .output()
        .expect("spawn kiro-trust");

    assert_eq!(
        output.status.code(),
        Some(17),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn launch_failure_is_exit_1_without_leaking_command_env_or_token() {
    let dir = tempfile::tempdir().unwrap();
    let (token_file, local_token) = write_valid_token(dir.path());

    // Not a real executable on any platform.
    let nonexistent = dir.path().join("does-not-exist-kiro-trust-exec-test");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--token-file")
        .arg(&token_file)
        .arg("--listen")
        .arg("127.0.0.1:3456")
        .arg("--")
        .arg(&nonexistent)
        .arg("--secret-looking-arg")
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
        "a launch failure must print nothing to stdout, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(local_token.expose_secret()),
        "the token must never reach stderr on a launch failure, got:\n{stderr}"
    );
}

#[test]
fn missing_token_file_prints_nothing_to_stdout_and_no_token_anywhere() {
    let dir = tempfile::tempdir().unwrap();
    // Never created: the failure path this test targets.
    let token_file = dir.path().join("token");

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--token-file")
        .arg(&token_file)
        .arg("--")
        .arg("true")
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
#[cfg(unix)]
fn unreadable_token_file_is_exit_1_without_leaking_content() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (token_file, _token) = write_valid_token(dir.path());
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o000)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--token-file")
        .arg(&token_file)
        .arg("--")
        .arg("true")
        .output()
        .expect("spawn kiro-trust");

    // Restore permissions so `tempdir`'s own cleanup can remove the file.
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_token_is_rejected_without_being_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    // A token file containing a newline and something that looks like a
    // shell command substitution: this must never reach stdout, stderr, or
    // the child, because `exec`'s only path for the token is the shape
    // check followed by the child's environment.
    std::fs::write(&token_file, "abc\nID=$(id -u)\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--token-file")
        .arg(&token_file)
        .arg("--")
        .arg("true")
        .output()
        .expect("spawn kiro-trust");

    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("id -u") && !stderr.contains("abc"),
        "the malformed token file's content must never appear in the error, got:\n{stderr}"
    );
}

#[test]
fn tokens_shaped_with_shell_metacharacters_are_rejected() {
    for bad in [";", "`", "$(", "'"] {
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        let mut content = "A".repeat(43);
        content.replace_range(20..20 + bad.len(), bad);
        std::fs::write(&token_file, &content).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
            .arg("exec")
            .arg("--token-file")
            .arg(&token_file)
            .arg("--")
            .arg("true")
            .output()
            .expect("spawn kiro-trust");

        assert_eq!(
            output.status.code(),
            Some(1),
            "{bad:?}: stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains(&content),
            "{bad:?}: the malformed token must never appear in the error, got:\n{stderr}"
        );
    }
}

// spec 4.4: on Unix, `exec` replaces this process's image rather than
// spawning a wrapper that waits around holding the token. `execvp(2)` never
// changes the pid, only what runs inside it, so the pid `Command::spawn`
// reports for `kiro-trust exec` must be running the helper's own executable
// image while the child is alive, which a `fork`+`exec` wrapper (a distinct
// parent pid staying alive, with a different pid for the child) would not
// produce. `/proc/<pid>/exe` gives that identity directly on Linux, the
// platform this repo's CI runs the Unix `exec` path on.
#[test]
#[cfg(unix)]
fn on_unix_exec_replaces_the_process_rather_than_spawning_a_wrapper() {
    let dir = tempfile::tempdir().unwrap();
    let (token_file, _token) = write_valid_token(dir.path());

    let helper = helper_exe();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kiro-trust"))
        .arg("exec")
        .arg("--token-file")
        .arg(&token_file)
        .arg("--listen")
        .arg("127.0.0.1:3456")
        .arg("--")
        .arg(&helper)
        .args(["--exact", "helper_echoes_argv_and_env", "--nocapture"])
        .env(HELPER_MARKER, "1")
        .env("KIRO_TRUST_EXEC_TEST_SLEEP_MS", "500")
        .spawn()
        .expect("spawn kiro-trust");
    let pid = child.id();

    // Give the child time to start and reach its sleep before inspecting it.
    std::thread::sleep(std::time::Duration::from_millis(150));
    let exe_link = std::fs::read_link(format!("/proc/{pid}/exe"));

    let status = child.wait().expect("wait for kiro-trust");
    assert!(
        status.success(),
        "helper exited with {:?}; the pid-identity check needs it to still be \
         running when read, so an early exit invalidates this test's timing",
        status.code()
    );

    let exe = exe_link.expect(
        "/proc/<pid>/exe must resolve while the child is running; if it does \
         not, `exec` may not have replaced the process image in time",
    );
    assert_eq!(
        exe.file_name(),
        helper.file_name(),
        "the pid `kiro-trust exec` was launched under must be running the \
         child's own executable image (exec replaces in place, spawning no \
         wrapper), got /proc/{pid}/exe -> {exe:?}"
    );
}
