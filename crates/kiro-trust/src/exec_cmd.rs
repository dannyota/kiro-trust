//! `kiro-trust exec -- <cmd> [args...]` (spec 4.4): runs a command with
//! `ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` set in its environment and
//! nothing else changed. It reads and validates the token file exactly as
//! `env` does (spec 4.3, `token::token_shape_is_valid`), then hands the
//! token to the child. Compared with `eval "$(kiro-trust env)"`, the token
//! never enters a shell, a shell history, or the environment of any process
//! but the child.
//!
//! `expose_secret()` below is the sixth and last site AGENTS.md's Security
//! contracts and spec 6.1 permit: this command's entire purpose is handing
//! the token to the child process, so there is no way to implement spec 4.4
//! without it. The token reaches only the child's environment, never a log,
//! stderr, or an error path; nothing in this file calls `tracing` or prints
//! the token itself (only `path.display()` and the child's own name ever
//! appear in an error).
//!
//! On Unix, `run` replaces this process with the child through
//! `std::os::unix::process::CommandExt::exec`, so no wrapper process
//! survives and the child inherits this process's pid, stdio, and signal
//! disposition directly. `exec` only returns on failure (it never returns on
//! success), so the fallback branch below is the failure path, not a
//! secondary implementation. Elsewhere, `run` spawns the child and waits,
//! forwarding its exit code.
//!
//! One precise limit on "no shell": this command never *constructs* a shell
//! invocation, never passes a command string to be word-split, and never
//! lets an argument be reinterpreted, so nothing the caller writes can be
//! expanded or injected. It does not, and cannot, prevent `execvp(3)` from
//! doing what POSIX specifies when the named program is an executable file
//! with no shebang: run it with `/bin/sh` (v020-exec-review.md, Medium 2).
//! That child then has the token in its environment, which is the intended
//! outcome, since the caller named that program and a shell script is a
//! legitimate thing to hand it. What matters for the token is that argv
//! boundaries survive intact and no shell metacharacter is ever interpreted
//! on kiro-trust's behalf.

use crate::config::{ExecArgs, parse_listen, resolve_token_file};
use crate::token::{read_token_file, token_shape_is_valid};
use secrecy::ExposeSecret;
use std::process::Command;

pub fn run(args: ExecArgs) -> i32 {
    // Validated, not merely interpolated: this address is where the child
    // will send the local token and every prompt, so a non-loopback value
    // would hand both to a remote host. `env` only prints a string for a
    // human to read, but `exec` acts on it, so it gets the same loopback
    // check `serve` applies to its bind address (spec 6.3), as a usage
    // error (exit 2) before the token file is ever read.
    let listen = match parse_listen(&args.listen) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("kiro-trust exec: {e}");
            return 2;
        }
    };
    let path = match resolve_token_file(args.token_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kiro-trust exec: {e}");
            return 2;
        }
    };
    let token = match read_token_file(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "kiro-trust exec: cannot read token file {} ({e}); is `kiro-trust serve` running?",
                path.display()
            );
            return 1;
        }
    };
    if !token_shape_is_valid(token.expose_secret()) {
        eprintln!(
            "kiro-trust exec: token file {} does not contain a well-formed token",
            path.display()
        );
        return 1;
    }

    // clap's `required = true` on `ExecArgs::cmd` (spec 4.4) already makes
    // zero arguments a usage error (exit 2) before `run` is ever called, so
    // `cmd` always has a first element here.
    let (program, rest) = args
        .cmd
        .split_first()
        .expect("clap requires at least one value for ExecArgs::cmd");

    let base = format!("http://{listen}");
    let mut command = Command::new(program);
    command
        .args(rest)
        .env("ANTHROPIC_BASE_URL", base)
        .env("ANTHROPIC_AUTH_TOKEN", token.expose_secret());
    // Standard input, output, and error are inherited by default: `Command`
    // does not touch a stdio stream unless `.stdin`/`.stdout`/`.stderr` is
    // called on it, and this file never calls any of the three.

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Never returns on success: the child's image replaces this
        // process's, in place, so no wrapper lingers to hold the token or
        // relay signals. It returns only the `io::Error` from the failed
        // `execvp(2)` call itself (e.g. the program does not exist or is not
        // executable), which is why everything after this call is the
        // failure path.
        let err = command.exec();
        // `CommandExt::exec` resets SIGPIPE to SIG_DFL before calling
        // execvp, for the child's benefit, and does not restore Rust's
        // SIG_IGN when execvp fails, so this process is left with the
        // default disposition. Writing the message below to a stderr with no
        // reader would then kill this process with SIGPIPE, exiting 141:
        // outside the 0/1/2 spec 4.5 allows, and inconsistent with every
        // other failure path in this command (v020-exec-review.md, Medium 1).
        // Catching the write error is not enough, because the signal arrives
        // at the write syscall itself, so the disposition has to be put back.
        //
        // SAFETY: reinstating SIG_IGN on SIGPIPE, which is what the Rust
        // runtime itself installs at startup. Sound precisely because execvp
        // failed: no child exists to inherit this disposition, and this is
        // the same process that had it a moment ago.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
        eprintln!("kiro-trust exec: cannot run {}: {err}", program.display());
        1
    }

    #[cfg(not(unix))]
    {
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("kiro-trust exec: cannot run {}: {e}", program.display());
                return 1;
            }
        };
        match child.wait() {
            Ok(status) => status.code().unwrap_or(1),
            Err(e) => {
                eprintln!(
                    "kiro-trust exec: failed waiting for {}: {e}",
                    program.display()
                );
                1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    // `tests/exec_command.rs` runs the real binary as a subprocess to
    // assert on argument boundaries, child environment, exit code
    // forwarding, and that the token never reaches stdout or stderr on any
    // failure path. This unit test pins the exit codes those process-level
    // checks build on.
    #[test]
    fn missing_token_file_is_a_runtime_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("token");
        let args = ExecArgs {
            listen: "127.0.0.1:3456".into(),
            token_file: Some(missing),
            cmd: vec![OsString::from("true")],
        };
        assert_eq!(run(args), 1);
    }

    // spec 6.3: the address the child is told to use must be loopback, and
    // it is rejected before the token file is read at all, so a non-loopback
    // `--listen` can never reach a child's environment.
    #[test]
    fn non_loopback_listen_is_a_usage_error_before_the_token_is_read() {
        let dir = tempfile::tempdir().unwrap();
        // Deliberately absent, not merely invalid: a token file that does not
        // exist makes the token path return 1, so exit 2 here can only come
        // from the listen check running first. With a valid token file this
        // test would still pass even if the ordering were reversed, which is
        // what made the original version no evidence at all
        // (v020-exec-review.md, Low finding on ordering).
        let missing = dir.path().join("no-such-token");
        let args = ExecArgs {
            listen: "10.0.0.1:3456".into(),
            token_file: Some(missing),
            cmd: vec![OsString::from("true")],
        };
        assert_eq!(
            run(args),
            2,
            "the loopback check must run before the token file is read"
        );
    }

    // The other half of that ordering claim: with a loopback address, the
    // same missing token file reaches the token path and returns 1.
    #[test]
    fn a_loopback_listen_lets_the_token_path_report_its_own_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no-such-token");
        let args = ExecArgs {
            listen: "127.0.0.1:3456".into(),
            token_file: Some(missing),
            cmd: vec![OsString::from("true")],
        };
        assert_eq!(run(args), 1);
    }

    #[test]
    fn unparseable_listen_is_a_usage_error() {
        let args = ExecArgs {
            listen: "not-an-address".into(),
            token_file: None,
            cmd: vec![OsString::from("true")],
        };
        assert_eq!(run(args), 2);
    }

    #[test]
    fn malformed_token_is_a_runtime_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "too-short").unwrap();
        let args = ExecArgs {
            listen: "127.0.0.1:3456".into(),
            token_file: Some(path),
            cmd: vec![OsString::from("true")],
        };
        assert_eq!(run(args), 1);
    }
}
