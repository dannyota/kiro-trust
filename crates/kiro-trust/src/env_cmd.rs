//! `kiro-trust env` (spec 4.3): prints the exports Claude Code needs.
//!
//! `expose_secret()` below is the fifth site CLAUDE.md's Security contracts
//! permit (task-20-rulings.md ruling 3): this command's entire purpose is
//! printing the token, so there is no way to implement spec 4.3 without it.
//! Two rules bind every path through `run`: the token goes to stdout only,
//! never to `tracing` and never to stderr, and no error path prints it. The
//! `--shell` value itself can never be a source of such an error path: clap's
//! `value_parser` on `EnvArgs::shell` (spec 4.3: `sh|fish`) rejects anything
//! else as a usage error (exit 2, naming the accepted shells) while parsing
//! arguments, before `run` is ever called, so the `match` below only ever
//! chooses between the two accepted shells.
//!
//! Two further defenses guard the printed value itself
//! (task-20-fix-1.md Critical 1: this command otherwise prints a token
//! file's contents unquoted into a stream the documentation tells users to
//! `eval`, so a token file containing a newline is arbitrary command
//! execution in the caller's shell, and the file path is
//! attacker-influenceable through `--token-file`/`KIRO_TRUST_TOKEN_FILE`):
//!
//! 1. `token::token_shape_is_valid` rejects anything that is not exactly the
//!    shape `token::generate` produces before it is ever printed. Checked
//!    here, not in `read_token_file`: the server reads the same file at
//!    startup and a shape change there is a separate decision. `exec_cmd`
//!    shares this same function rather than a copy (spec 4.4).
//! 2. `quote_posix`/`quote_fish` single-quote both exports anyway. With (1)
//!    in place neither escape can trigger; they are the safety net, not the
//!    mechanism, kept in case the token shape ever changes.

use crate::config::{EnvArgs, resolve_token_file};
use crate::token::{read_token_file, token_shape_is_valid};
use secrecy::ExposeSecret;

/// Quotes `s` for POSIX `sh`. Inside single quotes, `sh` treats every
/// character as completely literal, with no escape sequence at all, so an
/// embedded single quote cannot be escaped in place: the quoted string must
/// be closed, the quote emitted as an escaped literal, and the string
/// reopened: `'\''`. A backslash or a backtick needs no such treatment;
/// both are already literal between single quotes.
fn quote_posix(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Quotes `s` for fish. fish single-quoted strings support exactly two
/// escapes, `\'` and `\\`, and treat every other character, backtick
/// included, as literal, so only a single quote or a backslash needs a
/// backslash in front of it here.
fn quote_fish(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

pub fn run(args: EnvArgs) -> i32 {
    let path = match resolve_token_file(args.token_file) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("kiro-trust env: {e}");
            return 2;
        }
    };
    let token = match read_token_file(&path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "kiro-trust env: cannot read token file {} ({e}); is `kiro-trust serve` running?",
                path.display()
            );
            return 1;
        }
    };
    if !token_shape_is_valid(token.expose_secret()) {
        eprintln!(
            "kiro-trust env: token file {} does not contain a well-formed token",
            path.display()
        );
        return 1;
    }
    let base = format!("http://{}", args.listen);
    match args.shell.as_str() {
        "fish" => {
            println!("set -gx ANTHROPIC_BASE_URL {}", quote_fish(&base));
            println!(
                "set -gx ANTHROPIC_AUTH_TOKEN {}",
                quote_fish(token.expose_secret())
            );
        }
        _ => {
            println!("export ANTHROPIC_BASE_URL={}", quote_posix(&base));
            println!(
                "export ANTHROPIC_AUTH_TOKEN={}",
                quote_posix(token.expose_secret())
            );
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    // `tests/env_token_output.rs` runs the real binary as a subprocess to
    // assert that this failure path's stdout is empty and its stderr never
    // contains the token, and that the success path prints the token to
    // stdout only. This unit test pins the exit code these process-level
    // checks build on.
    #[test]
    fn missing_token_file_is_a_runtime_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("token");
        let args = EnvArgs {
            listen: "127.0.0.1:3456".into(),
            token_file: Some(missing),
            shell: "sh".into(),
        };
        assert_eq!(run(args), 1);
    }

    // `token_shape_is_valid`'s own tests moved to `token.rs`, where the
    // function now lives (shared with `exec_cmd`, spec 4.4).

    // Verified independently of the shape check (task-20-fix-1.md, "On the
    // shell-quoting fix"): the shape check means none of these characters
    // can reach a real token in practice, but the escaper is implemented
    // and tested on its own regardless.
    #[test]
    fn posix_quoting_escapes_single_quotes_and_leaves_backslash_and_backtick_literal() {
        assert_eq!(quote_posix("plain"), "'plain'");
        assert_eq!(quote_posix("a'b"), "'a'\\''b'");
        assert_eq!(quote_posix("a\\b"), "'a\\b'");
        assert_eq!(quote_posix("a`b"), "'a`b'");
        assert_eq!(quote_posix("a'b\\c`d"), "'a'\\''b\\c`d'");
    }

    #[test]
    fn fish_quoting_escapes_backslash_and_single_quote_and_leaves_backtick_literal() {
        assert_eq!(quote_fish("plain"), "'plain'");
        assert_eq!(quote_fish("a'b"), "'a\\'b'");
        assert_eq!(quote_fish("a\\b"), "'a\\\\b'");
        assert_eq!(quote_fish("a`b"), "'a`b'");
        assert_eq!(quote_fish("a'b\\c`d"), "'a\\'b\\\\c`d'");
    }
}
