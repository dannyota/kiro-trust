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

use crate::config::{EnvArgs, resolve_token_file};
use crate::token::read_token_file;
use secrecy::ExposeSecret;

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
                "kiro-trust env: no token file at {} ({e}); is `kiro-trust serve` running?",
                path.display()
            );
            return 1;
        }
    };
    let base = format!("http://{}", args.listen);
    match args.shell.as_str() {
        "fish" => {
            println!("set -gx ANTHROPIC_BASE_URL {base}");
            println!("set -gx ANTHROPIC_AUTH_TOKEN {}", token.expose_secret());
        }
        _ => {
            println!("export ANTHROPIC_BASE_URL={base}");
            println!("export ANTHROPIC_AUTH_TOKEN={}", token.expose_secret());
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
}
