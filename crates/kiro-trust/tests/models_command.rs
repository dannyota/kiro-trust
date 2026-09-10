//! The commands run against absent credential paths to prove they use only
//! compiled metadata.

use std::process::Command;

fn command(directory: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kiro-trust"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("KIRO_TRUST_") {
            command.env_remove(name);
        }
    }
    command.env("KIRO_TRUST_DB", directory.join("missing.sqlite3"));
    command.env("KIRO_TRUST_TOKEN_FILE", directory.join("missing-token"));
    command
}

#[test]
fn model_commands_are_offline_and_reject_unknown_ids() {
    let directory = tempfile::tempdir().unwrap();
    let list = command(directory.path())
        .args(["models", "list", "--json"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let value: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(value["object"], "model_catalog");
    assert_eq!(value["models"][0]["id"], "claude-opus-5[1m]");
    assert_eq!(value["models"][5]["id"], "claude-sonnet-4-6");
    assert_eq!(value["models"][6]["id"], "claude-sonnet-4-6[1m]");
    assert!(value["models"][0].get("key").is_none());

    let show = command(directory.path())
        .args(["models", "show", "claude-sonnet-4-6"])
        .output()
        .unwrap();
    assert!(show.status.success());
    assert_eq!(
        String::from_utf8(show.stdout).unwrap(),
        concat!(
            "ID\tclaude-sonnet-4-6\n",
            "DISPLAY NAME\tSonnet 4.6\n",
            "KIRO MODEL\tclaude-sonnet-4.6\n",
            "ALIASES\tclaude-sonnet-4-6,claude-sonnet-4.6\n",
            "ACCEPTS DATE SUFFIX\ttrue\n",
            "CONTEXT\t200K\n",
            "EFFORT\tlow,medium,high,max\n",
            "INPUTS\ttext,image\n",
            "HISTORY IMAGES FORWARDED\tfalse\n",
        )
    );

    let bad = command(directory.path())
        .args(["models", "show", "not-a-model"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    assert!(bad.stdout.is_empty());
}

#[test]
fn unknown_model_errors_never_echo_control_characters_or_long_input() {
    let directory = tempfile::tempdir().unwrap();
    let inputs = ["not-a-model\n\x1b[2J".to_string(), "x".repeat(16_384)];

    for json in [false, true] {
        for input in &inputs {
            let mut child = command(directory.path());
            child.args(["models", "show", input]);
            if json {
                child.arg("--json");
            }
            let output = child.output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stdout.is_empty());
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "kiro-trust: unknown model; run 'kiro-trust models list' for supported models\n"
            );
        }
    }
}
