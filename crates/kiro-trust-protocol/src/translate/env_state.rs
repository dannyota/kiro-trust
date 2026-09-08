//! Claude Code embeds `<env>` in the system prompt; Kiro wants envState on the
//! current message. Transcribed from kirocc internal/reqconv/env_state.go.

use crate::kiro::EnvState;

pub fn parse_env_state(system: &str) -> Option<EnvState> {
    let start = system.find("<env>")? + "<env>".len();
    let end = system[start..].find("</env>")? + start;
    let block = &system[start..end];
    let mut env = EnvState::default();
    for line in block.lines() {
        if let Some(v) = line.strip_prefix("Working directory:") {
            let v = v.trim();
            if !v.is_empty() {
                env.current_working_directory = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("Platform:") {
            let v = v.trim();
            if !v.is_empty() {
                env.operating_system = Some(normalize_platform(v).to_string());
            }
        }
    }
    if env.operating_system.is_none() && env.current_working_directory.is_none() {
        return None;
    }
    Some(env)
}

fn normalize_platform(p: &str) -> &str {
    match p {
        "darwin" => "macos",
        "win32" | "windows" => "windows",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // kirocc TestParseEnvState
    #[test]
    fn parses_env_block() {
        let s = "x\n<env>\nWorking directory: /w \nPlatform: win32\n</env>\nPlatform: ignored";
        assert_eq!(
            parse_env_state(s),
            Some(EnvState {
                operating_system: Some("windows".into()),
                current_working_directory: Some("/w".into())
            })
        );
        assert_eq!(
            parse_env_state("<env>\nPlatform: linux\n</env>"),
            Some(EnvState {
                operating_system: Some("linux".into()),
                current_working_directory: None
            })
        );
        assert_eq!(
            parse_env_state("Platform: darwin"),
            None,
            "outside an env block"
        );
        assert_eq!(parse_env_state("<env></env>"), None);
        assert_eq!(parse_env_state(""), None);
    }
}
