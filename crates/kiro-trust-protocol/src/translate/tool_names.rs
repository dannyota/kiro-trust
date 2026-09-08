//! Tool names longer than 64 bytes are shortened for Kiro and restored on
//! the way back. Transcribed from kirocc internal/reqconv/tool_name_map.go.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const MAX_TOOL_NAME_LEN: usize = 64;

#[derive(Debug, Default, Clone)]
pub struct ToolNameMap {
    to_short: HashMap<String, String>,
    to_original: HashMap<String, String>,
}

impl ToolNameMap {
    pub fn shorten(&mut self, name: &str) -> String {
        if name.len() <= MAX_TOOL_NAME_LEN {
            return name.to_string();
        }
        if let Some(s) = self.to_short.get(name) {
            return s.clone();
        }
        let digest = Sha256::digest(name.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let mut end = 50;
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        let short = format!("{}_{}", &name[..end], &hex[..13]);
        self.to_short.insert(name.to_string(), short.clone());
        self.to_original.insert(short.clone(), name.to_string());
        short
    }

    pub fn restore(&self, name: &str) -> String {
        self.to_original
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    pub fn reverse_map(&self) -> HashMap<String, String> {
        self.to_original.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // kirocc TestToolNameMap_Shorten_Short, _Exact64, _Long, _Deterministic, _Restore, _ReverseMap
    #[test]
    fn shortens_only_over_64_bytes_and_restores() {
        let mut m = ToolNameMap::default();
        assert_eq!(m.shorten("Read"), "Read");
        let exact = "a".repeat(64);
        assert_eq!(m.shorten(&exact), exact);
        let long = format!("mcp__server__{}", "x".repeat(80));
        let short = m.shorten(&long);
        assert_eq!(short.len(), 64);
        assert!(short.starts_with(&long[..50]));
        assert_eq!(short.as_bytes()[50], b'_');
        assert_eq!(m.shorten(&long), short, "deterministic");
        assert_eq!(m.restore(&short), long);
        assert_eq!(m.restore("unknown"), "unknown");
        let rev = m.reverse_map();
        assert_eq!(rev.get(&short).unwrap(), &long);
        assert_eq!(rev.len(), 1);
    }
}
