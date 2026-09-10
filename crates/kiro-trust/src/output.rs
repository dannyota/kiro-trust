//! Sanitized output helpers shared by offline diagnostics.

pub(crate) fn real_home() -> String {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub(crate) fn is_usable_home(home: &str) -> bool {
    !home.is_empty() && home != "/"
}

/// Abbreviates a whole path by stripping the home directory as a path prefix.
pub fn abbreviate_home_path(s: &str) -> String {
    abbreviate_home_path_with(s, &real_home())
}

pub(crate) fn abbreviate_home_path_with(s: &str, home: &str) -> String {
    if !is_usable_home(home) {
        return s.to_string();
    }
    match std::path::Path::new(s).strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => s.to_string(),
    }
}

/// Abbreviates a home path embedded inside an error message.
pub fn abbreviate_home_in_message(s: &str) -> String {
    abbreviate_home_in_message_with(s, &real_home())
}

pub(crate) fn abbreviate_home_in_message_with(s: &str, home: &str) -> String {
    if !is_usable_home(home) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut remaining = s;
    while let Some(idx) = remaining.find(home) {
        let (before, at_match) = remaining.split_at(idx);
        out.push_str(before);
        let after = &at_match[home.len()..];
        let boundary_ok = match after.chars().next() {
            None | Some('/') | Some('\\') => true,
            Some(c) => !(c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~'),
        };
        out.push_str(if boundary_ok { "~" } else { home });
        remaining = after;
    }
    out.push_str(remaining);
    out
}

/// Escapes control characters at a text-output boundary without changing the
/// semantic value retained by structured output.
pub fn escape_text_controls(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}
