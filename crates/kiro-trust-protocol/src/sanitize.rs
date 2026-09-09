//! Scrubbing and capping for any message that may reach a client or a log
//! (spec 5.6). Pure string transforms, shared by `kiro-trust-kiro` (upstream
//! exception messages) and `kiro-trust`'s `ApiError` (every error
//! constructor, including the SSE `error` event).

/// The spec 5.6 cap: every error message a client or a log sees is at most
/// this many bytes.
pub const MAX_MESSAGE_BYTES: usize = 1024;

/// Removes AWS identifiers that must never reach a client or a log
/// (`CLAUDE.md`): an ARN becomes `arn:***`, and a bare 12-digit account id
/// becomes `***`.
pub fn scrub_identifiers(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if s[i..].starts_with("arn:") {
            let mut j = i + "arn:".len();
            while j < bytes.len() {
                let b = bytes[j];
                if b.is_ascii_whitespace() || b == b'"' || b == b'\'' {
                    break;
                }
                j += 1;
            }
            out.push_str("arn:***");
            i = j;
            continue;
        }
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j - start == 12 {
                out.push_str("***");
            } else {
                out.push_str(&s[start..j]);
            }
            i = j;
            continue;
        }
        let ch = s[i..]
            .chars()
            .next()
            .expect("i < bytes.len() is a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Truncates `s` to at most `limit` bytes, never splitting a multi-byte
/// character. Appends no ellipsis or marker.
pub fn cap(s: &str, limit: usize) -> String {
    if s.len() <= limit {
        return s.to_string();
    }
    let mut end = limit;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_identifiers_masks_arns_with_no_surviving_digits() {
        assert_eq!(
            scrub_identifiers(
                "denied for arn:aws:codewhisperer:us-east-1:123456789012:profile/AAA"
            ),
            "denied for arn:***"
        );
    }

    #[test]
    fn scrub_identifiers_masks_a_bare_twelve_digit_account_id() {
        assert_eq!(
            scrub_identifiers("account 123456789012 rejected"),
            "account *** rejected"
        );
    }

    #[test]
    fn scrub_identifiers_leaves_a_thirteen_digit_run_untouched() {
        assert_eq!(
            scrub_identifiers("stamp 1234567890123"),
            "stamp 1234567890123"
        );
    }

    #[test]
    fn scrub_identifiers_leaves_an_eleven_digit_run_untouched() {
        assert_eq!(scrub_identifiers("short 12345678901"), "short 12345678901");
    }

    #[test]
    fn cap_truncates_on_a_char_boundary_without_a_marker() {
        let s = "a".repeat(2000);
        let capped = cap(&s, MAX_MESSAGE_BYTES);
        assert_eq!(capped.len(), MAX_MESSAGE_BYTES);
        assert!(!capped.contains('\u{2026}'), "no ellipsis appended");
    }

    #[test]
    fn cap_backs_off_from_a_multi_byte_character_at_the_boundary() {
        // Each 'é' is 2 bytes; put one straddling byte offset 10.
        let s = format!("{}{}", "a".repeat(9), "é".repeat(10));
        let capped = cap(&s, 10);
        assert!(capped.is_char_boundary(capped.len()));
        assert!(std::str::from_utf8(capped.as_bytes()).is_ok());
        assert_eq!(capped, "a".repeat(9));
    }

    #[test]
    fn cap_leaves_a_short_string_untouched() {
        assert_eq!(cap("short", MAX_MESSAGE_BYTES), "short");
    }
}
