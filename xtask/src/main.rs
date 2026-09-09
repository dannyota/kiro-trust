//! Developer tasks: fixture scrubbing, version checks, synthetic databases.

use kiro_trust_protocol::eventstream::{FrameDecoder, encode_frame, push_header};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The synthetic Kiro CLI database rows for the audit gate (spec 8.7),
/// shared by `include_str!` with the `#[cfg(test)] mod tests` block of
/// `crates/kiro-trust/src/audit.rs` so the two can never drift out of
/// byte-identical sync (task-20-fix-1.md Important 4). A relative-path
/// `include_str!`, not a crate dependency: `xtask` must not depend on the
/// binary crate (task-20-rulings.md ruling 2). The file lives in
/// `crates/kiro-trust/`, the same package that `audit.rs` includes it
/// from, so `cargo package --package kiro-trust` ships it
/// (task-20-fix-2.md Minor 3); `xtask` is never published
/// (`publish = false` in `xtask/Cargo.toml`), so this relative include
/// stays fine either way. See the SQL file's own header for what it
/// contains and why.
const SYNTHETIC_IDC_SQL: &str = include_str!("../../crates/kiro-trust/synthetic-idc.sql");

fn make_synthetic_db(path: &str) {
    let conn = rusqlite::Connection::open(path).expect("open");
    conn.execute_batch(SYNTHETIC_IDC_SQL).expect("populate");
}

// ---- Fixture scrubbing (spec 8.3) -----------------------------------------
//
// `cargo xtask scrub <capture-dir> <fixture-dir> --source "<text>"` turns a
// real `--capture-dir` recording into a public fixture case by removing the
// owner's identity: the profile ARN and its account id, the home directory,
// the hostname, and conversation/utterance ids. This is a security tool, not
// a formatting convenience (task-21-rulings ruling 5): every rule below is
// deliberately permissive about *matching* (so it never misses an
// occurrence) and precise about *scope* (so it never mangles unrelated
// content), because a missed match is a real identity leak and this output
// is committed to a public repository.

const FIXTURE_ARN: &str = "arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE";
const FIXTURE_CONVERSATION_ID: &str = "00000000-0000-4000-8000-00000000c0ff";

pub struct ScrubRules {
    pub home: String,
    pub hostname: String,
    pub conversation_ids: Vec<String>,
}

/// Replace every `arn:aws:codewhisperer:...` token with the fixture ARN.
///
/// Matches on the fixed prefix alone, not the full ARN shape, so an account
/// id of any digit count is still caught (ruling 5): validating the shape
/// before rewriting would let a malformed-but-real ARN through unscrubbed,
/// which is the failure mode this tool exists to prevent. A single forward
/// scan (rather than repeated `find`-from-start) avoids re-matching the
/// fixture ARN's own `arn:aws:codewhisperer:` prefix once it has been
/// substituted in.
fn replace_arns(input: &str) -> String {
    const NEEDLE: &str = "arn:aws:codewhisperer:";
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(rel) = rest.find(NEEDLE) {
        out.push_str(&rest[..rel]);
        let candidate = &rest[rel..];
        let end = candidate
            .find(|c: char| c == '"' || c == '\'' || c.is_whitespace() || c == ',' || c == '}')
            .unwrap_or(candidate.len());
        out.push_str(FIXTURE_ARN);
        rest = &candidate[end..];
    }
    out.push_str(rest);
    out
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric()
}

/// Replace `hostname` with `host`, but only where it stands alone: a
/// hostname that is merely a substring of a longer word is left untouched
/// (ruling 5), because rewriting it would silently corrupt unrelated
/// content without removing any identity (the surrounding word is not the
/// owner's hostname).
fn replace_hostname_token(input: &str, hostname: &str) -> String {
    if hostname.is_empty() {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(rel) = rest.find(hostname) {
        let before_ok = !rest[..rel].chars().next_back().is_some_and(is_word_char);
        let after = &rest[rel + hostname.len()..];
        let after_ok = !after.chars().next().is_some_and(is_word_char);
        out.push_str(&rest[..rel]);
        if before_ok && after_ok {
            out.push_str("host");
        } else {
            out.push_str(hostname);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn scrub_string(s: &str, rules: &ScrubRules) -> String {
    let mut out = replace_arns(s);

    for id in &rules.conversation_ids {
        if !id.is_empty() {
            out = out.replace(id.as_str(), FIXTURE_CONVERSATION_ID);
        }
    }

    // Trim a trailing separator from the configured home directory first,
    // so a home with (or without) a trailing slash rewrites identically and
    // the slash in the surrounding text is never duplicated or swallowed
    // (ruling 5). Unlike the hostname, the home path is rewritten wherever
    // it occurs, including mid-string: it is a long, specific path that
    // does not occur by coincidence inside unrelated text, so bounding it
    // to whole tokens would only risk leaving a fragment of it behind.
    let home = rules.home.trim_end_matches(['/', '\\']);
    if !home.is_empty() {
        out = out.replace(home, "/home/user");
    }

    if !rules.hostname.is_empty() {
        out = replace_hostname_token(&out, &rules.hostname);
    }

    out
}

fn scrub_value(v: Value, rules: &ScrubRules) -> Value {
    match v {
        Value::String(s) => Value::String(scrub_string(&s, rules)),
        Value::Array(a) => Value::Array(a.into_iter().map(|x| scrub_value(x, rules)).collect()),
        Value::Object(m) => Value::Object(
            m.into_iter()
                .map(|(k, x)| (k, scrub_value(x, rules)))
                .collect(),
        ),
        other => other,
    }
}

/// Collect every string found under a `conversationId` key, anywhere in the
/// value: nested inside an array, inside a deeply nested object, not only
/// at the documented `conversationState.conversationId` location (ruling
/// 5). Missing one location because a later capture nests it differently is
/// exactly the kind of gap that leaves a real conversation id in a public
/// fixture, so this walks the whole structure rather than a fixed path.
fn collect_conversation_ids(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                if k == "conversationId"
                    && let Some(s) = val.as_str()
                    && !s.is_empty()
                {
                    out.push(s.to_string());
                }
                collect_conversation_ids(val, out);
            }
        }
        Value::Array(a) => {
            for item in a {
                collect_conversation_ids(item, out);
            }
        }
        _ => {}
    }
}

/// Replace `"msg_..."` ids with a fixed placeholder so a captured id never
/// has to match a freshly generated one byte for byte (spec 8.2: the
/// fixture harness masks its own generated output the same way before
/// comparing).
fn mask_msg_ids(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("\"msg_") {
        out.push_str(&rest[..i]);
        out.push_str("\"msg_MASKED\"");
        let after = &rest[i + 1..];
        let end = after.find('"').map(|e| e + 1).unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

/// Scrub one event-stream frame's JSON payload. `messageMetadataEvent`
/// carries `conversationId` and `utteranceId` directly (spec 7.5); those
/// two fields are rewritten unconditionally, in case the runtime assigned
/// an id that never appeared in the request payload `rules.conversation_ids`
/// was built from. Every frame's payload also goes through the general
/// string scrub, since Kiro's own response text can quote the operator's
/// environment back (a path in an error message, for example).
fn scrub_frame_payload(event_type: Option<&str>, payload: &[u8], rules: &ScrubRules) -> Vec<u8> {
    let Ok(mut v) = serde_json::from_slice::<Value>(payload) else {
        return payload.to_vec();
    };
    if event_type == Some("messageMetadataEvent")
        && let Value::Object(m) = &mut v
    {
        for key in ["conversationId", "utteranceId"] {
            if m.contains_key(key) {
                m.insert(
                    key.to_string(),
                    Value::String(FIXTURE_CONVERSATION_ID.to_string()),
                );
            }
        }
    }
    serde_json::to_vec(&scrub_value(v, rules)).unwrap_or_else(|_| payload.to_vec())
}

/// Decode `raw` frame by frame, scrub each payload, and re-encode. Headers
/// are copied through unchanged: `:message-type`, `:event-type`, and
/// `:content-type` carry no identity (spec 7.5), and spec 8.3 only asks
/// for the payload to be scrubbed.
fn scrub_eventstream(raw: &[u8], rules: &ScrubRules) -> Vec<u8> {
    let mut decoder = FrameDecoder::new();
    decoder.push(raw);
    let mut out = Vec::new();
    loop {
        match decoder.next_frame() {
            Ok(Some(frame)) => {
                let payload = scrub_frame_payload(frame.event_type(), &frame.payload, rules);
                let mut headers = Vec::new();
                for (name, value) in &frame.headers {
                    push_header(&mut headers, name, value);
                }
                out.extend(encode_frame(&headers, &payload));
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("warning: stopping eventstream scrub early: {e}");
                break;
            }
        }
    }
    if decoder.finish().is_err() {
        eprintln!(
            "warning: capture ended with a truncated frame; only complete frames were scrubbed"
        );
    }
    out
}

fn write_json(path: &Path, v: &Value) {
    let text = serde_json::to_string_pretty(v).unwrap() + "\n";
    std::fs::write(path, text).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

fn detect_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn scrub_capture_dir(capture_dir: &Path, fixture_dir: &Path, source: &str) {
    let mut requests: Vec<PathBuf> = std::fs::read_dir(capture_dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", capture_dir.display()))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with("-request.json"))
        })
        .collect();
    requests.sort();
    assert!(
        !requests.is_empty(),
        "no *-request.json files under {}",
        capture_dir.display()
    );

    let home = std::env::var("HOME").unwrap_or_default();
    let hostname = detect_hostname();

    for request_path in &requests {
        let file_name = request_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap()
            .to_string();
        let seq = file_name
            .strip_suffix("-request.json")
            .expect("filtered by suffix above");

        let payload_path = capture_dir.join(format!("{seq}-payload.json"));
        let upstream_path = capture_dir.join(format!("{seq}-upstream.eventstream"));
        let response_path = capture_dir.join(format!("{seq}-response.sse"));

        let payload_value: Value = serde_json::from_slice(
            &std::fs::read(&payload_path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", payload_path.display())),
        )
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", payload_path.display()));
        let mut conversation_ids = Vec::new();
        collect_conversation_ids(&payload_value, &mut conversation_ids);
        let rules = ScrubRules {
            home: home.clone(),
            hostname: hostname.clone(),
            conversation_ids,
        };

        let case_dir = fixture_dir.join(seq);
        std::fs::create_dir_all(&case_dir)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", case_dir.display()));

        write_json(
            &case_dir.join("meta.json"),
            &serde_json::json!({"source": source, "features": []}),
        );

        let request_value: Value = serde_json::from_slice(
            &std::fs::read(request_path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", request_path.display())),
        )
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", request_path.display()));
        write_json(
            &case_dir.join("request.json"),
            &scrub_value(request_value, &rules),
        );

        write_json(
            &case_dir.join("expected-payload.json"),
            &scrub_value(payload_value, &rules),
        );

        if upstream_path.exists() {
            let raw = std::fs::read(&upstream_path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", upstream_path.display()));
            std::fs::write(
                case_dir.join("upstream.eventstream"),
                scrub_eventstream(&raw, &rules),
            )
            .unwrap();
        }

        if response_path.exists() {
            let text = std::fs::read_to_string(&response_path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", response_path.display()));
            let scrubbed = mask_msg_ids(&scrub_string(&text, &rules));
            std::fs::write(case_dir.join("expected-sse.txt"), scrubbed).unwrap();
        }

        println!(
            "wrote {}: rename it to a descriptive case name and fill in meta.json's \"features\"",
            case_dir.display()
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check-versions") => println!("versions ok"),
        Some("make-db") => {
            let path = args.get(1).expect("usage: cargo xtask make-db <path>");
            make_synthetic_db(path);
            println!("wrote {path}");
        }
        Some("scrub") => {
            let usage = "usage: cargo xtask scrub <capture-dir> <fixture-dir> --source \"<text>\"";
            let capture_dir = args.get(1).unwrap_or_else(|| panic!("{usage}"));
            let fixture_dir = args.get(2).unwrap_or_else(|| panic!("{usage}"));
            let source = args
                .iter()
                .position(|a| a == "--source")
                .and_then(|i| args.get(i + 1))
                .unwrap_or_else(|| panic!("{usage}"));
            scrub_capture_dir(Path::new(capture_dir), Path::new(fixture_dir), source);
        }
        other => {
            eprintln!(
                "usage: cargo xtask <check-versions|make-db <path>|scrub <capture-dir> <fixture-dir> --source \"<text>\">; got {other:?}"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_rewrites_identity_in_strings() {
        let home = "/home/someone";
        let v: Value = serde_json::json!({
            "profileArn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/ABCDEF",
            "conversationState": {"conversationId": "real-conv", "history": [{"userInputMessage": {"content": "cwd /home/someone/proj on host laptop.local"}}]}
        });
        let out = scrub_value(
            v,
            &ScrubRules {
                home: home.into(),
                hostname: "laptop.local".into(),
                conversation_ids: vec!["real-conv".into()],
            },
        );
        assert_eq!(out["profileArn"], FIXTURE_ARN);
        assert_eq!(
            out["conversationState"]["conversationId"],
            FIXTURE_CONVERSATION_ID
        );
        assert_eq!(
            out["conversationState"]["history"][0]["userInputMessage"]["content"],
            "cwd /home/user/proj on host host"
        );
    }

    // Ruling 5, case 1: a conversation id nested in an array rather than
    // the documented `conversationState.conversationId` location must
    // still be collected and scrubbed.
    #[test]
    fn conversation_id_is_found_in_a_nested_array() {
        let v: Value = serde_json::json!({
            "conversationState": {
                "history": [
                    {"assistantResponseMessage": {"toolUses": [{"conversationId": "buried-id"}]}}
                ]
            }
        });
        let mut ids = Vec::new();
        collect_conversation_ids(&v, &mut ids);
        assert_eq!(ids, vec!["buried-id".to_string()]);

        let rules = ScrubRules {
            home: String::new(),
            hostname: String::new(),
            conversation_ids: ids,
        };
        let text = scrub_string("session was buried-id, no other id here", &rules);
        assert_eq!(
            text,
            format!("session was {FIXTURE_CONVERSATION_ID}, no other id here")
        );
    }

    // Ruling 5, case 2: a home path with a trailing slash rewrites the same
    // as one without, and an occurrence mid-string (not just a whole path
    // component) is still rewritten.
    #[test]
    fn home_path_trailing_slash_and_mid_string_occurrences_are_rewritten() {
        let trailing = ScrubRules {
            home: "/home/someone/".into(),
            hostname: String::new(),
            conversation_ids: vec![],
        };
        assert_eq!(
            scrub_string("cwd is /home/someone/project", &trailing),
            "cwd is /home/user/project"
        );
        // The trailing slash on the rule itself must not be duplicated or
        // swallowed when the text already ends without one.
        assert_eq!(
            scrub_string("home is /home/someone", &trailing),
            "home is /home/user"
        );

        let no_trailing = ScrubRules {
            home: "/home/someone".into(),
            hostname: String::new(),
            conversation_ids: vec![],
        };
        // Mid-string: "/home/someone" appears immediately followed by more
        // characters with no path separator between them.
        assert_eq!(
            scrub_string("backup at /home/someonebackup.tar", &no_trailing),
            "backup at /home/userbackup.tar"
        );
    }

    // Ruling 5, case 3: an account id of a different length than 12 digits
    // is still a profile ARN and must still be scrubbed.
    #[test]
    fn profile_arn_with_a_nonstandard_account_id_length_is_scrubbed() {
        let rules = ScrubRules {
            home: String::new(),
            hostname: String::new(),
            conversation_ids: vec![],
        };
        for arn in [
            "arn:aws:codewhisperer:us-east-1:1234:profile/SHORT",
            "arn:aws:codewhisperer:us-east-1:123456789012345:profile/LONG",
        ] {
            assert_eq!(scrub_string(arn, &rules), FIXTURE_ARN);
        }
    }

    // Ruling 5, case 4: the hostname must not be rewritten when it occurs
    // only as a substring of a longer word.
    #[test]
    fn hostname_as_a_substring_of_a_longer_word_is_not_rewritten() {
        let rules = ScrubRules {
            home: String::new(),
            hostname: "laptop.local".into(),
            conversation_ids: vec![],
        };
        assert_eq!(
            scrub_string("reachable at somelaptop.localhost today", &rules),
            "reachable at somelaptop.localhost today"
        );
        // The same hostname standing alone is still rewritten.
        assert_eq!(
            scrub_string("reachable at laptop.local today", &rules),
            "reachable at host today"
        );
    }

    // Ruling 5, case 5: a payload with no identity fields at all round-trips
    // unchanged.
    #[test]
    fn payload_with_no_identity_fields_round_trips_unchanged() {
        let v: Value = serde_json::json!({
            "conversationState": {
                "chatTriggerType": "MANUAL",
                "currentMessage": {"userInputMessage": {"content": "plain text, nothing sensitive"}}
            }
        });
        let rules = ScrubRules {
            home: "/home/someone".into(),
            hostname: "laptop.local".into(),
            conversation_ids: vec!["real-conv".into()],
        };
        let out = scrub_value(v.clone(), &rules);
        assert_eq!(out, v);
    }

    #[test]
    fn mask_msg_ids_replaces_every_occurrence() {
        let text = r#"{"id":"msg_abc123"} then {"id":"msg_def456"}"#;
        assert_eq!(
            mask_msg_ids(text),
            r#"{"id":"msg_MASKED"} then {"id":"msg_MASKED"}"#
        );
    }
}
