//! Developer tasks: fixture scrubbing, version checks, synthetic databases.

#[cfg(test)]
use kiro_trust_protocol::eventstream::encode_event_frame;
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

// Kept in sync by hand with two other copies (task-21-fix-1 Minor 6):
// `crates/kiro-trust-tests/src/lib.rs`'s `FIXTURE_ARN`/`FIXTURE_CONVERSATION_ID`
// (`xtask` must not depend on `kiro-trust-tests`) and the grep allowlists
// in `scripts/check-fixtures.sh`. A drift here would make the scrubber
// emit an ARN or id the scanner treats as real; change all three together.
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

/// Candidate hostname strings to scrub, longest first: the full detected
/// value, then its first label (the part before the first `.`), when that
/// differs from the full value. `hostname` on most systems prints only the
/// short label, but detection can still yield an FQDN (an explicit
/// `--hostname` override, or a platform whose `hostname` prints one); if a
/// capture holds only the short label while detection returned the FQDN,
/// scrubbing the FQDN alone would never match it, because
/// `rest.find(hostname)` never finds the shorter string inside itself
/// (task-21-fix-1 Important 1). The reverse direction already worked: a
/// short label detected still matches inside a longer FQDN occurrence via
/// `replace_hostname_token`'s substring search. Longest first so the more
/// specific string is tried before the shorter one it may be a prefix of.
fn hostname_candidates(hostname: &str) -> Vec<&str> {
    if hostname.is_empty() {
        return Vec::new();
    }
    match hostname.split_once('.') {
        Some((label, _)) if !label.is_empty() => vec![hostname, label],
        _ => vec![hostname],
    }
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

    for candidate in hostname_candidates(&rules.hostname) {
        out = replace_hostname_token(&out, candidate);
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

/// Collect every string found under a `conversationId` or `utteranceId`
/// key, anywhere in the value: nested inside an array, inside a deeply
/// nested object, not only at the documented
/// `conversationState.conversationId` location (ruling 5). Missing one
/// location because a later capture nests it differently is exactly the
/// kind of gap that leaves a real id in a public fixture, so this walks
/// the whole structure rather than a fixed path.
///
/// Both id kinds are collected here, not only conversation ids
/// (task-21-fix-1 Important 4): spec 8.3 says the scrubber replaces
/// "conversation and utterance ids with a fixed id", but the previous code
/// only ever collected `conversationId`, so an `utteranceId` outside the
/// one special-cased `messageMetadataEvent` frame reached a public fixture
/// unscrubbed. An utterance id is session-linkable exactly like a
/// conversation id and belongs in the same class.
fn collect_conversation_and_utterance_ids(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                if (k == "conversationId" || k == "utteranceId")
                    && let Some(s) = val.as_str()
                    && !s.is_empty()
                {
                    out.push(s.to_string());
                }
                collect_conversation_and_utterance_ids(val, out);
            }
        }
        Value::Array(a) => {
            for item in a {
                collect_conversation_and_utterance_ids(item, out);
            }
        }
        _ => {}
    }
}

/// Replace `"msg_..."` ids with a fixed placeholder so a captured id never
/// has to match a freshly generated one byte for byte (spec 8.2: the
/// fixture harness masks its own generated output the same way before
/// comparing). Duplicates `crates/kiro-trust-tests/src/lib.rs`'s
/// `mask_message_ids` line for line (task-21-fix-1 Minor 6); `xtask` must
/// not depend on that crate, so keep both in sync by hand.
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
///
/// A payload that does not parse as JSON, or that fails to re-encode after
/// scrubbing, aborts the whole scrub instead of passing the original bytes
/// through unscrubbed (task-21-fix-1 Important 3): a frame this tool does
/// not understand is exactly the case where a person must look before
/// anything is published, and a security tool that silently forwards what
/// it cannot parse is worse than one that stops. A warning would be missed
/// in a long scrub run; aborting cannot be.
fn scrub_frame_payload(
    index: usize,
    event_type: Option<&str>,
    payload: &[u8],
    rules: &ScrubRules,
) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(payload).unwrap_or_else(|e| {
        panic!(
            "cannot scrub eventstream frame {index} (event type {}): payload is not valid JSON \
             ({e}); inspect this capture by hand before publishing it",
            event_type.unwrap_or("<none>")
        )
    });
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
    serde_json::to_vec(&scrub_value(v, rules)).unwrap_or_else(|e| {
        panic!(
            "cannot scrub eventstream frame {index} (event type {}): failed to re-encode \
             scrubbed JSON: {e}",
            event_type.unwrap_or("<none>")
        )
    })
}

/// Decode `raw` frame by frame, scrub each payload, and re-encode. Headers
/// are copied through unchanged: `:message-type`, `:event-type`, and
/// `:content-type` carry no identity (spec 7.5), and spec 8.3 only asks
/// for the payload to be scrubbed.
///
/// A malformed frame or a stream truncated mid-frame aborts the scrub
/// rather than returning the frames decoded so far behind a printed
/// warning (task-21-fix-1 Important 3's principle, applied to this whole
/// function and not only the payload-JSON case it names): writing out a
/// partial result under a warning that is easy to miss in a long scrub run
/// is the same silent partial-processing this round of fixes exists to
/// close.
fn scrub_eventstream(raw: &[u8], rules: &ScrubRules) -> Vec<u8> {
    let mut decoder = FrameDecoder::new();
    decoder.push(raw);
    let mut out = Vec::new();
    let mut index = 0usize;
    loop {
        match decoder.next_frame() {
            Ok(Some(frame)) => {
                let payload = scrub_frame_payload(index, frame.event_type(), &frame.payload, rules);
                let mut headers = Vec::new();
                for (name, value) in &frame.headers {
                    push_header(&mut headers, name, value);
                }
                out.extend(encode_frame(&headers, &payload));
                index += 1;
            }
            Ok(None) => break,
            Err(e) => panic!(
                "cannot scrub eventstream: malformed frame at index {index}: {e}; a partially \
                 scrubbed stream must not be published"
            ),
        }
    }
    decoder.finish().unwrap_or_else(|e| {
        panic!(
            "cannot scrub eventstream: the capture ended with a truncated frame ({e}); a \
             partially scrubbed stream must not be published"
        )
    });
    out
}

fn write_json(path: &Path, v: &Value) {
    let text = serde_json::to_string_pretty(v).unwrap() + "\n";
    std::fs::write(path, text).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

/// Run the `hostname` command and return its trimmed output, or `None` if
/// the binary is missing, exits non-zero, or prints invalid UTF-8 or
/// nothing at all. Never returns `Some("")`: callers must treat detection
/// failure as failure, not as an empty rule that silently scrubs nothing
/// (task-21-fix-1 Important 1).
fn detect_hostname() -> Option<String> {
    let out = std::process::Command::new("hostname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Resolve the home directory to scrub: an explicit `--home` wins, else
/// `$HOME`. Aborts rather than scrubbing with an empty rule (task-21-fix-1
/// Important 1): a missing or empty `$HOME` used to become
/// `unwrap_or_default()`, so a scrub could silently skip the home-path
/// rule with no output anywhere in the pipeline.
fn resolve_home(override_home: Option<&str>, home_env: Option<String>) -> String {
    if let Some(h) = override_home {
        return h.to_string();
    }
    match home_env {
        Some(h) if !h.is_empty() => h,
        _ => panic!(
            "cannot determine the home directory to scrub: $HOME is unset or empty; pass \
             --home <path>"
        ),
    }
}

/// Resolve the hostname to scrub: an explicit `--hostname` wins, else
/// `hostname` command detection. Aborts rather than scrubbing with an
/// empty rule (task-21-fix-1 Important 1): a failed detection used to
/// become an empty string that the caller then skipped silently.
fn resolve_hostname(override_hostname: Option<&str>, detected: Option<String>) -> String {
    if let Some(h) = override_hostname {
        return h.to_string();
    }
    detected.unwrap_or_else(|| {
        panic!(
            "cannot determine this machine's hostname: the `hostname` command failed, was not \
             found, or produced empty output; pass --hostname <name>"
        )
    })
}

fn scrub_capture_dir(
    capture_dir: &Path,
    fixture_dir: &Path,
    source: &str,
    home: &str,
    hostname: &str,
) {
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

        let request_value: Value = serde_json::from_slice(
            &std::fs::read(request_path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", request_path.display())),
        )
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", request_path.display()));

        let payload_value: Value = serde_json::from_slice(
            &std::fs::read(&payload_path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", payload_path.display())),
        )
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", payload_path.display()));

        // Collected from both the client request and the Kiro payload
        // (task-21-fix-1 Important 4): an utterance id is session-linkable
        // exactly like a conversation id and belongs wherever the walk
        // runs, not only inside a `messageMetadataEvent` frame.
        let mut ids = Vec::new();
        collect_conversation_and_utterance_ids(&request_value, &mut ids);
        collect_conversation_and_utterance_ids(&payload_value, &mut ids);
        let rules = ScrubRules {
            home: home.to_string(),
            hostname: hostname.to_string(),
            conversation_ids: ids,
        };

        // The Anthropic request's own `stream` field decides which
        // expected-output file the fixture harness looks for
        // (`expected-sse.txt` for a streaming case, `expected-message.json`
        // otherwise; spec 8.2), so the scrub must write the same one
        // (task-21-fix-1 Minor 4): a non-streaming capture's folded JSON
        // body was previously always written to `expected-sse.txt`, which
        // the harness never reads for a non-streaming request, so the case
        // was missing the file it actually checks.
        let streaming = request_value
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let case_dir = fixture_dir.join(seq);
        std::fs::create_dir_all(&case_dir)
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", case_dir.display()));

        write_json(
            &case_dir.join("meta.json"),
            &serde_json::json!({
                // The operator's `--source` text is scrubbed like every
                // other captured field (task-21-fix-1 Minor 5): it is free
                // text and could otherwise carry a path or hostname
                // straight into a public fixture.
                "source": scrub_string(source, &rules),
                "features": [],
                "stream": streaming,
            }),
        );

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
            if streaming {
                let scrubbed = mask_msg_ids(&scrub_string(&text, &rules));
                std::fs::write(case_dir.join("expected-sse.txt"), scrubbed).unwrap();
            } else {
                let v: Value = serde_json::from_str(&text).unwrap_or_else(|e| {
                    panic!(
                        "{} is not valid JSON (a non-streaming capture's response is the \
                         folded JSON body): {e}",
                        response_path.display()
                    )
                });
                write_json(
                    &case_dir.join("expected-message.json"),
                    &scrub_value(v, &rules),
                );
            }
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
            let usage = "usage: cargo xtask scrub <capture-dir> <fixture-dir> --source \"<text>\" \
                          [--hostname <name>] [--home <path>]";
            let capture_dir = args.get(1).unwrap_or_else(|| panic!("{usage}"));
            let fixture_dir = args.get(2).unwrap_or_else(|| panic!("{usage}"));
            let source = args
                .iter()
                .position(|a| a == "--source")
                .and_then(|i| args.get(i + 1))
                .unwrap_or_else(|| panic!("{usage}"));
            // `--hostname`/`--home` let an operator supply either value
            // explicitly when detection fails on this machine
            // (task-21-fix-1 Important 1).
            let hostname_arg = args
                .iter()
                .position(|a| a == "--hostname")
                .and_then(|i| args.get(i + 1));
            let home_arg = args
                .iter()
                .position(|a| a == "--home")
                .and_then(|i| args.get(i + 1));
            let home = resolve_home(home_arg.map(String::as_str), std::env::var("HOME").ok());
            let hostname = resolve_hostname(hostname_arg.map(String::as_str), detect_hostname());
            scrub_capture_dir(
                Path::new(capture_dir),
                Path::new(fixture_dir),
                source,
                &home,
                &hostname,
            );
        }
        other => {
            eprintln!(
                "usage: cargo xtask <check-versions|make-db <path>|scrub <capture-dir> <fixture-dir> --source \"<text>\" [--hostname <name>] [--home <path>]>; got {other:?}"
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
        collect_conversation_and_utterance_ids(&v, &mut ids);
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

    // ---- Important 1: hostname/home detection abort loudly instead of
    // scrubbing with an empty rule, and a short hostname label is caught
    // even when detection returned the FQDN. ------------------------------

    #[test]
    fn resolve_home_prefers_override_then_env() {
        assert_eq!(resolve_home(Some("/override"), None), "/override");
        assert_eq!(
            resolve_home(None, Some("/from/env".to_string())),
            "/from/env"
        );
    }

    #[test]
    #[should_panic(expected = "--home")]
    fn resolve_home_aborts_when_neither_is_available() {
        resolve_home(None, None);
    }

    #[test]
    #[should_panic(expected = "--home")]
    fn resolve_home_aborts_on_an_empty_env_value() {
        resolve_home(None, Some(String::new()));
    }

    #[test]
    fn resolve_hostname_prefers_override_then_detected() {
        assert_eq!(
            resolve_hostname(Some("override-host"), None),
            "override-host"
        );
        assert_eq!(
            resolve_hostname(None, Some("detected-host".to_string())),
            "detected-host"
        );
    }

    #[test]
    #[should_panic(expected = "--hostname")]
    fn resolve_hostname_aborts_when_neither_is_available() {
        resolve_hostname(None, None);
    }

    #[test]
    fn hostname_short_label_is_scrubbed_when_detection_returns_the_fqdn() {
        let rules = ScrubRules {
            home: String::new(),
            hostname: "laptop.corp.example.com".into(),
            conversation_ids: vec![],
        };
        // The capture holds only the short label; detection returned the
        // FQDN. Scrubbing the FQDN alone would never match this.
        assert_eq!(
            scrub_string("reachable at laptop today", &rules),
            "reachable at host today"
        );
        // The FQDN itself is still scrubbed when it does appear.
        assert_eq!(
            scrub_string("reachable at laptop.corp.example.com today", &rules),
            "reachable at host today"
        );
        // The short label as a substring of an unrelated word is still
        // left alone (ruling 5's whole-token rule applies to each
        // candidate).
        assert_eq!(
            scrub_string("laptops are great", &rules),
            "laptops are great"
        );
    }

    // ---- Important 2/3: the event-stream scrub path, previously
    // untested, is the highest-value coverage in this round. -------------

    #[test]
    fn scrub_eventstream_rewrites_identity_and_ids_in_the_re_encoded_bytes() {
        let rules = ScrubRules {
            home: "/home/someone".into(),
            hostname: "laptop.local".into(),
            conversation_ids: vec!["real-conv".into()],
        };
        let assistant_payload = br#"{"content":"error at /home/someone/proj on laptop.local"}"#;
        let metadata_payload =
            br#"{"conversationId":"real-conv","utteranceId":"runtime-assigned-utterance"}"#;
        let raw = [
            encode_event_frame("assistantResponseEvent", assistant_payload),
            encode_event_frame("messageMetadataEvent", metadata_payload),
        ]
        .concat();

        let out = scrub_eventstream(&raw, &rules);

        // Assert on the re-encoded bytes, decoding them back, so the test
        // covers push_header/encode_frame (the encode half) too, not only
        // scrub_frame_payload's return value.
        let mut decoder = FrameDecoder::new();
        decoder.push(&out);
        let first = decoder.next_frame().unwrap().unwrap();
        assert_eq!(first.event_type(), Some("assistantResponseEvent"));
        let first_json: Value = serde_json::from_slice(&first.payload).unwrap();
        assert_eq!(first_json["content"], "error at /home/user/proj on host");

        let second = decoder.next_frame().unwrap().unwrap();
        assert_eq!(second.event_type(), Some("messageMetadataEvent"));
        let second_json: Value = serde_json::from_slice(&second.payload).unwrap();
        assert_eq!(second_json["conversationId"], FIXTURE_CONVERSATION_ID);
        // A runtime-assigned utteranceId that never appeared in the
        // request is still replaced: messageMetadataEvent's two ids are
        // rewritten unconditionally (spec 8.3).
        assert_eq!(second_json["utteranceId"], FIXTURE_CONVERSATION_ID);

        assert!(decoder.next_frame().unwrap().is_none());
        decoder.finish().unwrap();
    }

    #[test]
    #[should_panic(expected = "payload is not valid JSON")]
    fn scrub_eventstream_aborts_on_a_non_json_payload() {
        let rules = ScrubRules {
            home: String::new(),
            hostname: String::new(),
            conversation_ids: vec![],
        };
        let raw = encode_event_frame("assistantResponseEvent", b"not json");
        scrub_eventstream(&raw, &rules);
    }

    #[test]
    #[should_panic(expected = "truncated frame")]
    fn scrub_eventstream_aborts_on_a_truncated_stream() {
        let rules = ScrubRules {
            home: String::new(),
            hostname: String::new(),
            conversation_ids: vec![],
        };
        let full = encode_event_frame("assistantResponseEvent", br#"{"content":"hi"}"#);
        // Cut the frame in half: an incomplete frame at end of input.
        let truncated = &full[..full.len() / 2];
        scrub_eventstream(truncated, &rules);
    }

    #[test]
    fn scrub_eventstream_on_zero_frames_does_not_panic() {
        let rules = ScrubRules {
            home: String::new(),
            hostname: String::new(),
            conversation_ids: vec![],
        };
        assert_eq!(scrub_eventstream(&[], &rules), Vec::<u8>::new());
    }

    // Important 4: an utteranceId is session-linkable like a conversation
    // id and must be collected and scrubbed wherever it appears, not only
    // inside a messageMetadataEvent frame.
    #[test]
    fn utterance_id_in_request_and_payload_is_replaced() {
        let request: Value = serde_json::json!({
            "messages": [],
            "utteranceId": "real-utterance-in-request"
        });
        let payload: Value = serde_json::json!({
            "conversationState": {
                "currentMessage": {"userInputMessage": {
                    "userInputMessageContext": {"utteranceId": "real-utterance-in-payload"}
                }}
            }
        });
        let mut ids = Vec::new();
        collect_conversation_and_utterance_ids(&request, &mut ids);
        collect_conversation_and_utterance_ids(&payload, &mut ids);
        assert_eq!(
            ids,
            vec![
                "real-utterance-in-request".to_string(),
                "real-utterance-in-payload".to_string(),
            ]
        );

        let rules = ScrubRules {
            home: String::new(),
            hostname: String::new(),
            conversation_ids: ids,
        };
        let scrubbed_request = scrub_value(request, &rules);
        assert_eq!(scrubbed_request["utteranceId"], FIXTURE_CONVERSATION_ID);
        let scrubbed_payload = scrub_value(payload, &rules);
        assert_eq!(
            scrubbed_payload["conversationState"]["currentMessage"]["userInputMessage"]["userInputMessageContext"]
                ["utteranceId"],
            FIXTURE_CONVERSATION_ID
        );
    }

    // Important 6: two ARNs in one string is the exact input that
    // triggered the infinite loop this task fixed; pin it as a regression.
    #[test]
    fn two_arns_in_one_string_are_both_scrubbed() {
        let rules = ScrubRules {
            home: String::new(),
            hostname: String::new(),
            conversation_ids: vec![],
        };
        let input = "first arn:aws:codewhisperer:us-east-1:111111111111:profile/AAAA then \
                     arn:aws:codewhisperer:eu-central-1:222222222222:profile/BBBB end";
        assert_eq!(
            scrub_string(input, &rules),
            format!("first {FIXTURE_ARN} then {FIXTURE_ARN} end")
        );
    }

    #[test]
    fn two_arns_in_different_fields_of_a_nested_object_are_both_scrubbed() {
        let v: Value = serde_json::json!({
            "a": {"profileArn": "arn:aws:codewhisperer:us-east-1:111111111111:profile/AAAA"},
            "b": {"nested": {
                "otherArn": "arn:aws:codewhisperer:eu-central-1:222222222222:profile/BBBB"
            }}
        });
        let rules = ScrubRules {
            home: String::new(),
            hostname: String::new(),
            conversation_ids: vec![],
        };
        let out = scrub_value(v, &rules);
        assert_eq!(out["a"]["profileArn"], FIXTURE_ARN);
        assert_eq!(out["b"]["nested"]["otherArn"], FIXTURE_ARN);
    }

    // ---- Important 2 (end to end): a synthetic capture directory through
    // scrub_capture_dir, the test that would have caught Important 4 and
    // Minor 4. -------------------------------------------------------------

    #[test]
    fn scrub_capture_dir_end_to_end_produces_a_clean_streaming_fixture_case() {
        let capture = tempfile::tempdir().unwrap();
        let fixtures = tempfile::tempdir().unwrap();

        let request = serde_json::json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 16,
            "stream": true,
            "messages": [{"role": "user", "content": "hi from /home/someone on laptop.local"}]
        });
        let payload = serde_json::json!({
            "profileArn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/REAL",
            "conversationState": {
                "conversationId": "real-conv",
                "currentMessage": {"userInputMessage": {
                    "content": "hi",
                    "userInputMessageContext": {"utteranceId": "real-utterance"}
                }}
            }
        });
        std::fs::write(
            capture.path().join("0001-request.json"),
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        std::fs::write(
            capture.path().join("0001-payload.json"),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        let metadata_payload = serde_json::json!({
            "conversationId": "real-conv",
            "utteranceId": "runtime-assigned"
        });
        let stream = encode_event_frame(
            "messageMetadataEvent",
            &serde_json::to_vec(&metadata_payload).unwrap(),
        );
        std::fs::write(capture.path().join("0001-upstream.eventstream"), &stream).unwrap();
        std::fs::write(
            capture.path().join("0001-response.sse"),
            "event: message_start\ndata: \
             {\"id\":\"msg_realid123\",\"conversationId\":\"real-conv\"}\n\n",
        )
        .unwrap();

        scrub_capture_dir(
            capture.path(),
            fixtures.path(),
            "capture kiro-cli 2.21.1 2026-09-09 from /home/someone",
            "/home/someone",
            "laptop.local",
        );

        let case_dir = fixtures.path().join("0001");
        for name in [
            "meta.json",
            "request.json",
            "expected-payload.json",
            "upstream.eventstream",
            "expected-sse.txt",
        ] {
            assert!(case_dir.join(name).exists(), "missing {name}");
        }
        assert!(
            !case_dir.join("expected-message.json").exists(),
            "a streaming case must not write expected-message.json"
        );

        let leaks = [
            "123456789012",
            "real-conv",
            "runtime-assigned",
            "real-utterance",
            "/home/someone",
            "laptop.local",
            "msg_realid123",
        ];
        for name in [
            "meta.json",
            "request.json",
            "expected-payload.json",
            "upstream.eventstream",
            "expected-sse.txt",
        ] {
            let bytes = std::fs::read(case_dir.join(name)).unwrap();
            for needle in leaks {
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                    "{name} still contains {needle:?}"
                );
            }
        }
    }

    #[test]
    fn scrub_capture_dir_writes_expected_message_json_for_a_non_streaming_capture() {
        let capture = tempfile::tempdir().unwrap();
        let fixtures = tempfile::tempdir().unwrap();
        let request = serde_json::json!({
            "model": "claude-haiku-4-5",
            "max_tokens": 8,
            "stream": false,
            "messages": []
        });
        let payload = serde_json::json!({"profileArn": FIXTURE_ARN, "conversationState": {}});
        std::fs::write(
            capture.path().join("0001-request.json"),
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        std::fs::write(
            capture.path().join("0001-payload.json"),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        std::fs::write(
            capture.path().join("0001-response.sse"),
            serde_json::to_vec(&serde_json::json!({"id": "msg_real", "type": "message"})).unwrap(),
        )
        .unwrap();

        scrub_capture_dir(
            capture.path(),
            fixtures.path(),
            "capture test",
            "/home/x",
            "host.example.com",
        );

        let case_dir = fixtures.path().join("0001");
        assert!(case_dir.join("expected-message.json").exists());
        assert!(
            !case_dir.join("expected-sse.txt").exists(),
            "a non-streaming case must not write expected-sse.txt"
        );
        let meta: Value =
            serde_json::from_slice(&std::fs::read(case_dir.join("meta.json")).unwrap()).unwrap();
        assert_eq!(meta["stream"], false);
    }
}
