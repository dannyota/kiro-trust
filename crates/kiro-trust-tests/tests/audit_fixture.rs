//! The audit gate's committed JSON must never carry the fixture's ARN,
//! account id, or the synthetic database's placeholder values, proven
//! directly by a test and not only by `scripts/check-fixtures.sh`
//! (task-20-rulings.md ruling 4).
//!
//! Extended for the `extra_ca` field (spec 6.6): the fixture's audit run
//! configures no `--extra-ca`, so `extra_ca` must be the literal `none`,
//! and this file must never carry a home directory or PEM certificate
//! bytes either, the same leak classes this test already guards for the
//! credential path.

use std::fs;

#[test]
fn committed_audit_json_has_no_arn_account_id_or_placeholder() {
    let path = kiro_trust_tests::fixtures_dir().join("db/idc-audit.json");
    let json = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert!(
        !json.contains("arn:aws"),
        "audit fixture JSON contains an ARN:\n{json}"
    );
    assert!(
        !json.contains("000000000000"),
        "audit fixture JSON contains an account id:\n{json}"
    );
    assert!(
        !json.contains("placeholder"),
        "audit fixture JSON contains a placeholder value:\n{json}"
    );
    // spec 6.6: the fixture's audit run has no --extra-ca configured, so
    // the field must be the literal "none", never a path or certificate
    // content.
    assert!(
        json.contains("\"extra_ca\": \"none\""),
        "audit fixture JSON is missing extra_ca: \"none\":\n{json}"
    );
    assert!(
        !json.contains("BEGIN CERTIFICATE"),
        "audit fixture JSON contains certificate bytes:\n{json}"
    );
    assert!(
        !json.contains("/home/") && !json.contains("\\Users\\"),
        "audit fixture JSON contains an unabbreviated home directory:\n{json}"
    );
}
