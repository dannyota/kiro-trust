//! The audit gate's committed JSON must never carry the fixture's ARN,
//! account id, or the synthetic database's placeholder values, proven
//! directly by a test and not only by `scripts/check-fixtures.sh`
//! (task-20-rulings.md ruling 4).

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
}
