//! Developer tasks: fixture scrubbing, version checks, synthetic databases.

/// The synthetic Kiro CLI database for the audit gate (spec 8.7). Byte
/// identical to the `make_synthetic_db` helper in the `#[cfg(test)] mod
/// tests` block of `crates/kiro-trust/src/audit.rs`, duplicated rather than
/// shared because `xtask` must not depend on the binary crate
/// (task-20-rulings.md ruling 2). Only placeholders and the fixture ARN
/// (task-20-rulings.md ruling 1, ruling 4); never a real credential.
fn make_synthetic_db(path: &str) {
    let conn = rusqlite::Connection::open(path).expect("open");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS auth_kv (key TEXT PRIMARY KEY, value TEXT);
         CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value BLOB);
         DELETE FROM auth_kv; DELETE FROM state;
         INSERT INTO auth_kv VALUES ('kirocli:odic:token', '{\"access_token\":\"placeholder-access\",\"refresh_token\":\"ph-ref\",\"expires_at\":\"2099-01-01T00:00:00Z\",\"region\":\"us-east-1\"}');
         INSERT INTO auth_kv VALUES ('kirocli:odic:device-registration', '{\"clientId\":\"placeholder-client\",\"clientSecret\":\"ph-sec\"}');
         INSERT INTO state VALUES ('auth.idc.region', '\"us-east-1\"');
         INSERT INTO state VALUES ('api.codewhisperer.profile', '{\"arn\":\"arn:aws:codewhisperer:us-east-1:000000000000:profile/FIXTURE\",\"profile_name\":\"KiroProfile-us-east-1\"}');",
    )
    .expect("populate");
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
        other => {
            eprintln!("usage: cargo xtask <check-versions|make-db <path>>; got {other:?}");
            std::process::exit(2);
        }
    }
}
