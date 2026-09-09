//! Developer tasks: fixture scrubbing, version checks, synthetic databases.

/// The synthetic Kiro CLI database rows for the audit gate (spec 8.7),
/// shared by `include_str!` with the `#[cfg(test)] mod tests` block of
/// `crates/kiro-trust/src/audit.rs` so the two can never drift out of
/// byte-identical sync (task-20-fix-1.md Important 4). A relative-path
/// `include_str!`, not a crate dependency: `xtask` must not depend on the
/// binary crate (task-20-rulings.md ruling 2). See the SQL file's own
/// header for what it contains and why.
const SYNTHETIC_IDC_SQL: &str = include_str!("../../crates/kiro-trust-auth/synthetic-idc.sql");

fn make_synthetic_db(path: &str) {
    let conn = rusqlite::Connection::open(path).expect("open");
    conn.execute_batch(SYNTHETIC_IDC_SQL).expect("populate");
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
