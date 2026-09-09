//! `kiro-trust audit` (spec 4.2, 6.6). Reads the database read-only, never
//! touches the network, never prints an ARN, an account id, or a secret.
//!
//! No network call is made anywhere in this file: the only network-capable
//! type in the dependency graph is `kiro_trust_net::Client`, which this
//! module never constructs or imports, and `KiroDb::read_identity_center`
//! only reads rows already in the database (it never refreshes a token,
//! which is the one path in this workspace that calls the network).

use crate::config::{AuditArgs, parse_listen, resolve_db_path, resolve_token_file};
use kiro_trust_auth::KiroDb;
use kiro_trust_net::{Destination, RuntimeRegion};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;

/// Abbreviating the real home directory to `~` in audit output
/// (task-20-fix-1.md Important 1). Audit output is what a user pastes into
/// a bug report to show their configuration is safe, and a bare path leaks
/// the OS username the way a log line must not (CLAUDE.md; spec 6.4).
///
/// The two call sites need different mechanisms (task-20-fix-2.md Minor 1).
/// `credential_source.path` is a whole path, so `abbreviate_home_path`
/// strips the home as a path prefix with `Path::strip_prefix`, which
/// matches whole components: that fixes both `HOME=/` (which a plain
/// substring replace would turn into a `~` at every separator) and a
/// sibling directory that merely shares the home as a string prefix
/// (`/home/x-backup` under `HOME=/home/x`, which a substring replace would
/// mangle into `~-backup`). The `problems` string embeds the path
/// mid-sentence inside rusqlite's own error text, where a prefix strip
/// cannot reach it, so `abbreviate_home_in_message` keeps a substring
/// replacement, guarded to require the match be followed by a path
/// separator or the end of the string, for the same reason a sibling
/// directory must be left alone.
///
/// Both mechanisms treat `""` and `/` as "no abbreviation possible" and
/// return the input unchanged: an empty home has nothing to strip, and `/`
/// as home would eat the leading separator of every absolute path.
fn real_home() -> String {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn is_usable_home(home: &str) -> bool {
    !home.is_empty() && home != "/"
}

/// Abbreviates a whole path by stripping the home directory as a path
/// prefix. See the module-level comment above `real_home` for why this
/// call site needs `Path::strip_prefix` rather than a substring replace.
fn abbreviate_home_path(s: &str) -> String {
    abbreviate_home_path_with(s, &real_home())
}

fn abbreviate_home_path_with(s: &str, home: &str) -> String {
    if !is_usable_home(home) {
        return s.to_string();
    }
    match std::path::Path::new(s).strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => s.to_string(),
    }
}

/// Abbreviates a home-directory occurrence embedded mid-sentence inside a
/// message. See the module-level comment above `real_home` for why this
/// call site keeps a substring replace instead of a prefix strip, and why
/// each match is only abbreviated when followed by a path separator or the
/// end of the string.
fn abbreviate_home_in_message(s: &str) -> String {
    abbreviate_home_in_message_with(s, &real_home())
}

fn abbreviate_home_in_message_with(s: &str, home: &str) -> String {
    if !is_usable_home(home) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut remaining = s;
    while let Some(idx) = remaining.find(home) {
        let (before, at_match) = remaining.split_at(idx);
        out.push_str(before);
        let after = &at_match[home.len()..];
        let boundary_ok = after.is_empty() || after.starts_with('/') || after.starts_with('\\');
        out.push_str(if boundary_ok { "~" } else { home });
        remaining = after;
    }
    out.push_str(remaining);
    out
}

#[derive(Serialize, Default)]
pub struct CredentialSource {
    pub path: String,
    pub mode: String,
}

#[derive(Serialize, Default)]
pub struct Authentication {
    #[serde(rename = "type")]
    pub kind: String,
    pub sso_region: String,
    pub token_expires: String,
}

#[derive(Serialize, Default)]
pub struct Runtime {
    pub region: String,
    pub source: String,
}

#[derive(Serialize, Default)]
pub struct AuditReport {
    pub version: String,
    pub commit: String,
    pub credential_source: CredentialSource,
    pub authentication: Authentication,
    pub runtime: Runtime,
    pub allowed_outbound: Vec<String>,
    pub tls_roots: String,
    pub http_proxy: String,
    pub redirects: String,
    pub local_listener: String,
    pub local_authentication: String,
    pub telemetry: String,
    pub content_sharing: String,
    pub request_body_logging: String,
    pub dynamic_model_discovery: String,
    pub automatic_updates: String,
    pub build_features: Vec<String>,
    pub problems: Vec<String>,
}

pub fn report(args: &AuditArgs) -> Result<AuditReport, String> {
    let mut problems = Vec::new();
    let listener = match parse_listen(&args.listen) {
        Ok(a) => a.to_string(),
        Err(e) => {
            problems.push(e.to_string());
            args.listen.clone()
        }
    };
    let db_path = resolve_db_path(args.kiro_db.clone()).map_err(|e| e.to_string())?;
    // Resolved but, per spec 6.6, never printed: `local_authentication` is a
    // fixed description of the guarantee, not a report of where this
    // particular run would write a token (audit never writes one). When
    // `--token-file` is not given, this validates that a token directory
    // can be determined at all, the same config-error class `serve` fails
    // on at startup. When `--token-file` *is* given, `resolve_token_file`
    // cannot fail (it returns the given path unconditionally), so this
    // validates nothing in that case; the flag is kept for parity with
    // `serve`, which accepts the same flag, and so the CI audit gate can
    // point it at a scratch path rather than the caller's real runtime
    // directory (task-20-fix-1.md minor 5).
    let _token_file = resolve_token_file(args.token_file.clone()).map_err(|e| e.to_string())?;

    // Validated regardless of whether the credential loaded below (
    // task-20-fix-1.md minor 7): an invalid --runtime-region must always be
    // reported, not silently discarded when the database can't be opened.
    let region_arg = args.runtime_region.as_deref().map(RuntimeRegion::parse);
    if let Some(Err(e)) = &region_arg {
        problems.push(e.to_string());
    }

    let db_open = KiroDb::open_read_only(&db_path);
    // Measured, not asserted (task-20-fix-1.md Important 2): `is_read_only`
    // reads back the live connection's `query_only` pragma rather than this
    // module trusting that `open_read_only`'s flags took effect.
    let mode = match &db_open {
        Ok(db) if db.is_read_only() => "read-only, authorizer enforced".to_string(),
        Ok(_) => {
            problems.push(
                "database connection is not read-only: PRAGMA query_only reports false".to_string(),
            );
            "NOT read-only (query_only pragma unset)".to_string()
        }
        Err(_) => "unavailable (could not open the database)".to_string(),
    };
    let creds = db_open.and_then(|db| db.read_identity_center());
    let (auth, runtime, outbound) = match &creds {
        Ok(c) => {
            let (region, source) = match &region_arg {
                Some(Ok(r)) => (r.clone(), "from --runtime-region".to_string()),
                Some(Err(_)) | None => (c.runtime_region.clone(), "from profile".to_string()),
            };
            let expires = time::OffsetDateTime::from(c.expires_at)
                .format(&Rfc3339)
                .unwrap_or_else(|_| "unknown".into());
            (
                Authentication {
                    kind: "AWS IAM Identity Center".into(),
                    sso_region: c.sso_region.to_string(),
                    token_expires: format!("{expires} (refresh on demand)"),
                },
                Runtime {
                    region: region.to_string(),
                    source,
                },
                vec![
                    Destination::Oidc {
                        sso_region: c.sso_region.clone(),
                    }
                    .host(),
                    Destination::Runtime { region }.host(),
                ],
            )
        }
        Err(e) => {
            // AuthError::Open wraps rusqlite's message, which embeds the
            // full database path; abbreviate the whole formatted string,
            // not a pre-extracted path fragment, since the path is not
            // leading in this text (task-20-fix-1.md Important 1).
            problems.push(abbreviate_home_in_message(&format!("credential: {e}")));
            (
                Authentication {
                    kind: "unavailable".into(),
                    sso_region: "-".into(),
                    token_expires: "-".into(),
                },
                Runtime {
                    region: "-".into(),
                    source: "-".into(),
                },
                vec![],
            )
        }
    };
    let mut build_features = Vec::new();
    // `capture` is a feature of this binary crate, so `cfg!` here reports
    // this crate's own compiled features directly (task-20-rulings.md
    // ruling 5).
    if cfg!(feature = "capture") {
        build_features.push("capture".to_string());
    }
    // `test-endpoints` belongs to `kiro-trust-net`, not this crate, so the
    // constant is read from `kiro_trust_net` rather than evaluated with
    // `cfg!` here: a `cfg!(feature = "test-endpoints")` in this crate would
    // check this crate's own (nonexistent) feature of that name, not
    // whether `kiro-trust-net` itself was built with it, and would miss the
    // feature being unified in through `kiro-trust-tests` in a
    // workspace-wide build (task-20-rulings.md ruling 5; CLAUDE.md
    // Architecture rules).
    if kiro_trust_net::TEST_ENDPOINTS_COMPILED {
        build_features.push("test-endpoints".to_string());
    }
    for f in &build_features {
        problems.push(format!("development feature {f} is compiled in"));
    }
    Ok(AuditReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("KIRO_TRUST_COMMIT").to_string(),
        credential_source: CredentialSource {
            path: abbreviate_home_path(&db_path.display().to_string()),
            mode,
        },
        authentication: auth,
        runtime,
        allowed_outbound: outbound,
        tls_roots: kiro_trust_net::TLS_ROOTS.to_string(),
        http_proxy: kiro_trust_net::HTTP_PROXY.to_string(),
        redirects: kiro_trust_net::REDIRECTS.to_string(),
        local_listener: listener,
        // spec 6.3: file mode 0600 is set only `#[cfg(unix)]`
        // (crates/kiro-trust/src/token.rs); on Windows nothing sets a mode,
        // the file inherits the user profile ACL, and asserting the Unix
        // text there would be a false guarantee (task-20-fix-1.md
        // Critical 2).
        local_authentication: if cfg!(unix) {
            "required (token file 0600)".to_string()
        } else {
            "required (token file, user profile ACL)".to_string()
        },
        // telemetry, request_body_logging, dynamic_model_discovery, and
        // automatic_updates stay fixed literals (task-20-fix-1.md
        // Important 2, scoped): each asserts the *absence* of code, and a
        // constant sitting next to nothing cannot prove that any better
        // than a string literal does. Mechanizing tls_roots, http_proxy,
        // and redirects works because those assert the *presence* of a
        // specific, one-place builder call this module can read back.
        telemetry: "none".into(),
        content_sharing: if args.share_content {
            "enabled (--share-content)".into()
        } else {
            "opted out (x-amzn-codewhisperer-optout: true)".into()
        },
        request_body_logging: "disabled (no flag exists)".into(),
        dynamic_model_discovery: "disabled".into(),
        automatic_updates: "disabled".into(),
        build_features,
        problems,
    })
}

pub fn render_text(r: &AuditReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("kiro-trust {} ({})\n\n", r.version, r.commit));
    s.push_str(&format!(
        "Credential source\n  Kiro CLI SQLite      {}\n  mode                 {}\n\n",
        r.credential_source.path, r.credential_source.mode
    ));
    s.push_str(&format!(
        "Authentication\n  type                 {}\n  SSO region           {}\n  token expires        {}\n\n",
        r.authentication.kind, r.authentication.sso_region, r.authentication.token_expires
    ));
    s.push_str(&format!(
        "Runtime\n  region               {} ({})\n\n",
        r.runtime.region, r.runtime.source
    ));
    s.push_str("Allowed outbound\n");
    for h in &r.allowed_outbound {
        s.push_str(&format!("  {h}\n"));
    }
    s.push_str(&format!(
        "\nTLS roots              {}\nHTTP proxy             {}\nRedirects              {}\n\n",
        r.tls_roots, r.http_proxy, r.redirects
    ));
    s.push_str(&format!(
        "Local listener         {}\nLocal authentication   {}\n\n",
        r.local_listener, r.local_authentication
    ));
    s.push_str(&format!(
        "Telemetry              {}\nKiro content sharing   {}\nRequest body logging   {}\nDynamic model discovery {}\nAutomatic updates      {}\n\n",
        r.telemetry,
        r.content_sharing,
        r.request_body_logging,
        r.dynamic_model_discovery,
        r.automatic_updates
    ));
    s.push_str(&format!(
        "Build features         {}\n",
        if r.build_features.is_empty() {
            "none".to_string()
        } else {
            r.build_features.join(", ")
        }
    ));
    if !r.problems.is_empty() {
        s.push_str("\nProblems\n");
        for p in &r.problems {
            s.push_str(&format!("  {p}\n"));
        }
    }
    s
}

pub fn exit_code(r: &AuditReport) -> i32 {
    if r.problems.is_empty() { 0 } else { 1 }
}

pub fn run(args: AuditArgs) -> i32 {
    match report(&args) {
        Ok(r) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            } else {
                print!("{}", render_text(&r));
            }
            exit_code(&r)
        }
        Err(e) => {
            eprintln!("kiro-trust audit: {e}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditArgs;
    use std::path::Path;

    /// Placeholder database with the real schema (spec 8.7), for tests only.
    /// The SQL is `include_str!`-shared with `xtask/src/main.rs`'s
    /// `make-db` command, not duplicated, so the audit gate's fixture and
    /// this crate's own tests can never drift out of byte-identical sync
    /// (task-20-fix-1.md Important 4). This crate still carries no
    /// `rusqlite` in `[dependencies]` (CLAUDE.md: `KiroDb::open_read_only`
    /// is the only opener); `rusqlite` here is a `[dev-dependencies]` entry
    /// used only inside this `#[cfg(test)]` module. The file lives in this
    /// package's own directory, not `kiro-trust-auth`'s, so `cargo package`
    /// ships it and the published crate can run its own unit tests
    /// (task-20-fix-2.md Minor 3).
    const SYNTHETIC_IDC_SQL: &str = include_str!("../synthetic-idc.sql");

    fn make_synthetic_db(path: &Path) -> Result<(), String> {
        let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(SYNTHETIC_IDC_SQL)
            .map_err(|e| e.to_string())
    }

    fn synthetic_db(dir: &std::path::Path) -> std::path::PathBuf {
        let p = dir.join("idc.sqlite3");
        make_synthetic_db(&p).unwrap();
        p
    }

    #[test]
    fn report_has_every_line_and_no_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let db = synthetic_db(dir.path());
        let args = AuditArgs {
            json: false,
            listen: "127.0.0.1:3456".into(),
            kiro_db: Some(db.clone()),
            runtime_region: None,
            token_file: None,
            share_content: false,
        };
        let r = report(&args).unwrap();
        assert_eq!(r.authentication.kind, "AWS IAM Identity Center");
        // task-20-rulings.md ruling 1: us-east-1, not the owner's real
        // ap-southeast-1 SSO region.
        assert_eq!(r.authentication.sso_region, "us-east-1");
        assert_eq!(r.runtime.region, "us-east-1");
        assert_eq!(
            r.allowed_outbound,
            vec!["oidc.us-east-1.amazonaws.com", "runtime.us-east-1.kiro.dev"]
        );
        assert_eq!(r.tls_roots, "webpki-roots (compiled in)");
        assert_eq!(r.http_proxy, "disabled (environment ignored)");
        assert_eq!(r.telemetry, "none");
        assert_eq!(
            r.content_sharing,
            "opted out (x-amzn-codewhisperer-optout: true)"
        );
        assert_eq!(r.request_body_logging, "disabled (no flag exists)");
        // `cargo test -p kiro-trust` alone never compiles a development
        // feature into this crate or into `kiro-trust-net`, so both are
        // empty there. `cargo test --workspace` also builds
        // `kiro-trust-tests`, which depends on `kiro-trust-net` with
        // `test-endpoints` enabled; the new feature resolver unifies that
        // into the copy of `kiro-trust-net` this crate links against too
        // (CLAUDE.md Architecture rules: release builds and the feature
        // check select `-p kiro-trust` alone precisely to avoid this), so
        // `TEST_ENDPOINTS_COMPILED` can legitimately be true here. Compare
        // against that same ground truth instead of hard-coding "empty" so
        // this test holds under both invocations without weakening what it
        // proves: report() must derive build_features/problems from exactly
        // these two compiled-in signals, nothing else.
        let mut expected_features = Vec::new();
        if cfg!(feature = "capture") {
            expected_features.push("capture".to_string());
        }
        if kiro_trust_net::TEST_ENDPOINTS_COMPILED {
            expected_features.push("test-endpoints".to_string());
        }
        assert_eq!(r.build_features, expected_features);
        let expected_problems: Vec<String> = expected_features
            .iter()
            .map(|f| format!("development feature {f} is compiled in"))
            .collect();
        assert_eq!(r.problems, expected_problems);
        let text = render_text(&r);
        let build_features_line = if expected_features.is_empty() {
            "Build features         none".to_string()
        } else {
            format!("Build features         {}", expected_features.join(", "))
        };
        for line in [
            "Credential source".to_string(),
            "mode                 read-only, authorizer enforced".to_string(),
            "Local listener         127.0.0.1:3456".to_string(),
            "Automatic updates      disabled".to_string(),
            build_features_line,
        ] {
            assert!(text.contains(&line), "missing {line:?} in:\n{text}");
        }
        assert!(!text.contains("placeholder"));
        assert!(!text.contains("arn:aws"));
        assert!(!text.contains("000000000000"));
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("placeholder") && !json.contains("arn:aws"));
        assert!(!json.contains("000000000000"));
    }

    // task-20-fix-1.md minor 1: split from the old `problems_make_audit_fail`,
    // which set both a non-loopback `--listen` and `--share-content` and
    // asserted exit 1, so it never proved which condition caused the
    // failure. This half isolates the non-loopback listener.
    #[test]
    fn a_non_loopback_listener_fails_the_audit() {
        let dir = tempfile::tempdir().unwrap();
        let db = synthetic_db(dir.path());
        let args = AuditArgs {
            json: false,
            listen: "0.0.0.0:3456".into(),
            kiro_db: Some(db),
            runtime_region: None,
            token_file: None,
            share_content: false,
        };
        let r = report(&args).unwrap();
        assert!(
            r.problems.iter().any(|p| p.contains("loopback")),
            "{:?}",
            r.problems
        );
        assert_eq!(exit_code(&r), 1);
    }

    // task-20-fix-1.md minor 1: the other half. `--share-content` is
    // spec-conformant (it produces no `problems` entry, so the exit code
    // stays 0), and this test pins exactly that: the warning text is
    // present but the command still succeeds.
    #[test]
    fn share_content_warns_but_does_not_fail_the_audit() {
        let dir = tempfile::tempdir().unwrap();
        let db = synthetic_db(dir.path());
        let args = AuditArgs {
            json: false,
            listen: "127.0.0.1:3456".into(),
            kiro_db: Some(db),
            runtime_region: None,
            token_file: None,
            share_content: true,
        };
        let r = report(&args).unwrap();
        assert_eq!(r.content_sharing, "enabled (--share-content)");
        assert!(render_text(&r).contains("enabled (--share-content)"));
        // --share-content alone never produces a `problems` entry (spec
        // conformant, task-20-fix-1.md minor 1). Build the expected
        // problems from exactly the compiled-in feature signals, the same
        // invocation-independent pattern `report_has_every_line_and_no_secrets`
        // above uses, instead of guarding the assertion on those signals:
        // that proves --share-content contributes nothing under either
        // `cargo test -p kiro-trust` or `cargo test --workspace`, rather
        // than skipping the proof under the invocation where it could
        // matter (task-20-fix-2.md Minor 2).
        let mut expected_features = Vec::new();
        if cfg!(feature = "capture") {
            expected_features.push("capture".to_string());
        }
        if kiro_trust_net::TEST_ENDPOINTS_COMPILED {
            expected_features.push("test-endpoints".to_string());
        }
        let expected_problems: Vec<String> = expected_features
            .iter()
            .map(|f| format!("development feature {f} is compiled in"))
            .collect();
        assert_eq!(r.problems, expected_problems);
        assert_eq!(
            exit_code(&r),
            if expected_problems.is_empty() { 0 } else { 1 },
            "{:?}",
            r.problems
        );
    }

    // task-20-fix-1.md minor 7: an invalid --runtime-region must be
    // reported even when the credential itself fails to load, not silently
    // discarded because the validation used to sit inside the `Ok(c)` arm.
    #[test]
    fn an_invalid_runtime_region_is_reported_even_when_the_credential_fails_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent.sqlite3");
        let args = AuditArgs {
            json: false,
            listen: "127.0.0.1:3456".into(),
            kiro_db: Some(missing),
            runtime_region: Some("not-a-region".into()),
            token_file: None,
            share_content: false,
        };
        let r = report(&args).unwrap();
        assert!(
            r.problems.iter().any(|p| p.contains("not-a-region")),
            "{:?}",
            r.problems
        );
        assert!(
            r.problems.iter().any(|p| p.contains("credential")),
            "{:?}",
            r.problems
        );
    }

    // task-20-fix-1.md Critical 2: this must not be `#[cfg(unix)]`-gated,
    // the exact pattern that let the audit's Windows text go unasserted in
    // CI in the first place (`writes_0600_reads_back_and_removes` in
    // `token.rs`). Branching inside one test that always runs proves the
    // text on whichever platform actually executes it.
    #[test]
    fn local_authentication_text_matches_the_platform() {
        let dir = tempfile::tempdir().unwrap();
        let db = synthetic_db(dir.path());
        let args = AuditArgs {
            json: false,
            listen: "127.0.0.1:3456".into(),
            kiro_db: Some(db),
            runtime_region: None,
            token_file: None,
            share_content: false,
        };
        let r = report(&args).unwrap();
        if cfg!(unix) {
            assert_eq!(r.local_authentication, "required (token file 0600)");
        } else {
            assert_eq!(
                r.local_authentication,
                "required (token file, user profile ACL)"
            );
        }
        assert!(render_text(&r).contains(&format!(
            "Local authentication   {}",
            r.local_authentication
        )));
    }

    // task-20-fix-2.md Minor 1, Minor 4: both abbreviation mechanisms
    // tested directly against a synthetic, hardcoded home, never a real one
    // and never read from the environment (CLAUDE.md's rule against a real
    // home path in a test; task-20-fix-2.md Minor 4 against reading a
    // process-wide environment variable in a test at all, since the
    // previous version's `std::env::var("HOME")` diverged from how the
    // code under test derives home on Windows). `abbreviate_home_path_with`
    // backs `credential_source.path`; `abbreviate_home_in_message_with`
    // backs the `problems` entry, where the path sits mid-sentence inside
    // rusqlite's own error text (task-20-fix-1.md Important 1 exercised
    // both call sites; this covers each mechanism directly instead).
    #[test]
    fn abbreviate_home_path_with_covers_home_root_sibling_and_outside_cases() {
        // Under home: the whole remainder becomes a `~`-relative path.
        assert_eq!(
            abbreviate_home_path_with("/home/someone/kiro-cli/data.sqlite3", "/home/someone"),
            "~/kiro-cli/data.sqlite3"
        );
        assert_eq!(
            abbreviate_home_path_with("/home/someone", "/home/someone"),
            "~"
        );
        // A sibling directory that only shares the home as a string prefix
        // is left alone: `Path::strip_prefix` matches whole components.
        assert_eq!(
            abbreviate_home_path_with("/home/x-backup/data.sqlite3", "/home/x"),
            "/home/x-backup/data.sqlite3"
        );
        // `HOME=/` is degenerate: abbreviating would turn every path
        // separator into `~`, so it is a no-op instead.
        assert_eq!(
            abbreviate_home_path_with("/tests/fixtures/db/idc.sqlite3", "/"),
            "/tests/fixtures/db/idc.sqlite3"
        );
        // A relative path outside home is unchanged.
        assert_eq!(
            abbreviate_home_path_with("tests/fixtures/db/idc.sqlite3", "/home/someone"),
            "tests/fixtures/db/idc.sqlite3"
        );
    }

    #[test]
    fn abbreviate_home_in_message_with_covers_home_root_sibling_and_outside_cases() {
        // Under home, mid-sentence: only the path is abbreviated.
        assert_eq!(
            abbreviate_home_in_message_with(
                "credential: cannot open the Kiro CLI database read-only: unable to open \
                 database file: /home/someone/nonexistent.sqlite3",
                "/home/someone"
            ),
            "credential: cannot open the Kiro CLI database read-only: unable to open \
             database file: ~/nonexistent.sqlite3"
        );
        // A sibling directory sharing the home as a string prefix is left
        // literal, not partially abbreviated into `~-backup/...`.
        assert_eq!(
            abbreviate_home_in_message_with(
                "credential: unable to open database file: /home/x-backup/data.sqlite3",
                "/home/x"
            ),
            "credential: unable to open database file: /home/x-backup/data.sqlite3"
        );
        // `HOME=/` is degenerate: a no-op, same as the path-typed version.
        assert_eq!(
            abbreviate_home_in_message_with(
                "credential: unable to open database file: /tests/fixtures/db/idc.sqlite3",
                "/"
            ),
            "credential: unable to open database file: /tests/fixtures/db/idc.sqlite3"
        );
        // A path outside home is unchanged.
        assert_eq!(
            abbreviate_home_in_message_with(
                "credential: unable to open database file: tests/fixtures/db/idc.sqlite3",
                "/home/someone"
            ),
            "credential: unable to open database file: tests/fixtures/db/idc.sqlite3"
        );
    }

    // task-20-fix-1.md Important 2: `KiroDb::open_read_only` is the only
    // constructor and it always yields a genuinely read-only connection
    // (`open_read_only_is_measured_true_via_pragma_readback` in
    // kiro-trust-auth proves that with a real call), so a failing case
    // cannot be constructed without a second, writable constructor, which
    // CLAUDE.md forbids. Assert on a hand-built report instead, pinning the
    // exit-code and rendering contract `report()` wires up when the
    // measured check fails.
    #[test]
    fn a_non_read_only_connection_fails_the_audit() {
        let r = AuditReport {
            credential_source: CredentialSource {
                mode: "NOT read-only (query_only pragma unset)".into(),
                ..Default::default()
            },
            problems: vec![
                "database connection is not read-only: PRAGMA query_only reports false".to_string(),
            ],
            ..Default::default()
        };
        assert_eq!(exit_code(&r), 1);
        let text = render_text(&r);
        assert!(text.contains("mode                 NOT read-only (query_only pragma unset)"));
        assert!(text.contains("database connection is not read-only"));
    }

    // task-20-rulings.md ruling 5: `test-endpoints` lives in kiro-trust-net
    // and `capture` is off in ordinary `cargo test -p kiro-trust`, so
    // neither can be turned on from inside this test. Assert on a
    // hand-built report instead, pinning the exit-code contract that
    // `report()` wires up when either constant is true.
    #[test]
    fn a_compiled_in_development_feature_fails_the_audit() {
        let r = AuditReport {
            build_features: vec!["capture".to_string()],
            problems: vec!["development feature capture is compiled in".to_string()],
            ..Default::default()
        };
        assert_eq!(exit_code(&r), 1);
        let text = render_text(&r);
        assert!(text.contains("Build features         capture"));
        assert!(text.contains("development feature capture is compiled in"));
    }
}
