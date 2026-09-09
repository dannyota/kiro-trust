//! Structured logs to stderr only, allowlisted fields only (spec 6.4).

use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{Directive, LevelFilter};

/// This project's own crates: the only targets `--log-level`/`KIRO_TRUST_LOG`
/// may ever raise above `warn` (spec 6.4).
const OWN_TARGETS: [&str; 4] = [
    "kiro_trust",
    "kiro_trust_auth",
    "kiro_trust_kiro",
    "kiro_trust_net",
];

/// Third-party crates stay at `warn` regardless of the requested level, so
/// `hyper`, `rustls`, and `reqwest` never log request data even at `trace`
/// (spec 6.4).
///
/// `level` reaches here from `--log-level`/`KIRO_TRUST_LOG`. `config.rs`'s
/// clap `value_parser` already restricts both to `error`, `warn`, `info`,
/// `debug`, but this function does not lean on that: it parses `level` into
/// a typed `LevelFilter` itself and only ever builds a directive from that
/// value's fixed `Display` output (always exactly one of `off`, `error`,
/// `warn`, `info`, `debug`, `trace`, with no `,` or `=`) paired with a
/// hardcoded target name from `OWN_TARGETS`. The untrusted string itself is
/// never interpolated into a directive string, so a `,` or `=` inside it can
/// never introduce or widen a directive for `hyper`, `rustls`, `reqwest`, or
/// anything else, even if an invalid level ever reached this function.
pub fn filter(level: &str) -> EnvFilter {
    let Ok(level_filter) = level.parse::<LevelFilter>() else {
        return EnvFilter::new("warn,kiro_trust=info");
    };
    let mut filter = EnvFilter::new("warn");
    for target in OWN_TARGETS {
        let directive: Directive = format!("{target}={level_filter}").parse().expect(
            "a hardcoded target plus LevelFilter::Display is always valid directive syntax",
        );
        filter = filter.add_directive(directive);
    }
    filter
}

pub fn init(level: &str) -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(filter(level))
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec 6.4: hyper, rustls, and reqwest stay at warn at every level the
    // CLI accepts, including trace, so third-party crates never log
    // request data.
    #[test]
    fn third_party_crates_stay_at_warn_at_every_level() {
        for level in ["error", "warn", "info", "debug", "trace"] {
            let f = filter(level).to_string();
            // `EnvFilter::to_string()` does not preserve input order, so
            // check for a bare `warn` directive (the default level applied
            // to every target with no directive of its own) rather than
            // assuming it comes first.
            assert!(
                f.split(',').any(|d| d == "warn"),
                "{level}: no bare default-level warn directive in {f}"
            );
            for noisy in ["hyper", "rustls", "reqwest"] {
                assert!(
                    !f.contains(&format!("{noisy}=")),
                    "{level} filter narrows {noisy}: {f}"
                );
            }
        }
    }

    // Important 1: a directive-list injection through an untrusted level
    // string must never widen a third-party target. This is the exact
    // string from the finding: `EnvFilter` splits on `,` before parsing each
    // comma-separated piece as its own directive, so a naive
    // `format!("...{level}...")` builder would let this string add a
    // `hyper=trace` directive.
    #[test]
    fn a_directive_list_in_the_level_string_cannot_inject_a_third_party_directive() {
        let f = filter("info,hyper=trace").to_string();
        assert!(
            !f.contains("hyper"),
            "the injected level string produced a hyper directive: {f}"
        );
        // The whole string fails `LevelFilter::from_str`, so this is the
        // documented fallback, not a partial parse of "info". (`EnvFilter`'s
        // `to_string()` does not preserve input order, so compare the parsed
        // directive set, not a literal string.)
        assert_eq!(f, "kiro_trust=info,warn");
    }

    #[test]
    fn an_unparseable_level_falls_back_to_the_documented_default() {
        assert_eq!(filter("bogus").to_string(), "kiro_trust=info,warn");
    }

    #[test]
    fn each_accepted_level_raises_only_this_projects_own_crates() {
        for level in ["error", "warn", "info", "debug"] {
            let f = filter(level).to_string();
            for target in OWN_TARGETS {
                assert!(
                    f.contains(&format!("{target}={level}")),
                    "{level}: missing a {target}={level} directive in {f}"
                );
            }
            assert!(
                f.split(',').any(|d| d == "warn"),
                "{level}: no bare default-level warn directive in {f}"
            );
            for noisy in ["hyper", "rustls", "reqwest"] {
                assert!(
                    !f.contains(&format!("{noisy}=")),
                    "{level} filter narrows {noisy}: {f}"
                );
            }
            // Exactly OWN_TARGETS.len() targeted directives plus the bare
            // default: nothing else above warn.
            assert_eq!(
                f.split(',').count(),
                OWN_TARGETS.len() + 1,
                "{level}: unexpected extra directive in {f}"
            );
        }
    }
}
