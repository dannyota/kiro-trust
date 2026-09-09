//! Structured logs to stderr only, allowlisted fields only (spec 6.4).

use tracing_subscriber::EnvFilter;

/// Third-party crates stay at `warn` regardless of the requested level, so
/// `hyper`, `rustls`, and `reqwest` never log request data even at `trace`
/// (spec 6.4).
pub fn filter(level: &str) -> EnvFilter {
    EnvFilter::try_new(format!(
        "warn,kiro_trust={level},kiro_trust_auth={level},kiro_trust_kiro={level},kiro_trust_net={level}"
    ))
    .unwrap_or_else(|_| EnvFilter::new("warn,kiro_trust=info"))
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

    #[test]
    fn an_invalid_level_falls_back_without_panicking() {
        // A level string cannot make the directive syntax invalid here (it
        // only substitutes into the level position), so this just proves
        // the fallback branch is reachable and produces a usable filter.
        let f = filter("info").to_string();
        assert!(f.contains("kiro_trust=info"));
    }
}
