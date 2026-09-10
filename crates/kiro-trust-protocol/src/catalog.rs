//! Static Claude model catalog (spec 5.2). Transcribed from kirocc v0.11.1
//! `internal/models/models.go` and `effort.go`; see NOTICE. New models arrive
//! through a release, never through discovery.

pub const DEFAULT_CONTEXT: u32 = 200_000;
pub const ONE_M_CONTEXT: u32 = 1_000_000;
const SUFFIX: &str = "[1m]";

const FULL: &[&str] = &["low", "medium", "high", "xhigh", "max"];
const STANDARD: &[&str] = &["low", "medium", "high", "max"];
const NONE: &[&str] = &[];
const RANKED: &[&str] = &["low", "medium", "high", "xhigh", "max"];

struct Row {
    /// Canonical Anthropic id, dashed minor version.
    anthropic: &'static str,
    kiro: &'static str,
    /// Separate 1M SKU, or `None` when `always_1m`.
    kiro_1m: Option<&'static str>,
    always_1m: bool,
    display: &'static str,
    effort: &'static [&'static str],
}

static ROWS: &[Row] = &[
    Row {
        anthropic: "claude-opus-5",
        kiro: "claude-opus-5",
        kiro_1m: None,
        always_1m: true,
        display: "Opus 5",
        effort: FULL,
    },
    Row {
        anthropic: "claude-opus-4-8",
        kiro: "claude-opus-4.8",
        kiro_1m: None,
        always_1m: true,
        display: "Opus 4.8",
        effort: FULL,
    },
    Row {
        anthropic: "claude-opus-4-7",
        kiro: "claude-opus-4.7",
        kiro_1m: None,
        always_1m: true,
        display: "Opus 4.7",
        effort: FULL,
    },
    Row {
        anthropic: "claude-opus-4-6",
        kiro: "claude-opus-4.6",
        kiro_1m: None,
        always_1m: true,
        display: "Opus 4.6",
        effort: STANDARD,
    },
    Row {
        anthropic: "claude-sonnet-5",
        kiro: "claude-sonnet-5",
        kiro_1m: None,
        always_1m: true,
        display: "Sonnet 5",
        effort: FULL,
    },
    Row {
        anthropic: "claude-sonnet-4-6",
        kiro: "claude-sonnet-4.6",
        kiro_1m: Some("claude-sonnet-4.6-1m"),
        always_1m: false,
        display: "Sonnet 4.6",
        effort: STANDARD,
    },
    Row {
        anthropic: "claude-sonnet-4-5",
        kiro: "claude-sonnet-4.5",
        kiro_1m: Some("claude-sonnet-4.5-1m"),
        always_1m: false,
        display: "Sonnet 4.5",
        effort: NONE,
    },
    Row {
        anthropic: "claude-opus-4-5",
        kiro: "claude-opus-4.5",
        kiro_1m: None,
        always_1m: false,
        display: "Opus 4.5",
        effort: NONE,
    },
    Row {
        anthropic: "claude-haiku-4-5",
        kiro: "claude-haiku-4.5",
        kiro_1m: None,
        always_1m: false,
        display: "Haiku 4.5",
        effort: NONE,
    },
];

/// A bounded catalog row and context tier. Only this module can construct it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ModelKey {
    row: u8,
    context_1m: bool,
}

impl ModelKey {
    fn new(row: usize, context_1m: bool) -> Self {
        Self {
            row: row.try_into().expect("catalog has at most 256 rows"),
            context_1m,
        }
    }

    /// The stable, contiguous slot for this routable row and context tier.
    pub fn catalog_index(self) -> usize {
        ROWS[..usize::from(self.row)]
            .iter()
            .map(|row| {
                if row.always_1m || row.kiro_1m.is_none() {
                    1
                } else {
                    2
                }
            })
            .sum::<usize>()
            + usize::from(self.context_1m && !ROWS[usize::from(self.row)].always_1m)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ModelInfo {
    #[serde(skip)]
    pub key: ModelKey,
    pub id: String,
    pub display_name: String,
    pub kiro_model: String,
    pub aliases: Vec<String>,
    pub accepts_date_suffix: bool,
    pub context_window: u32,
    pub effort_levels: Vec<String>,
    pub proxy_input_types: Vec<String>,
    pub history_images_forwarded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub key: ModelKey,
    /// The SKU sent upstream; never carries `[1m]`.
    pub kiro_model: String,
    /// Echoed in responses; carries `[1m]` when the window is 1M.
    pub anthropic_model: String,
    pub context_window: u32,
    /// `[1m]` on a separate-SKU model enables thinking (kirocc tier 2).
    pub thinking: bool,
    pub effort_levels: &'static [&'static str],
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("model {0} is not in the kiro-trust catalog")]
pub struct UnknownModel(pub String);

/// Strip a trailing `-YYYYMMDD` date.
fn strip_date(s: &str) -> &str {
    if let Some((base, tail)) = s.rsplit_once('-')
        && tail.len() == 8
        && tail.bytes().all(|b| b.is_ascii_digit())
    {
        return base;
    }
    s
}

/// `claude-opus-4-8` → `claude-opus-4.8`; leaves dotted and single-digit ids alone.
fn canonical_sku(s: &str) -> String {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() >= 3 {
        let (major, minor) = (parts[parts.len() - 2], parts[parts.len() - 1]);
        if major.bytes().all(|b| b.is_ascii_digit()) && minor.bytes().all(|b| b.is_ascii_digit()) {
            return format!("{}-{major}.{minor}", parts[..parts.len() - 2].join("-"));
        }
    }
    s.to_string()
}

fn find_row(sku: &str) -> Option<(usize, &'static Row, bool)> {
    ROWS.iter().enumerate().find_map(|(index, r)| {
        if r.kiro == sku {
            Some((index, r, false))
        } else if r.kiro_1m == Some(sku) {
            Some((index, r, true))
        } else {
            None
        }
    })
}

pub fn resolve(model: &str, context_1m_beta: bool) -> Result<Resolved, UnknownModel> {
    let trimmed = model.trim();
    let lower_suffix = trimmed.to_ascii_lowercase();
    let (base, has_suffix) = if lower_suffix.ends_with(SUFFIX) {
        (&trimmed[..trimmed.len() - SUFFIX.len()], true)
    } else {
        (trimmed, false)
    };
    let sku = canonical_sku(strip_date(base));
    let (row_index, row, input_was_1m_sku) =
        find_row(&sku).ok_or_else(|| UnknownModel(model.to_string()))?;

    let thinking = has_suffix && !row.always_1m && row.kiro_1m.is_some();
    let want_1m = context_1m_beta || has_suffix || input_was_1m_sku;
    let (kiro_model, context_window) = if row.always_1m {
        (row.kiro, ONE_M_CONTEXT)
    } else if want_1m && let Some(one_m) = row.kiro_1m {
        (one_m, ONE_M_CONTEXT)
    } else {
        (row.kiro, DEFAULT_CONTEXT)
    };
    let mut anthropic_model = row.anthropic.to_string();
    if context_window == ONE_M_CONTEXT {
        anthropic_model.push_str(SUFFIX);
    }
    Ok(Resolved {
        key: ModelKey::new(row_index, context_window == ONE_M_CONTEXT),
        kiro_model: kiro_model.to_string(),
        anthropic_model,
        context_window,
        thinking,
        effort_levels: row.effort,
    })
}

fn add_alias(aliases: &mut Vec<String>, alias: String) {
    if !aliases.contains(&alias) {
        aliases.push(alias);
    }
}

fn model_info(row_index: usize, row: &Row, context_1m: bool) -> ModelInfo {
    let kiro_model = if context_1m && !row.always_1m {
        row.kiro_1m.unwrap_or(row.kiro)
    } else {
        row.kiro
    };
    let mut id = row.anthropic.to_string();
    if context_1m {
        id.push_str(SUFFIX);
    }
    let mut aliases = Vec::new();
    let dotted = canonical_sku(row.anthropic);
    if context_1m {
        add_alias(&mut aliases, id.clone());
        add_alias(&mut aliases, format!("{dotted}{SUFFIX}"));
        add_alias(&mut aliases, kiro_model.to_string());
        if row.always_1m {
            add_alias(&mut aliases, row.anthropic.to_string());
            add_alias(&mut aliases, dotted);
        }
    } else {
        add_alias(&mut aliases, id.clone());
        add_alias(&mut aliases, dotted);
        add_alias(&mut aliases, kiro_model.to_string());
    }
    ModelInfo {
        key: ModelKey::new(row_index, context_1m),
        id,
        display_name: if context_1m {
            format!("{} (1M context)", row.display)
        } else {
            row.display.to_string()
        },
        kiro_model: kiro_model.to_string(),
        aliases,
        accepts_date_suffix: true,
        context_window: if context_1m {
            ONE_M_CONTEXT
        } else {
            DEFAULT_CONTEXT
        },
        effort_levels: row
            .effort
            .iter()
            .map(|level| (*level).to_string())
            .collect(),
        proxy_input_types: vec!["text".to_string(), "image".to_string()],
        history_images_forwarded: false,
    }
}

/// Metadata for every routable catalog row and context tier, in catalog order.
pub fn models() -> Vec<ModelInfo> {
    let mut out = Vec::new();
    for (index, row) in ROWS.iter().enumerate() {
        if row.always_1m {
            out.push(model_info(index, row, true));
        } else {
            out.push(model_info(index, row, false));
            if row.kiro_1m.is_some() {
                out.push(model_info(index, row, true));
            }
        }
    }
    out
}

/// Resolve an accepted catalog alias to the metadata for its routed tier.
pub fn model(model: &str) -> Result<ModelInfo, UnknownModel> {
    let resolved = resolve(model, false)?;
    models()
        .into_iter()
        .find(|info| info.key == resolved.key)
        .ok_or_else(|| UnknownModel(model.to_string()))
}

/// True only for exact compiled Kiro SKU values.
pub fn supports_kiro_model(model_id: &str) -> bool {
    ROWS.iter()
        .any(|row| row.kiro == model_id || row.kiro_1m == Some(model_id))
}

/// kirocc `resolveEffort` for Claude models: an explicit recognized level
/// wins (clamped to the model's top tier); thinking without a level gives
/// `medium`; anything else omits the field.
pub fn resolve_effort(model: &Resolved, requested: Option<&str>, thinking: bool) -> Option<String> {
    let levels = model.effort_levels;
    if levels.is_empty() {
        return None;
    }
    match requested {
        Some(req) if levels.contains(&req) => Some(req.to_string()),
        Some(req) if RANKED.contains(&req) => Some(levels[levels.len() - 1].to_string()),
        Some(_) => None,
        None if thinking => Some("medium".to_string()),
        None => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelListing {
    pub id: String,
    pub display_name: Option<String>,
}

/// kirocc `ListModels`: every row's Anthropic id (with `[1m]` on always-1M
/// rows), a `[1m]` alias for rows with a separate 1M SKU, and the Kiro SKUs.
pub fn list_models() -> Vec<ModelListing> {
    let mut out: Vec<ModelListing> = Vec::new();
    let mut add = |id: String, display: Option<String>| {
        if !out.iter().any(|m| m.id == id) {
            out.push(ModelListing {
                id,
                display_name: display,
            });
        }
    };
    for r in ROWS {
        if r.always_1m {
            add(
                format!("{}{SUFFIX}", r.anthropic),
                Some(format!("{} (1M context)", r.display)),
            );
            add(r.anthropic.to_string(), None);
        } else {
            add(r.anthropic.to_string(), Some(r.display.to_string()));
            if r.kiro_1m.is_some() {
                add(
                    format!("{}{SUFFIX}", r.anthropic),
                    Some(format!("{} (1M context)", r.display)),
                );
            }
        }
        add(r.kiro.to_string(), None);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Transcribed from kirocc models_test.go TestResolve (Claude rows only).
    #[test]
    fn resolves_aliases_dates_and_suffixes() {
        let r = resolve("claude-sonnet-4-6", false).unwrap();
        assert_eq!(r.kiro_model, "claude-sonnet-4.6");
        assert_eq!(r.anthropic_model, "claude-sonnet-4-6");
        assert_eq!(r.context_window, DEFAULT_CONTEXT);
        assert!(!r.thinking);

        let r = resolve("claude-sonnet-4-6[1m]", false).unwrap();
        assert_eq!(r.kiro_model, "claude-sonnet-4.6-1m");
        assert_eq!(r.anthropic_model, "claude-sonnet-4-6[1m]");
        assert_eq!(r.context_window, ONE_M_CONTEXT);
        assert!(r.thinking, "[1m] on a separate-SKU model enables thinking");

        let r = resolve("claude-sonnet-4-6[1M]", false).unwrap();
        assert_eq!(r.kiro_model, "claude-sonnet-4.6-1m");

        let r = resolve("claude-sonnet-4-6", true).unwrap();
        assert_eq!(
            r.kiro_model, "claude-sonnet-4.6-1m",
            "context-1m beta routes to the 1M SKU"
        );
        assert!(!r.thinking, "the beta header never enables thinking");

        let r = resolve("claude-opus-4-7[1m]", false).unwrap();
        assert_eq!(r.kiro_model, "claude-opus-4.7");
        assert!(!r.thinking, "[1m] on an always-1M model is only an alias");
        assert_eq!(r.context_window, ONE_M_CONTEXT);
        assert_eq!(r.anthropic_model, "claude-opus-4-7[1m]");

        let r = resolve("claude-opus-4-7", false).unwrap();
        assert_eq!(r.context_window, ONE_M_CONTEXT);
        assert_eq!(
            r.anthropic_model, "claude-opus-4-7[1m]",
            "always-1M rows advertise 1M"
        );

        let r = resolve("claude-sonnet-4-5-20250929", false).unwrap();
        assert_eq!(r.kiro_model, "claude-sonnet-4.5");
        let r = resolve("claude-sonnet-4.5", false).unwrap();
        assert_eq!(r.kiro_model, "claude-sonnet-4.5");
        let r = resolve("claude-haiku-4-5", false).unwrap();
        assert_eq!(r.kiro_model, "claude-haiku-4.5");
        let r = resolve("claude-sonnet-4.6-1m", false).unwrap();
        assert_eq!(
            r.kiro_model, "claude-sonnet-4.6-1m",
            "a Kiro SKU is accepted as input"
        );
    }

    #[test]
    fn unknown_models_are_rejected_not_defaulted() {
        assert!(resolve("gpt-5.6-sol", false).is_err());
        assert!(resolve("claude-nonexistent-9", false).is_err());
        assert!(resolve("", false).is_err());
    }

    // Transcribed from kirocc effort_test.go TestResolveEffort and
    // app/messages/effort_test.go.
    #[test]
    fn effort_resolution_follows_model_enum() {
        let r = resolve("claude-sonnet-4-6", false).unwrap();
        assert_eq!(
            resolve_effort(&r, Some("high"), false).as_deref(),
            Some("high")
        );
        assert_eq!(
            resolve_effort(&r, Some("xhigh"), false).as_deref(),
            Some("max"),
            "clamps to top tier"
        );
        assert_eq!(
            resolve_effort(&r, Some("enabled"), true),
            None,
            "unrecognized value is dropped, no fallback"
        );
        assert_eq!(
            resolve_effort(&r, None, true).as_deref(),
            Some("medium"),
            "thinking without effort defaults to medium"
        );
        assert_eq!(resolve_effort(&r, None, false), None);

        let r = resolve("claude-opus-5", false).unwrap();
        assert_eq!(
            resolve_effort(&r, Some("xhigh"), false).as_deref(),
            Some("xhigh")
        );

        let r = resolve("claude-haiku-4-5", false).unwrap();
        assert_eq!(
            resolve_effort(&r, Some("high"), true),
            None,
            "no effort capability"
        );
        assert_eq!(resolve_effort(&r, None, true), None);
    }

    #[test]
    fn model_list_advertises_every_row_and_separate_1m_aliases() {
        let list = list_models();
        let ids: Vec<&str> = list.iter().map(|m| m.id.as_str()).collect();
        assert!(ids.contains(&"claude-sonnet-4-6"));
        assert!(ids.contains(&"claude-sonnet-4-6[1m]"));
        assert!(ids.contains(&"claude-opus-5[1m]"));
        assert!(
            ids.contains(&"claude-sonnet-4.6"),
            "Kiro SKUs are listed too"
        );
        assert!(!ids.contains(&"claude-opus-5[1m][1m]"));
        let sonnet_1m = list
            .iter()
            .find(|m| m.id == "claude-sonnet-4-6[1m]")
            .unwrap();
        assert_eq!(
            sonnet_1m.display_name.as_deref(),
            Some("Sonnet 4.6 (1M context)")
        );
        assert_eq!(
            ids.iter().filter(|i| **i == "claude-sonnet-4.6").count(),
            1,
            "no duplicates"
        );
    }

    #[test]
    fn model_info_and_resolution_share_a_bounded_key() {
        let info = model("claude-sonnet-4-6[1m]").unwrap();
        let resolved = resolve("claude-sonnet-4-6[1m]", false).unwrap();
        assert_eq!(info.key, resolved.key);
        assert_eq!(info.context_window, 1_000_000);
        assert_eq!(info.proxy_input_types, ["text", "image"]);
        assert!(!info.history_images_forwarded);
    }

    #[test]
    fn generated_aliases_resolve_to_the_same_row() {
        let info = model("claude-sonnet-4-6").unwrap();
        for alias in &info.aliases {
            assert_eq!(model(alias).unwrap().key, info.key, "{alias}");
        }
    }

    #[test]
    fn model_keys_index_each_routable_tier_contiguously() {
        for (index, info) in models().iter().enumerate() {
            assert_eq!(info.key.catalog_index(), index, "{}", info.id);
        }
    }

    #[test]
    fn only_compiled_kiro_skus_are_supported() {
        assert!(supports_kiro_model("claude-sonnet-4.6"));
        assert!(supports_kiro_model("claude-sonnet-4.6-1m"));
        assert!(!supports_kiro_model("claude-sonnet-4-6"));
        assert!(!supports_kiro_model("not-a-model"));
    }
}
