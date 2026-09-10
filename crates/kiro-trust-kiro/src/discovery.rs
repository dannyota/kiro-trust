//! Bounded, operator-invoked model availability discovery (spec 3.3-3.5).

use kiro_trust_auth::TokenSource;
use kiro_trust_net::{Client, Destination, DiscoveryRegion, ModelDiscoveryQuery, SensitiveBearer};
use kiro_trust_protocol::catalog;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

const MAX_PAGES: usize = 16;
const MAX_MODELS: usize = 512;
const MAX_ID_BYTES: usize = 256;
const MAX_TOKEN_BYTES: usize = 4096;
const DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogStatus {
    Supported,
    NotListed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryInputType {
    Text,
    Image,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DiscoveredModel {
    pub id: String,
    pub available: bool,
    pub catalog_status: CatalogStatus,
    pub input_types: Vec<DiscoveryInputType>,
    pub max_input_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub supports_prompt_cache: Option<bool>,
    pub rate_multiplier: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct DiscoveryReport {
    pub object: &'static str,
    pub region: String,
    pub default_model: String,
    pub models: Vec<DiscoveredModel>,
    #[serde(skip)]
    pub page_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryError {
    #[error("authentication failed")]
    Authentication,
    #[error("access denied")]
    AccessDenied,
    #[error("catalog region is unverified; source-verified regions: us-east-1, eu-central-1")]
    RegionUnverified,
    #[error("transport failed")]
    Transport,
    #[error("catalog response violated the protocol")]
    Protocol,
    #[error("catalog operation exceeded a fixed limit")]
    LimitExceeded,
}

pub struct DiscoveryClient {
    net: Arc<Client>,
    tokens: Arc<TokenSource>,
}

impl DiscoveryClient {
    pub fn new(net: Arc<Client>, tokens: Arc<TokenSource>) -> Self {
        Self { net, tokens }
    }

    pub async fn discover(&self) -> Result<DiscoveryReport, DiscoveryError> {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        tokio::time::timeout_at(deadline, self.discover_before(deadline))
            .await
            .map_err(|_| DiscoveryError::LimitExceeded)?
    }

    async fn discover_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<DiscoveryReport, DiscoveryError> {
        let identity = self
            .tokens
            .identity()
            .await
            .map_err(|_| DiscoveryError::Authentication)?;
        let region = identity
            .profile_region
            .ok_or(DiscoveryError::RegionUnverified)
            .and_then(|region| {
                DiscoveryRegion::parse(region.as_str())
                    .map_err(|_| DiscoveryError::RegionUnverified)
            })?;
        let destination = Destination::ModelCatalog {
            region: region.clone(),
        };
        let mut models = BTreeMap::new();
        let mut seen_tokens = HashSet::new();
        let mut next_token = None;
        let mut default = None;
        let mut page_count = 0;

        for page in 0..MAX_PAGES {
            page_count = page + 1;
            let bearer = self
                .tokens
                .with_token(|token| SensitiveBearer::new(token))
                .await
                .map_err(|_| DiscoveryError::Authentication)?
                .map_err(|_| DiscoveryError::Authentication)?;
            let response = self
                .net
                .post_model_discovery(
                    &destination,
                    ModelDiscoveryQuery {
                        profile_arn: &identity.profile_arn,
                        next_token: next_token.as_deref(),
                    },
                    bearer,
                )
                .await
                .map_err(|_| DiscoveryError::Transport)?;

            let bytes = match response.status {
                200 => response
                    .model_catalog_bytes()
                    .await
                    .map_err(|error| match error {
                        kiro_trust_net::NetError::ModelCatalogBodyLimit => {
                            DiscoveryError::LimitExceeded
                        }
                        _ => DiscoveryError::Transport,
                    })?,
                401 => return Err(DiscoveryError::Authentication),
                403 => return Err(DiscoveryError::AccessDenied),
                _ => return Err(DiscoveryError::Transport),
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(DiscoveryError::LimitExceeded);
            }
            let parsed: Page =
                serde_json::from_slice(&bytes).map_err(|_| DiscoveryError::Protocol)?;
            let page_default = parsed
                .default_model
                .ok_or(DiscoveryError::Protocol)
                .and_then(|model| validate_id(&model.model_id).map(|_| model.model_id))?;
            match &default {
                Some(value) if value != &page_default => return Err(DiscoveryError::Protocol),
                None => default = Some(page_default),
                _ => {}
            }
            for raw in parsed.models.unwrap_or_default() {
                let model = normalize_model(raw)?;
                if let Some(previous) = models.get(&model.id) {
                    if previous != &model {
                        return Err(DiscoveryError::Protocol);
                    }
                } else {
                    if models.len() == MAX_MODELS {
                        return Err(DiscoveryError::LimitExceeded);
                    }
                    models.insert(model.id.clone(), model);
                }
            }
            match parsed.next_token {
                None => break,
                Some(token) => {
                    if token.len() > MAX_TOKEN_BYTES {
                        return Err(DiscoveryError::LimitExceeded);
                    }
                    if !seen_tokens.insert(token.clone()) {
                        return Err(DiscoveryError::Protocol);
                    }
                    if page + 1 == MAX_PAGES {
                        return Err(DiscoveryError::LimitExceeded);
                    }
                    next_token = Some(token);
                }
            }
        }
        let default_model = default.ok_or(DiscoveryError::Protocol)?;
        if !models.contains_key(&default_model) {
            return Err(DiscoveryError::Protocol);
        }
        Ok(DiscoveryReport {
            object: "discovered_models",
            region: region.to_string(),
            default_model,
            models: models.into_values().collect(),
            page_count,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Page {
    #[serde(default)]
    models: Option<Vec<RawModel>>,
    default_model: Option<RawDefault>,
    next_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDefault {
    model_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawModel {
    model_id: String,
    #[serde(default)]
    rate_multiplier: Option<f64>,
    #[serde(default)]
    token_limits: Option<RawTokenLimits>,
    #[serde(default)]
    supported_input_types: Option<Vec<String>>,
    #[serde(default)]
    supports_prompt_cache: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawTokenLimits {
    #[serde(default)]
    max_input_tokens: Option<serde_json::Value>,
    #[serde(default)]
    max_output_tokens: Option<serde_json::Value>,
}

fn normalize_model(raw: RawModel) -> Result<DiscoveredModel, DiscoveryError> {
    validate_id(&raw.model_id)?;
    let rate_multiplier = match raw.rate_multiplier {
        Some(value) if value.is_finite() && value >= 0.0 => Some(value),
        Some(_) => return Err(DiscoveryError::Protocol),
        None => None,
    };
    let (max_input_tokens, max_output_tokens) = match raw.token_limits {
        Some(limits) => (
            parse_limit(limits.max_input_tokens)?,
            parse_limit(limits.max_output_tokens)?,
        ),
        None => (None, None),
    };
    let mut input_types = Vec::new();
    for input in raw.supported_input_types.unwrap_or_default() {
        let input = match input.as_str() {
            "TEXT" => DiscoveryInputType::Text,
            "IMAGE" => DiscoveryInputType::Image,
            _ => DiscoveryInputType::Unknown,
        };
        if !input_types.contains(&input) {
            input_types.push(input);
        }
    }
    input_types.sort_by_key(|input| match input {
        DiscoveryInputType::Text => 0,
        DiscoveryInputType::Image => 1,
        DiscoveryInputType::Unknown => 2,
    });
    Ok(DiscoveredModel {
        catalog_status: if catalog::supports_kiro_model(&raw.model_id) {
            CatalogStatus::Supported
        } else {
            CatalogStatus::NotListed
        },
        id: raw.model_id,
        available: true,
        input_types,
        max_input_tokens,
        max_output_tokens,
        supports_prompt_cache: raw.supports_prompt_cache,
        rate_multiplier,
    })
}

fn parse_limit(value: Option<serde_json::Value>) -> Result<Option<u32>, DiscoveryError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.as_u64().ok_or(DiscoveryError::Protocol)?;
    if value == 0 || value > u64::from(u32::MAX) {
        return Err(DiscoveryError::Protocol);
    }
    Ok(Some(value as u32))
}

fn validate_id(id: &str) -> Result<(), DiscoveryError> {
    if id.len() > MAX_ID_BYTES {
        return Err(DiscoveryError::LimitExceeded);
    }
    if id.is_empty()
        || id.chars().any(char::is_control)
        || id.contains('\u{1b}')
        || id.to_ascii_lowercase().contains("arn:")
        || id.starts_with("aoa")
        || id.starts_with("eyJ")
    {
        return Err(DiscoveryError::Protocol);
    }
    let digits = id.as_bytes();
    if digits
        .windows(12)
        .any(|window| window.iter().all(u8::is_ascii_digit))
    {
        return Err(DiscoveryError::Protocol);
    }
    Ok(())
}
