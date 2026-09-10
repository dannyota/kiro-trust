//! AWS IAM Identity Center OIDC refresh (spec 7.3). The only place besides
//! `TokenSource::with_token` that exposes a secret.

use crate::db::Credentials;
use crate::error::AuthError;
use http::{HeaderMap, HeaderValue, header};
use kiro_trust_net::{Client, Destination};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);
/// Identity Center issues one-hour tokens; anything larger indicates a
/// malformed response rather than a legitimate long-lived token.
const MAX_EXPIRES_IN_SECS: i64 = 31_536_000;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: i64,
}

/// `past_200` is set the instant a 200 status is confirmed, before any body
/// is read (spec 3.3 rule 3's cancellation paragraph). `try_refresh` reads
/// it from a drop guard, so a cancelled call — the future dropped without
/// this function ever returning — still leaves an accurate record of which
/// side of the response status it reached, exactly like a normal return.
pub(crate) async fn refresh(
    net: &Client,
    creds: &Credentials,
    past_200: &AtomicBool,
) -> Result<Credentials, AuthError> {
    let body = serde_json::json!({
        "grantType": "refresh_token",
        "clientId": creds.client_id,
        "clientSecret": creds.client_secret.expose_secret(),
        "refreshToken": creds.refresh_token.expose_secret(),
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let dest = Destination::Oidc {
        sso_region: creds.sso_region.clone(),
    };
    let body_bytes = serde_json::to_vec(&body).unwrap();
    // One 30s deadline for the whole exchange (spec 7.3), split across two
    // `timeout_at` calls sharing it rather than one `timeout` wrapping both:
    // which side of the response status a failure landed on must be
    // structural, not inferred, since rule 3 (spec 3.3) burns the seed only
    // for a failure after a 200 status arrived, never before.
    let deadline = tokio::time::Instant::now() + REFRESH_TIMEOUT;
    let resp = tokio::time::timeout_at(deadline, net.post(&dest, "/token", headers, body_bytes))
        .await
        .map_err(|_| AuthError::Refresh("timed out".into()))??;
    if resp.status != 200 {
        return Err(AuthError::RefreshRejected {
            status: resp.status,
        });
    }
    // From here on the OIDC endpoint has committed: every path below either
    // succeeds or is a spent seed, never a not-exchanged one.
    past_200.store(true, Ordering::SeqCst);
    let bytes = match tokio::time::timeout_at(deadline, resp.bytes_limited()).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => return Err(AuthError::RefreshIncomplete(e.to_string())),
        Err(_) => return Err(AuthError::RefreshIncomplete("timed out".into())),
    };
    let parsed: TokenResponse = serde_json::from_slice(&bytes)
        .map_err(|_| AuthError::RefreshIncomplete("response was not the expected JSON".into()))?;
    if parsed.access_token.is_empty() {
        return Err(AuthError::RefreshIncomplete("empty accessToken".into()));
    }
    if parsed.expires_in <= 0 || parsed.expires_in > MAX_EXPIRES_IN_SECS {
        return Err(AuthError::RefreshIncomplete(format!(
            "invalid expiresIn {}",
            parsed.expires_in
        )));
    }
    let expires_at = SystemTime::now()
        .checked_add(Duration::from_secs(parsed.expires_in as u64))
        .ok_or_else(|| AuthError::RefreshIncomplete("expiresIn out of range".into()))?;
    Ok(Credentials {
        access_token: SecretString::from(parsed.access_token),
        refresh_token: parsed
            .refresh_token
            .filter(|s| !s.is_empty())
            .map(SecretString::from)
            .unwrap_or_else(|| creds.refresh_token.clone()),
        client_id: creds.client_id.clone(),
        client_secret: creds.client_secret.clone(),
        expires_at,
        sso_region: creds.sso_region.clone(),
        runtime_region: creds.runtime_region.clone(),
        profile_arn: creds.profile_arn.clone(),
    })
}
