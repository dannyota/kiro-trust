#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("cannot open the Kiro CLI database read-only: {0}")]
    Open(String),
    #[error("database query failed: {0}")]
    Query(String),
    #[error("no Kiro CLI credentials found; run `kiro-cli login` with IAM Identity Center")]
    NoCredentials,
    #[error("{0} is not supported by kiro-trust v0.1; only IAM Identity Center logins are")]
    Unsupported(&'static str),
    #[error("the token record is not valid JSON")]
    BadTokenJson,
    #[error("the device registration record is missing or incomplete (clientId/clientSecret)")]
    MissingDeviceRegistration,
    #[error("no SSO region is stored for this credential; check the Kiro CLI login")]
    NoSsoRegion,
    #[error(
        "no allowed runtime region could be derived from the credential; pass --runtime-region (spec 7.2)"
    )]
    NoRuntimeRegion,
    #[error("region rejected: {0}")]
    Region(#[from] kiro_trust_net::RegionError),
    /// Failed before any response status arrived: connect, TLS, DNS, send,
    /// or the 30s cap firing while still waiting (spec 3.3 rule 3). Treated
    /// as not-exchanged and never burns the seed. That is a deliberate
    /// trade, not a proof: a request Identity Center answered slowly looks
    /// identical, and treating it as spent would strand a long-lived proxy
    /// on an ordinary network blip.
    #[error("token refresh failed: {0}")]
    Refresh(String),
    /// Any non-200 status (spec 3.3 rule 3). Treated as not-exchanged and
    /// never burns the seed — the same deliberate trade as `Refresh`'s
    /// timeout case: a 502 from an intermediary that had already relayed
    /// the exchange looks identical to one that never reached it.
    #[error("token refresh rejected with HTTP {status}")]
    RefreshRejected { status: u16 },
    /// A network error before any response status arrived. Same deliberate
    /// trade as `Refresh`'s timeout case.
    #[error("token refresh network error: {0}")]
    Net(#[from] kiro_trust_net::NetError),
    /// A 200 arrived but no usable credential came out of it: an unparsable
    /// body, an empty `accessToken`, an `expiresIn` outside the guard, a
    /// body that failed to read, or the 30s cap firing after the response
    /// status arrived (spec 3.3 rule 3). This is the error that accompanies
    /// a burn, not what causes one: `try_refresh`'s `BurnGuard` burns on the
    /// `past_200` flag `refresh()` sets, and every path that can produce
    /// this variant happens to run only after that flag is already set.
    #[error("token refresh response was incomplete: {0}")]
    RefreshIncomplete(String),
    /// Rule 3 (spec 3.3): a refresh failed and no newer Kiro CLI credential
    /// was found to retry with, so nothing left to try but a fresh login.
    #[error("{0}; log in to Kiro CLI again")]
    ReauthRequired(String),
}
