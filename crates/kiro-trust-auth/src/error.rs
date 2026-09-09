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
    #[error("token refresh failed: {0}")]
    Refresh(String),
    #[error("token refresh rejected with HTTP {status}")]
    RefreshRejected { status: u16 },
    #[error("token refresh network error: {0}")]
    Net(#[from] kiro_trust_net::NetError),
}
