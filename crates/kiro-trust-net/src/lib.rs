//! The single outbound network policy for kiro-trust (spec 3.2). Nothing
//! else in the workspace may depend on reqwest.

mod client;
mod destination;
mod policy;
mod region;

pub use client::{
    Client, HTTP_PROXY, NetError, REDIRECTS, Response, TLS_ROOTS, probe_loopback_health,
};
pub use destination::Destination;
pub use policy::{ExtraCa, Policy};
pub use region::{RUNTIME_ALLOWLIST, Region, RegionError, RuntimeRegion};

/// Whether this crate itself was built with `test-endpoints` (spec 8.4;
/// task-20-rulings.md ruling 5). Evaluated here, in this crate's own
/// compilation, rather than with a bare `cfg!` in a dependent crate: a
/// `cfg!(feature = "test-endpoints")` written in `kiro-trust` would check
/// `kiro-trust`'s own features, not whether this crate was built with it,
/// and would miss the feature being unified in through `kiro-trust-tests`
/// in a workspace-wide build (CLAUDE.md Architecture rules: release builds
/// and the feature check select `-p kiro-trust` alone precisely to avoid
/// that unification).
pub const TEST_ENDPOINTS_COMPILED: bool = cfg!(feature = "test-endpoints");
