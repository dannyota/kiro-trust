//! The single outbound network policy for kiro-trust (spec 3.2). Nothing
//! else in the workspace may depend on reqwest.

mod client;
mod destination;
mod policy;
mod region;

pub use client::{Client, NetError, Response};
pub use destination::Destination;
pub use policy::Policy;
pub use region::{RUNTIME_ALLOWLIST, Region, RegionError, RuntimeRegion};
