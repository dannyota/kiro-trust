//! The only two hosts kiro-trust talks to (spec 6.2). No URL type exists
//! in this crate's public API.

use crate::region::{Region, RuntimeRegion};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Oidc { sso_region: Region },
    Runtime { region: RuntimeRegion },
}

impl Destination {
    pub fn host(&self) -> String {
        match self {
            Destination::Oidc { sso_region } => format!("oidc.{sso_region}.amazonaws.com"),
            Destination::Runtime { region } => format!("runtime.{region}.kiro.dev"),
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.host())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::region::{Region, RuntimeRegion};

    #[test]
    fn hosts_are_built_from_validated_regions_only() {
        let oidc = Destination::Oidc {
            sso_region: Region::parse("ap-southeast-1").unwrap(),
        };
        assert_eq!(oidc.host(), "oidc.ap-southeast-1.amazonaws.com");
        let rt = Destination::Runtime {
            region: RuntimeRegion::parse("us-east-1").unwrap(),
        };
        assert_eq!(rt.host(), "runtime.us-east-1.kiro.dev");
    }
}
