//! Region strings become hostnames, so they are validated, never trusted
//! (spec 6.2). Pattern: `^[a-z]{2}(-gov)?-[a-z]+-[0-9]$`, at most 32 bytes.

use std::fmt;

pub const RUNTIME_ALLOWLIST: &[&str] = &[
    "us-east-1",
    "eu-central-1",
    "us-gov-east-1",
    "us-gov-west-1",
];
const MAX_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RegionError {
    #[error("region {0:?} does not match ^[a-z]{{2}}(-gov)?-[a-z]+-[0-9]$")]
    Pattern(String),
    #[error(
        "region {0} has no Kiro runtime; allowed: us-east-1, eu-central-1, us-gov-east-1, us-gov-west-1 (spec 6.2)"
    )]
    NotServed(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Region(String);

impl Region {
    pub fn parse(s: &str) -> Result<Self, RegionError> {
        let err = || RegionError::Pattern(s.chars().take(40).collect());
        if s.is_empty() || s.len() > MAX_LEN {
            return Err(err());
        }
        let parts: Vec<&str> = s.split('-').collect();
        let (prefix, direction, number) = match parts.as_slice() {
            [p, d, n] => (p, d, n),
            [p, "gov", d, n] => (p, d, n),
            _ => return Err(err()),
        };
        let lower_alpha = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_lowercase());
        if prefix.len() != 2 || !lower_alpha(prefix) || !lower_alpha(direction) {
            return Err(err());
        }
        if number.len() != 1 || !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err());
        }
        Ok(Region(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeRegion(Region);

impl RuntimeRegion {
    pub fn parse(s: &str) -> Result<Self, RegionError> {
        let r = Region::parse(s)?;
        if !RUNTIME_ALLOWLIST.contains(&r.as_str()) {
            return Err(RegionError::NotServed(r.0));
        }
        Ok(RuntimeRegion(r))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for RuntimeRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // spec 6.2 and security test invalid_region_rejected
    #[test]
    fn region_pattern() {
        for ok in [
            "us-east-1",
            "ap-southeast-1",
            "eu-central-1",
            "us-gov-west-1",
            "ap-northeast-3",
        ] {
            assert!(Region::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "us-east-1/",
            "evil.com",
            "US-EAST-1",
            "us-east",
            "us-east-10",
            "us_east_1",
            "",
            "us-east-1.example.com",
            "a-b-c-d-1",
            "us-east-1@x",
            &"a".repeat(33),
        ] {
            assert!(
                matches!(Region::parse(bad), Err(RegionError::Pattern(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn runtime_allowlist() {
        assert!(RuntimeRegion::parse("us-east-1").is_ok());
        assert!(RuntimeRegion::parse("us-gov-east-1").is_ok());
        assert!(matches!(
            RuntimeRegion::parse("ap-southeast-1"),
            Err(RegionError::NotServed(_))
        ));
        assert!(matches!(
            RuntimeRegion::parse("us-east-1/"),
            Err(RegionError::Pattern(_))
        ));
    }
}
