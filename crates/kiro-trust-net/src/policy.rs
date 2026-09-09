//! Timeouts and limits for the single outbound client (spec 3.2, 5.5).

use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Policy {
    pub connect_timeout: Duration,
    /// Response headers must arrive within this.
    pub header_timeout: Duration,
    /// Each body read must produce a byte within this.
    pub read_idle_timeout: Duration,
    pub max_error_body: usize,
    /// Test-only: send every destination to 127.0.0.1:port over plain HTTP.
    loopback_port: Option<u16>,
}

impl Policy {
    pub fn production() -> Self {
        Policy {
            connect_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(30),
            read_idle_timeout: Duration::from_secs(180),
            max_error_body: 64 * 1024,
            loopback_port: None,
        }
    }

    #[cfg(feature = "test-endpoints")]
    pub fn loopback_plain_http(port: u16) -> Self {
        Policy {
            loopback_port: Some(port),
            ..Policy::production()
        }
    }

    pub fn https_only(&self) -> bool {
        self.loopback_port.is_none()
    }

    pub(crate) fn loopback_port(&self) -> Option<u16> {
        self.loopback_port
    }
}
