//! Timeouts and limits for the single outbound client (spec 3.2, 5.5).

use crate::client::NetError;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::time::Duration;

/// One extra trust anchor, parsed and validated from a PEM file at startup
/// (spec 6.2, 4.1: `--extra-ca <pem>`). Additive only: `Client::new` adds
/// these certificates to the compiled `webpki-roots` set, never in place of
/// it. Opaque outside this crate: no accessor returns certificate bytes, and
/// `Debug` prints only a count, so a log or error path can describe an
/// `ExtraCa` without ever being able to leak the certificate it holds.
pub struct ExtraCa {
    roots: RootCertStore,
    count: usize,
}

impl ExtraCa {
    /// Parses every certificate block in `pem`. Rejects PEM that fails to
    /// parse, PEM that parses but holds zero certificates, and any
    /// certificate that is not a usable trust anchor: each parsed
    /// certificate is validated by adding it to a `RootCertStore`, so input
    /// that merely looks like PEM without being a usable trust anchor fails
    /// here rather than silently doing nothing (spec 6.2).
    pub fn from_pem(pem: &[u8]) -> Result<Self, NetError> {
        let mut roots = RootCertStore::empty();
        let mut count = 0;
        for cert in CertificateDer::pem_slice_iter(pem) {
            let cert = cert.map_err(|_| NetError::ExtraCa(ExtraCaError::MalformedPem))?;
            roots
                .add(cert)
                .map_err(|_| NetError::ExtraCa(ExtraCaError::NotATrustAnchor))?;
            count += 1;
        }
        if count == 0 {
            return Err(NetError::ExtraCa(ExtraCaError::NoCertificateFound));
        }
        Ok(ExtraCa { roots, count })
    }

    pub(crate) fn add_to(&self, roots: &mut RootCertStore) {
        roots.roots.extend(self.roots.roots.iter().cloned());
    }
}

// Manual, not derived: the only thing this ever renders is the certificate
// count. No path to the certificate bytes exists through Debug (spec 6.2,
// AGENTS.md: never print a secret or trust material verbatim).
impl std::fmt::Debug for ExtraCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtraCa")
            .field("certificate_count", &self.count)
            .finish()
    }
}

/// Reason class for an `ExtraCa::from_pem` failure. Never carries certificate
/// bytes or a file path (spec 6.2): the caller (a later slice's `--extra-ca`
/// handling) attaches the path itself when it reports the configuration
/// error, this type never does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExtraCaError {
    #[error("input is not valid PEM")]
    MalformedPem,
    #[error("PEM contained no certificate")]
    NoCertificateFound,
    #[error("certificate is not a usable trust anchor")]
    NotATrustAnchor,
}

#[derive(Clone)]
pub struct Policy {
    pub connect_timeout: Duration,
    /// Response headers must arrive within this.
    pub header_timeout: Duration,
    /// Each body read must produce a byte within this.
    pub read_idle_timeout: Duration,
    pub max_error_body: usize,
    /// Test-only: send every destination to 127.0.0.1:port over plain HTTP.
    loopback_port: Option<u16>,
    extra_ca: Option<std::sync::Arc<ExtraCa>>,
}

impl Policy {
    pub fn production() -> Self {
        Policy {
            connect_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(30),
            read_idle_timeout: Duration::from_secs(180),
            max_error_body: 64 * 1024,
            loopback_port: None,
            extra_ca: None,
        }
    }

    #[cfg(feature = "test-endpoints")]
    pub fn loopback_plain_http(port: u16) -> Self {
        Policy {
            loopback_port: Some(port),
            ..Policy::production()
        }
    }

    /// Adds one extra trust anchor to the compiled roots this policy's
    /// client will build (spec 6.2). Additive only: it never replaces the
    /// signature of `production()` or `loopback_plain_http()`, and it never
    /// narrows what the compiled roots already trust.
    pub fn with_extra_ca(self, extra_ca: ExtraCa) -> Self {
        Policy {
            extra_ca: Some(std::sync::Arc::new(extra_ca)),
            ..self
        }
    }

    pub fn https_only(&self) -> bool {
        self.loopback_port.is_none()
    }

    pub(crate) fn loopback_port(&self) -> Option<u16> {
        self.loopback_port
    }

    pub(crate) fn extra_ca(&self) -> Option<&ExtraCa> {
        self.extra_ca.as_deref()
    }
}

// Manual, not derived: `ExtraCa`'s own Debug (certificate count only) is the
// only thing that ever renders for that field. A derived Debug would be
// forward-fragile: it stays safe today only because ExtraCa's Debug is safe,
// and a future field added here without this note would derive straight
// through it (spec 6.2, AGENTS.md security contracts).
impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("connect_timeout", &self.connect_timeout)
            .field("header_timeout", &self.header_timeout)
            .field("read_idle_timeout", &self.read_idle_timeout)
            .field("max_error_body", &self.max_error_body)
            .field("loopback_port", &self.loopback_port)
            .field("extra_ca", &self.extra_ca)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    /// A minimal self-signed CA certificate's PEM, generated fresh per call:
    /// a real, structurally valid trust anchor, distinct from a leaf
    /// certificate, for the "one valid test root" and "several valid roots"
    /// cases (spec 6.2's `--extra-ca` validates against real CA material).
    fn test_root_pem() -> String {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn empty_bytes_reports_no_certificate_found() {
        let err = ExtraCa::from_pem(b"").unwrap_err();
        assert_eq!(
            err.to_string(),
            NetError::ExtraCa(ExtraCaError::NoCertificateFound).to_string()
        );
    }

    #[test]
    fn text_with_no_certificate_block_reports_no_certificate_found() {
        let err = ExtraCa::from_pem(b"just some ordinary text\nwith multiple lines\n").unwrap_err();
        assert_eq!(
            err.to_string(),
            NetError::ExtraCa(ExtraCaError::NoCertificateFound).to_string()
        );
    }

    #[test]
    fn malformed_pem_is_rejected() {
        let broken =
            b"-----BEGIN CERTIFICATE-----\nnot valid base64!!!\n-----END CERTIFICATE-----\n";
        let err = ExtraCa::from_pem(broken).unwrap_err();
        assert_eq!(
            err.to_string(),
            NetError::ExtraCa(ExtraCaError::MalformedPem).to_string()
        );
    }

    #[test]
    fn valid_pem_framing_with_garbage_der_is_rejected() {
        // Valid base64 (so the PEM layer accepts it), but the decoded bytes
        // are not a certificate: proves the trust-anchor validation, not
        // just the PEM/base64 framing, actually runs.
        let garbage_der =
            b"not a certificate, just some bytes padded out to look substantial 1234567890";
        let body = base64_encode(garbage_der);
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");
        let err = ExtraCa::from_pem(pem.as_bytes()).unwrap_err();
        assert_eq!(
            err.to_string(),
            NetError::ExtraCa(ExtraCaError::NotATrustAnchor).to_string()
        );
    }

    #[test]
    fn one_valid_test_root_is_accepted() {
        let extra_ca = ExtraCa::from_pem(test_root_pem().as_bytes()).unwrap();
        assert_eq!(extra_ca.count, 1);
    }

    #[test]
    fn several_valid_roots_in_one_file_are_all_accepted() {
        let mut combined = test_root_pem();
        combined.push_str(&test_root_pem());
        let extra_ca = ExtraCa::from_pem(combined.as_bytes()).unwrap();
        assert_eq!(extra_ca.count, 2);
    }

    #[test]
    fn debug_never_renders_certificate_bytes() {
        let extra_ca = ExtraCa::from_pem(test_root_pem().as_bytes()).unwrap();
        let rendered = format!("{extra_ca:?}");
        assert_eq!(rendered, "ExtraCa { certificate_count: 1 }");
    }

    #[test]
    fn policy_debug_never_renders_certificate_bytes() {
        let pem_text = test_root_pem();
        let extra_ca = ExtraCa::from_pem(pem_text.as_bytes()).unwrap();
        let policy = Policy::production().with_extra_ca(extra_ca);
        let rendered = format!("{policy:?}");
        assert!(rendered.contains("certificate_count: 1"));
        // The PEM fixture's own base64 body must never appear verbatim in
        // Policy's Debug output.
        let body_line = pem_text
            .lines()
            .find(|l| !l.starts_with("-----"))
            .expect("fixture has a body line");
        assert!(!rendered.contains(body_line));
    }

    /// Minimal base64 encoder for the malformed-DER fixture above, so that
    /// one test does not need a base64 crate dependency.
    fn base64_encode(input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(CHARS[((n >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((n >> 12) & 0x3f) as usize] as char);
            out.push(if chunk.len() > 1 {
                CHARS[((n >> 6) & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                CHARS[(n & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    }
}
