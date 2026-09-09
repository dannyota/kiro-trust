//! Developer-only payload capture (spec 8.3). The whole module is compiled
//! out unless built with the `capture` feature, which is not a default
//! feature of this crate and is never enabled in a release build; `audit`
//! reports it and exits 1 when present (spec 6.6, task-21-rulings ruling 4).
//!
//! Capture writes real prompts, Kiro payloads, and responses to disk for
//! recording fixtures from a live session. Nothing captured here is ever
//! logged through `tracing` (spec 6.4); it is written straight to files
//! under the operator-chosen `--capture-dir`, each with mode 0600 in a
//! directory with mode 0700 (Unix).

#![cfg(feature = "capture")]

use bytes::Bytes;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Capture {
    dir: PathBuf,
    seq: AtomicU64,
}

impl Capture {
    pub fn new(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Capture {
            dir: dir.to_path_buf(),
            seq: AtomicU64::new(1),
        })
    }

    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.dir.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut f) => {
                if let Err(e) = std::io::Write::write_all(&mut f, bytes) {
                    tracing::warn!(error_type = "capture_write_failed", "{e}");
                }
            }
            Err(e) => tracing::warn!(error_type = "capture_open_failed", "{e}"),
        }
    }

    /// Write the four files for one request (spec 8.3): the Anthropic
    /// request as the client sent it, the Kiro payload kiro-trust built,
    /// the raw upstream event-stream bytes, and the SSE (or JSON, for a
    /// non-streaming call) response text sent back to the client.
    pub fn record(
        &self,
        seq: u64,
        request: &[u8],
        payload: &[u8],
        upstream: &[u8],
        response: &str,
    ) {
        self.write(&format!("{seq:04}-request.json"), request);
        self.write(&format!("{seq:04}-payload.json"), payload);
        self.write(&format!("{seq:04}-upstream.eventstream"), upstream);
        self.write(&format!("{seq:04}-response.sse"), response.as_bytes());
    }
}

/// Per-request capture state, carried on the `Pump` that serves the
/// request (`server::pump`) so the streaming and non-streaming completion
/// paths in `server::messages` can record it without threading extra
/// parameters through `stream_response`.
pub struct CaptureState {
    pub handle: Arc<Capture>,
    pub seq: u64,
    pub request: Bytes,
    pub payload: Vec<u8>,
    /// Accumulated response text: the streaming path appends every SSE
    /// chunk as it is produced; the non-streaming path is written directly
    /// from the final JSON body instead of through this field.
    pub text: String,
}
