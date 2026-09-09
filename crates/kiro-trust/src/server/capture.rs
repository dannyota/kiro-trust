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
        // Create the directory at 0700 only when it is missing. An
        // existing directory keeps whatever mode it already has, and a
        // pre-existing symlink at `dir` never has its target's mode
        // changed: `DirBuilder::create` with `recursive(true)` succeeds
        // without touching a path that already exists, the same way
        // `create_dir_all` does (task-21-fix-1 Important 7, mirroring
        // `crates/kiro-trust/src/token.rs::write_token_file`, which the
        // task 17 review fixed the same way for the same reason).
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(dir)?;
        }
        Ok(Capture {
            dir: dir.to_path_buf(),
            seq: AtomicU64::new(1),
        })
    }

    pub fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }

    /// `create_new` rather than `create` plus `truncate` (task-21-fix-1
    /// Minor 3): a restart pointed at a non-empty `--capture-dir` must not
    /// silently replace a previous run's files, and a pre-existing
    /// symlink at this path must not be followed and have its target
    /// overwritten with a real prompt. `create_new` fails on either case
    /// without touching whatever the name already refers to; the operator
    /// sees why and can point `--capture-dir` at an empty directory.
    fn write(&self, name: &str, bytes: &[u8]) {
        let path = self.dir.join(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
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
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                tracing::warn!(
                    error_type = "capture_file_exists",
                    "{name} already exists in the capture directory; point --capture-dir at an \
                     empty directory to start a new capture"
                );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn existing_directory_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        Capture::new(dir.path()).unwrap();
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o755,
            "an existing directory's mode must not be narrowed"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_new_directory_is_created_at_0700() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("capture");
        Capture::new(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn record_never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let capture = Capture::new(dir.path()).unwrap();
        capture.record(1, b"first request", b"{}", b"", "first response");
        // A second record() at the same seq must not silently replace the
        // first run's files (task-21-fix-1 Minor 3): create_new fails on
        // the pre-existing files and the write is skipped, leaving the
        // original content in place.
        capture.record(1, b"second request", b"{}", b"", "second response");
        let saved = std::fs::read_to_string(dir.path().join("0001-request.json")).unwrap();
        assert_eq!(saved, "first request");
    }
}
