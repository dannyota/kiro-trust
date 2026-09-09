//! `GuardedListener`: a connection cap and a header-read deadline that axum's
//! `Listener` trait cannot express on its own (spec 6.3).
//!
//! Two bounds live here, and neither is the `MAX_CONCURRENT` semaphore in
//! `server` (that one bounds `/v1/messages` handlers): `MAX_CONNECTIONS` caps
//! concurrently open connections, and `HEADER_READ_TIMEOUT` fails a connection
//! whose first request has not been parsed in time. Both bound connections
//! that never reach a handler.
//!
//! The deadline signal is a **parsed request**, not a first response write.
//! `/v1/messages` can legitimately wait on a credential refresh, on upstream
//! response headers, and on `Pump::prime` for well over `HEADER_READ_TIMEOUT`
//! after hyper has parsed the request (spec 6.3); a first-write deadline
//! would cancel those valid slow requests. So `GuardedIo` does not watch for
//! a response write. Instead, a `HeaderDeadline` flag travels with the
//! connection into a `ConnectionInfo`, and `server::headers_received`
//! disarms it once axum has invoked that middleware, which only happens after
//! hyper has parsed a complete request. Nothing here scans the byte stream
//! for `\r\n\r\n`; hyper owns HTTP syntax.

use axum::serve::{IncomingStream, Listener};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Sleep;

/// Concurrent connection cap (spec 6.3, 4.1 audit output).
pub const MAX_CONNECTIONS: usize = 32;

/// How long a connection has to get its first request parsed before it is
/// dropped (spec 6.3, 4.1 audit output).
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// A cloneable flag shared between a connection's `GuardedIo` and the
/// `ConnectionInfo` extracted for it. `disarm` is the only mutator; there is
/// no way to re-arm, matching the one-shot "first request on this
/// connection" bound described in spec 6.3.
#[derive(Clone, Debug)]
pub struct HeaderDeadline {
    armed: Arc<AtomicBool>,
}

impl HeaderDeadline {
    fn new() -> Self {
        Self {
            armed: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Disarm the deadline. Called from `server::headers_received`, which
    /// axum only invokes after hyper has parsed a complete request on this
    /// connection.
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    fn is_armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }
}

/// `Listener::Io` for `GuardedListener`: the accepted stream, the owned
/// semaphore permit that keeps the connection under `MAX_CONNECTIONS`, and
/// the header-read deadline. Dropping this releases the permit.
pub struct GuardedIo {
    stream: TcpStream,
    // Held only to release on drop; never read.
    _permit: OwnedSemaphorePermit,
    deadline: HeaderDeadline,
    // Boxed so `GuardedIo` stays `Unpin` even though `tokio::time::Sleep`
    // itself is not: `Box<T>` is `Unpin` regardless of `T`, which lets
    // `poll_read` below use plain `&mut self` access with no manual pin
    // projection or extra dependency.
    timer: Pin<Box<Sleep>>,
}

impl GuardedIo {
    fn new(
        stream: TcpStream,
        permit: OwnedSemaphorePermit,
        deadline: HeaderDeadline,
        header_timeout: Duration,
    ) -> Self {
        Self {
            stream,
            _permit: permit,
            deadline,
            timer: Box::pin(tokio::time::sleep(header_timeout)),
        }
    }
}

impl AsyncRead for GuardedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Once headers_received has disarmed the deadline, this is a plain
        // delegation with no timer in the race: the first request on this
        // connection has been parsed, and later requests on a kept-alive
        // connection are covered by the connection cap alone (spec 6.3).
        if self.deadline.is_armed() && self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no complete request parsed within the header read timeout",
            )));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for GuardedIo {
    // Writes never disarm the deadline (spec 6.3): only headers_received
    // does, and only in response to a parsed request. A response write can
    // happen for reasons unrelated to a fully parsed request on some future
    // hyper internals, so this stays a plain delegation regardless.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

/// A `TcpListener` wrapped to cap concurrent connections and to hand each
/// accepted connection a header-read deadline (spec 6.3).
pub struct GuardedListener {
    inner: TcpListener,
    semaphore: Arc<Semaphore>,
    header_timeout: Duration,
}

impl GuardedListener {
    pub fn new(inner: TcpListener, max_connections: usize, header_timeout: Duration) -> Self {
        Self {
            inner,
            semaphore: Arc::new(Semaphore::new(max_connections)),
            header_timeout,
        }
    }
}

impl Listener for GuardedListener {
    type Io = GuardedIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            // Take the permit before accepting, not after: `Listener::accept`
            // cannot return an error, so backpressure at the cap has to work
            // by not accepting rather than by accepting and dropping (spec
            // 6.3). `acquire_owned` only fails if the semaphore is closed,
            // which `GuardedListener` never does.
            let permit = self
                .semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("connection semaphore is never closed");
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    let io =
                        GuardedIo::new(stream, permit, HeaderDeadline::new(), self.header_timeout);
                    return (io, addr);
                }
                Err(e) => {
                    // Permit is dropped (and released) here on the error
                    // path, then axum's own accept-error policy applies
                    // (axum-0.8.9 src/serve/listener.rs handle_accept_error):
                    // return to the loop immediately for a per-connection
                    // error kind, otherwise log and sleep one second.
                    drop(permit);
                    if is_connection_error(&e) {
                        continue;
                    }
                    tracing::error!(error_type = "accept_error", "accept error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

/// Connection metadata served alongside each request via
/// `into_make_service_with_connect_info::<ConnectionInfo>()`. `header_deadline`
/// is the handle `server::headers_received` disarms.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub remote_addr: SocketAddr,
    pub header_deadline: HeaderDeadline,
}

impl axum::extract::connect_info::Connected<IncomingStream<'_, GuardedListener>>
    for ConnectionInfo
{
    fn connect_info(stream: IncomingStream<'_, GuardedListener>) -> Self {
        ConnectionInfo {
            remote_addr: *stream.remote_addr(),
            header_deadline: stream.io().deadline.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unlike the listener.rs integration tests, this exercises HeaderDeadline
    // in isolation without an event loop.
    #[test]
    fn disarm_is_observed_by_a_clone() {
        let d = HeaderDeadline::new();
        let clone = d.clone();
        assert!(d.is_armed());
        assert!(clone.is_armed());
        clone.disarm();
        assert!(!d.is_armed());
        assert!(!clone.is_armed());
    }

    #[test]
    fn is_connection_error_matches_axum_policy() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
        ] {
            assert!(is_connection_error(&io::Error::new(kind, "x")));
        }
        assert!(!is_connection_error(&io::Error::other("x")));
    }
}
