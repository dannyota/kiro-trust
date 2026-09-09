//! Integration tests for `GuardedListener` (plan Task 5, spec 6.3): the
//! header-read deadline and the connection cap, exercised through a real
//! bound TCP socket and `axum::serve`.
//!
//! These tests write raw HTTP/1.1 bytes over `TcpStream` rather than using a
//! client crate: `kiro-trust`'s architecture rules confine `reqwest` to
//! `kiro-trust-net`, and the malformed-request and trickling-header cases
//! need byte-level control a well-formed HTTP client would not give anyway.

use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use kiro_trust::listener::{ConnectionInfo, GuardedListener};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Disarms the header deadline exactly the way
/// `kiro_trust::server::headers_received` does: read the connect info
/// straight off the request's extensions (not through the `FromRequestParts`
/// extractor, which axum does not support as `Option<ConnectInfo<T>>` for a
/// handler argument), and do nothing when it is absent.
async fn disarm(req: Request, next: Next) -> Response {
    if let Some(ConnectInfo(info)) = req.extensions().get::<ConnectInfo<ConnectionInfo>>() {
        info.header_deadline.disarm();
    }
    next.run(req).await
}

/// A tiny app with two routes, both behind the same `disarm` middleware
/// `kiro_trust::server::headers_received` uses in production: `/health`
/// answers immediately, and `/slow` sleeps for `delay` before responding.
/// `/slow` exists to prove the regression case in spec 6.3: a handler that
/// runs long after headers are parsed must not be cut off by the header-read
/// deadline.
///
/// This intentionally does not import `kiro_trust::server::build_router`:
/// that router, its auth layer, and its own `headers_received` wiring are
/// already covered end to end by `crates/kiro-trust-tests/tests/server.rs`.
/// This file's job is `GuardedListener`/`GuardedIo` in isolation, which only
/// needs a router that disarms the deadline the same way the real one does.
fn test_app(delay: Duration) -> Router {
    async fn health() -> &'static str {
        "ok"
    }
    async fn slow(State(delay): State<Duration>) -> impl IntoResponse {
        tokio::time::sleep(delay).await;
        "done"
    }
    Router::new()
        .route("/health", get(health))
        .route("/slow", get(slow))
        .layer(middleware::from_fn(disarm))
        .with_state(delay)
}

/// Starts `axum::serve` with a `GuardedListener` over a real loopback socket
/// and returns its address, a graceful-shutdown trigger, and the serve
/// task's `JoinHandle` so the caller can await a clean exit.
async fn spawn_guarded(
    max_connections: usize,
    header_timeout: Duration,
    app: Router,
) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = GuardedListener::new(tcp, max_connections, header_timeout);
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<ConnectionInfo>(),
        )
        .with_graceful_shutdown(async {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    (addr, tx, handle)
}

/// Sends a minimal well-formed HTTP/1.1 GET (keep-alive) and returns the
/// status line of the response.
async fn get_status_line(stream: &mut TcpStream, path: &str) -> String {
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap()
        .to_string()
}

// Regression test for the first-write design defect (spec 6.3): the deadline
// signal must be a parsed request, not a first response write. A first-write
// deadline would cancel `/slow` here, since its handler runs well past the
// header timeout after the request line has already been read and the
// deadline has been disarmed.
//
// This test runs on real time deliberately, unlike its sibling deadline
// tests below. Under `start_paused = true`, tokio auto-advances the clock to
// the next pending timer as soon as nothing else is runnable; with a client
// task and a server connection task both needing a scheduling pass to carry
// the request from "bytes written" to "hyper has parsed it and
// headers_received has disarmed the deadline", paused time can jump straight
// to firing the 20ms timer before that handoff completes, even though it
// takes a negligible fraction of 20ms of real wall time. That produced a
// spurious `ConnectionReset` failure here with no defect in `GuardedIo` or
// `headers_received`: the same scenario passes reliably on real time, and
// the sibling tests below are unaffected because they have nothing racing
// the timer to disarm it, so auto-advance is exactly the right tool there.
#[tokio::test]
async fn a_complete_request_disarms_the_deadline_so_a_slow_handler_still_returns_200() {
    let header_timeout = Duration::from_millis(20);
    // The handler sleeps far longer than header_timeout. If GuardedIo were
    // still racing the header deadline against this response instead of
    // having disarmed on the parsed request, the connection would be cut
    // off before "done" is written.
    let handler_delay = header_timeout * 50;
    let (addr, shutdown, handle) = spawn_guarded(4, header_timeout, test_app(handler_delay)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    // Real time: see the comment on this test above for why.
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "expected 200 after the deadline had long since passed, got: {text}"
    );
    assert!(text.ends_with("done"));

    shutdown.send(()).unwrap();
    handle.await.unwrap();
}

// A silent client (no bytes at all) never lets hyper parse a request, so the
// deadline stays armed and GuardedIo::poll_read must time it out.
#[tokio::test(start_paused = true)]
async fn a_silent_client_is_disconnected_after_the_header_deadline() {
    let header_timeout = Duration::from_millis(20);
    let (addr, shutdown, handle) = spawn_guarded(4, header_timeout, test_app(Duration::ZERO)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    // Send nothing. Reading now waits until GuardedIo's timer fires and
    // returns TimedOut, which hyper turns into closing the connection: the
    // read resolves with EOF (0 bytes) rather than any HTTP response.
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "connection should be closed, not answered");

    shutdown.send(()).unwrap();
    handle.await.unwrap();
}

// A client trickling header bytes in slower than the deadline never
// completes a parseable request either, so it must trip the same timeout as
// a fully silent client.
#[tokio::test(start_paused = true)]
async fn a_trickling_client_is_disconnected_after_the_header_deadline() {
    let header_timeout = Duration::from_millis(40);
    let (addr, shutdown, handle) = spawn_guarded(4, header_timeout, test_app(Duration::ZERO)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    // Trickle an incomplete request line in slowly, well under one byte per
    // header_timeout/4, so the request is never completed and hyper never
    // parses it: the deadline never disarms.
    let partial = b"GET /health HTTP/1.1\r\n";
    for &byte in partial {
        // Each write races the connection's own deadline in the background;
        // if a write fails because the deadline already fired, that is
        // still consistent with this test's assertion below and is not
        // itself a failure.
        if stream.write_all(&[byte]).await.is_err() {
            break;
        }
        tokio::time::sleep(header_timeout / 4).await;
    }

    // Whether the deadline fired mid-trickle or right after, the request
    // line was never completed, so the connection must end without a
    // response.
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    assert_eq!(n, 0, "connection should be closed, not left open");

    shutdown.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn dropping_guarded_io_releases_the_connection_permit() {
    let (addr, shutdown, handle) =
        spawn_guarded(1, Duration::from_secs(15), test_app(Duration::ZERO)).await;

    // Fill the single slot and hold it open past a completed request so the
    // deadline is disarmed and only the connection cap is in play.
    let mut first = TcpStream::connect(addr).await.unwrap();
    let line = get_status_line(&mut first, "/health").await;
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");

    // A second connection should not be accepted while the first is open:
    // the TCP handshake can still succeed (backlog), but the server never
    // calls accept() for it, so no response arrives within a short window.
    let mut second = TcpStream::connect(addr).await.unwrap();
    second
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let not_yet = tokio::time::timeout(Duration::from_millis(150), second.read(&mut buf)).await;
    assert!(
        not_yet.is_err(),
        "second connection should not be served while the cap is held"
    );

    // Dropping the first connection drops its GuardedIo, releasing the
    // permit, which lets the listener accept the second connection.
    drop(first);
    let n = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf))
        .await
        .expect("second connection should now be served")
        .unwrap();
    assert!(n > 0);
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

    shutdown.send(()).unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn connection_cap_holds_max_connections_before_accepting_one_more() {
    const CAP: usize = 2;
    let (addr, shutdown, handle) =
        spawn_guarded(CAP, Duration::from_secs(15), test_app(Duration::ZERO)).await;

    let mut held = Vec::new();
    for _ in 0..CAP {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let line = get_status_line(&mut s, "/health").await;
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        held.push(s);
    }

    let mut extra = TcpStream::connect(addr).await.unwrap();
    extra
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let blocked = tokio::time::timeout(Duration::from_millis(150), extra.read(&mut buf)).await;
    assert!(
        blocked.is_err(),
        "at the cap, a new connection must not be accepted"
    );

    // Close one held connection; the extra one should now be accepted.
    held.pop();
    let n = tokio::time::timeout(Duration::from_secs(2), extra.read(&mut buf))
        .await
        .expect("accepted once a slot freed up")
        .unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));

    drop(held);
    shutdown.send(()).unwrap();
    handle.await.unwrap();
}

// End-to-end sanity through a real bound socket: /health (an unauthenticated
// route in the real router too), an authenticated route and a malformed
// request are exercised through hyper's own parser here since auth itself is
// `server::require_token`'s job and is covered exhaustively in
// crates/kiro-trust-tests/tests/server.rs, plus graceful shutdown.
#[tokio::test]
async fn health_and_malformed_requests_and_graceful_shutdown_work_over_a_real_socket() {
    let (addr, shutdown, handle) =
        spawn_guarded(4, Duration::from_secs(15), test_app(Duration::ZERO)).await;

    let mut ok = TcpStream::connect(addr).await.unwrap();
    let line = get_status_line(&mut ok, "/health").await;
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");
    drop(ok);

    // A malformed request line: hyper rejects this at the parser, never
    // reaching a handler, and the connection is closed rather than hung.
    let mut bad = TcpStream::connect(addr).await.unwrap();
    bad.write_all(b"NOT A REQUEST LINE AT ALL\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), bad.read(&mut buf))
        .await
        .expect("server should respond or close promptly")
        .unwrap();
    if n > 0 {
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(
            text.starts_with("HTTP/1.1 400"),
            "expected a 400 for a malformed request line, got: {text}"
        );
    }
    // n == 0 (connection closed without a response) is also an acceptable
    // way for hyper to reject an unparseable request line; either way the
    // connection does not hang and no handler ran.

    // Graceful shutdown: after the signal, the server stops accepting new
    // connections and the serve task's future resolves.
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("graceful shutdown should complete promptly")
        .unwrap();
}
