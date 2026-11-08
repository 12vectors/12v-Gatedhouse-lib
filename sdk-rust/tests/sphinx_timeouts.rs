// Copyright (c) 2026 12vectors.com
// SPDX-License-Identifier: MIT
// See the LICENSE file in the repository root for the full license text.

//! Issue #4: every outbound HTTP call is bounded, and Sphinx failures are
//! typed. Mirrors the Java SphinxClientTest: each test stands up a local
//! server that misbehaves in one specific way.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use gatedhouse::{
    GatedhouseFactory, SphinxClient, SphinxErrorKind, TokenVerificationReason, TokenVerifierConfig,
};

const SHORT: Duration = Duration::from_millis(500);

/// Connections a misbehaving server keeps open (never answered) for the
/// life of the test.
type Held = Arc<Mutex<Vec<TcpStream>>>;

/// Accepts connections, then never sends a byte.
fn black_hole() -> (String, Held) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let held: Held = Arc::default();
    let keep = held.clone();
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            keep.lock().unwrap().push(conn); // keep it open, say nothing
        }
    });
    (base, held)
}

/// Sends a status line and headers promising a body, then stalls.
fn stalls_mid_body() -> (String, Held) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let held: Held = Arc::default();
    let keep = held.clone();
    thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut buf = [0u8; 8192];
            let _ = conn.read(&mut buf); // consume the request
            let _ = conn.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                  Content-Length: 100\r\n\r\n{\"access",
            ); // ... and never finishes
            keep.lock().unwrap().push(conn);
        }
    });
    (base, held)
}

/// A port with nothing listening on it.
fn refusing() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", listener.local_addr().unwrap())
}

/// Answers every request with the given status and body.
fn answering(status: u16, body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut buf = [0u8; 8192];
            let _ = conn.read(&mut buf);
            let _ = write!(
                conn,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    base
}

fn client(base_url: &str) -> SphinxClient {
    SphinxClient::new(base_url, "client", "secret").with_timeout(SHORT)
}

/// Well-formed RS256 JWT with a kid, so verification must fetch the JWKS.
/// A literal, so the test needs no base64 dependency. It decodes to
/// header `{"alg":"RS256","typ":"JWT","kid":"k1"}`, payload
/// `{"sub":"x","iss":"https://issuer","aud":"app","exp":4102444800}`, and
/// a 256-byte all-zero signature.
const UNVERIFIABLE_TOKEN_WITH_KID: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0.eyJzdWIiOiJ4IiwiaXNzIjoiaHR0cHM6Ly9pc3N1ZXIiLCJhdWQiOiJhcHAiLCJleHAiOjQxMDI0NDQ4MDB9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

// ---- timeouts ---------------------------------------------------------------

#[test]
fn default_timeout_is_ten_seconds() {
    assert_eq!(SphinxClient::DEFAULT_TIMEOUT, Duration::from_secs(10));
    assert_eq!(SphinxClient::new("http://x", "c", "s").timeout(), Duration::from_secs(10));
}

#[test]
#[should_panic(expected = "timeout must be positive")]
fn timeout_must_be_positive() {
    let _ = SphinxClient::new("http://x", "c", "s").with_timeout(Duration::ZERO);
}

#[test]
fn unresponsive_token_endpoint_times_out_instead_of_hanging() {
    let (base, _held) = black_hole();
    let start = Instant::now();
    let err = client(&base).exchange_code("code", "http://cb").unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(err.kind, SphinxErrorKind::Timeout, "{err}");
    assert_eq!(err.status_code, None);
    assert!(
        elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(3),
        "timed out after {elapsed:?}"
    );
}

#[test]
fn unresponsive_introspection_endpoint_times_out() {
    let (base, _held) = black_hole();
    let err = client(&base).introspect("tok").unwrap_err();
    assert_eq!(err.kind, SphinxErrorKind::Timeout, "{err}");
}

#[test]
fn body_that_stalls_midway_times_out() {
    let (base, _held) = stalls_mid_body();
    let start = Instant::now();
    let err = client(&base).refresh_token("rt").unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(err.kind, SphinxErrorKind::Timeout, "{err}");
    assert!(elapsed < Duration::from_secs(3), "gave up after {elapsed:?}");
}

// ---- other failure kinds ----------------------------------------------------

#[test]
fn unreachable_endpoint_is_transport() {
    let err = client(&refusing()).client_credentials(None).unwrap_err();
    assert_eq!(err.kind, SphinxErrorKind::Transport, "{err}");
}

#[test]
fn refused_token_request_is_http_status_with_code_and_body() {
    let base = answering(400, r#"{"error":"invalid_grant"}"#);
    let err = client(&base).exchange_code("used-code", "http://cb").unwrap_err();
    assert_eq!(err.kind, SphinxErrorKind::HttpStatus);
    assert_eq!(err.status_code, Some(400));
    assert!(err.message.contains("invalid_grant"), "{err}");
}

#[test]
fn non_json_token_response_is_invalid_response() {
    let err = client(&answering(200, "<html>proxy error</html>")).refresh_token("rt").unwrap_err();
    assert_eq!(err.kind, SphinxErrorKind::InvalidResponse, "{err}");
}

#[test]
fn still_a_std_error_for_existing_handlers() {
    let err = client(&refusing()).refresh_token("rt").unwrap_err();
    let boxed: Box<dyn std::error::Error> = Box::new(err);
    assert!(!boxed.to_string().is_empty());
}

// ---- unchanged success paths ------------------------------------------------

#[test]
fn successful_token_response_is_parsed() {
    let base = answering(
        200,
        r#"{"access_token":"at","refresh_token":"rt","token_type":"Bearer","expires_in":3600}"#,
    );
    let t = client(&base).exchange_code("code", "http://cb").unwrap();
    assert_eq!(t.access_token.as_deref(), Some("at"));
    assert_eq!(t.refresh_token.as_deref(), Some("rt"));
    assert_eq!(t.expires_in, 3600);
}

#[test]
fn introspection_still_parses_the_body_of_a_non_success_status() {
    let result = client(&answering(401, r#"{"active":false}"#)).introspect("tok").unwrap();
    assert_eq!(result.get("active"), Some(&serde_json::Value::Bool(false)));
}

// ---- JWKS -------------------------------------------------------------------

#[test]
fn default_jwks_timeout_is_five_seconds() {
    assert_eq!(TokenVerifierConfig::new("http://x/jwks", "i", "a").jwks_timeout, Duration::from_secs(5));
    assert_eq!(TokenVerifierConfig::DEFAULT_JWKS_TIMEOUT, Duration::from_secs(5));
}

#[test]
fn unresponsive_jwks_endpoint_fails_fast_as_jwks_unavailable() {
    let (base, _held) = black_hole();
    let config = TokenVerifierConfig::new(format!("{base}/jwks.json"), "https://issuer", "app")
        .with_jwks_timeout(SHORT);
    let gh = GatedhouseFactory::create_just_token_verifier(config);
    let start = Instant::now();
    let err = gh.verify_token(UNVERIFIABLE_TOKEN_WITH_KID).unwrap_err();
    let elapsed = start.elapsed();
    assert_eq!(err.reason, TokenVerificationReason::JwksUnavailable, "{}", err.message);
    assert!(elapsed < Duration::from_secs(3), "JWKS fetch gave up after {elapsed:?}");
}
