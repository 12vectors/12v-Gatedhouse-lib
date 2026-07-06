//! Internal URL-scheme guard (mirrors Java `SecureUrls`).
//!
//! Security-sensitive endpoints — the Sphinx base URL and the JWKS URI — carry
//! credentials or root the token-verification trust chain, so they must be
//! reached over TLS. HTTPS is required; plain HTTP is permitted only for
//! loopback hosts so local development and tests still work.
//!
//! Like the Java SDK (which throws `IllegalArgumentException` at construction),
//! a violation is a configuration error and **panics** — fail fast at startup.
//! Not part of the public API.

/// Panic unless `url` is https (or http to a loopback host). `what` names the
/// setting for the message.
pub(crate) fn require_https_or_loopback(url: &str, what: &str) {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => panic!("{what} is not a valid URL: {url}"),
    };
    if scheme == "https" {
        return;
    }
    // authority = up to the first '/', '?' or '#'; drop any userinfo before '@'.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host = if authority.starts_with('[') {
        // IPv6 literal: [::1]:port
        let end = authority.find(']').unwrap_or(authority.len());
        &authority[1..end]
    } else {
        authority.split(':').next().unwrap_or(authority)
    };
    let host = host.to_ascii_lowercase();
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if scheme == "http" && loopback {
        return;
    }
    panic!("{what} must use https (http is allowed only for localhost): {url}");
}
