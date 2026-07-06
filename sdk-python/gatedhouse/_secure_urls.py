"""Internal URL-scheme guard (mirrors Java ``SecureUrls``).

Security-sensitive endpoints — the Sphinx base URL and the JWKS URI — carry
credentials or root the token-verification trust chain, so they must be reached
over TLS. HTTPS is required; plain HTTP is permitted only for loopback hosts so
local development and tests still work. Not part of the public API.
"""

from __future__ import annotations

from urllib.parse import urlparse

# urlparse's ``hostname`` lowercases and strips IPv6 brackets, so bare forms here.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def require_https_or_loopback(url: str, what: str) -> None:
    """Raise ``ValueError`` unless *url* is https (or http to a loopback host)."""
    if url is None:
        raise ValueError(f"{what} must not be None")
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        return
    host = (parsed.hostname or "").lower()
    if scheme == "http" and host in _LOOPBACK_HOSTS:
        return
    raise ValueError(
        f"{what} must use https (http is allowed only for localhost): {url}"
    )
