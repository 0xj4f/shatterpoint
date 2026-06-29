"""
Proxy resolution for shatterpoint.

A single ``--proxy`` value routes **all** outbound HTTP/S traffic through one
upstream proxy. Three intended use cases:

  * **TOR**       — scan from a different exit IP (``socks5h://127.0.0.1:9050``).
  * **Burp**      — inspect every request in the proxy history (``http://127.0.0.1:8080``).
  * **mitmproxy** — rewrite / record traffic (``http://127.0.0.1:8080``).

These are pure functions — no network calls. They normalise and validate the
value so a typo fails *loudly at startup* instead of silently sending traffic
direct, which for a TOR user would be a deanonymisation footgun.

Precedence (resolved by :func:`resolve_proxy`): CLI ``--proxy`` > config
``proxy.url``.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Schemes httpx understands (with the ``socks`` extra installed for the
# SOCKS variants). ``socks5h`` routes DNS *through* the proxy — use it for
# TOR so the target hostname is resolved at the exit node, not locally
# (a plain ``socks5`` leaks the DNS lookup).
ALLOWED_SCHEMES = ("http", "https", "socks5", "socks5h")


def normalize_proxy(value: str | None) -> tuple[str | None, str | None]:
    """Normalise a raw proxy value into a full proxy URL.

    Returns ``(url, error)`` where exactly one side is meaningful:

      * ``(None, None)``      — no proxy requested (empty / blank input).
      * ``(url, None)``       — a valid, normalised proxy URL.
      * ``(None, "reason")``  — the value was provided but is malformed; the
        caller must abort rather than fall back to a direct connection.

    A bare ``host:port`` (no scheme) defaults to ``http://`` — the common
    Burp / mitmproxy case. Any explicit scheme is preserved and validated
    against :data:`ALLOWED_SCHEMES`, and a host must be present.
    """
    if not value or not value.strip():
        return None, None

    raw = value.strip()
    if "://" not in raw:
        # Bare host:port → assume an HTTP proxy (Burp / mitmproxy default).
        raw = f"http://{raw}"

    try:
        parsed = urlparse(raw)
    except Exception:
        return None, f"could not parse proxy URL: {value!r}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return None, (
            f"unsupported proxy scheme {scheme!r} "
            f"(use one of: {', '.join(ALLOWED_SCHEMES)}) — got {value!r}"
        )
    if not parsed.hostname:
        return None, f"proxy URL is missing a host: {value!r}"

    return raw, None


def resolve_proxy(cli_value: str | None, config: dict) -> tuple[str | None, str | None]:
    """Resolve the effective proxy URL with **CLI > config** precedence.

    ``cli_value`` is the ``--proxy`` argument; the config fallback is
    ``config['proxy']['url']``. Returns the same ``(url, error)`` contract as
    :func:`normalize_proxy`. An ``error`` is only set when a value *was*
    provided and is malformed — never when no proxy is configured.
    """
    raw = cli_value if cli_value else (config.get("proxy") or {}).get("url")
    return normalize_proxy(raw)
