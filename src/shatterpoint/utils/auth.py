"""
Authentication helpers for shatterpoint.

Pure functions for:
  - resolving a bearer token with CLI > env > config precedence
  - redacting tokens for safe display in logs/reports
  - decoding the `exp` claim from JWTs (best-effort)
  - warning when a JWT is expired or expiring soon
  - deciding whether the Authorization header is safe to send to a
    given URL (used for redirect-strip logic)

None of these helpers make network calls. None raise on bad input —
opaque or malformed tokens return None from the decode helpers so the
caller can treat the token as an opaque bearer.
"""

import base64
import json
import os
import time
from urllib.parse import urlparse

ENV_VAR = "SHATTERPOINT_TOKEN"
_DEFAULT_PORTS = {"http": 80, "https": 443}


def resolve_token(cli_token: str | None, config: dict) -> str | None:
    """Return the bearer token to use, or None.

    Precedence: CLI flag > SHATTERPOINT_TOKEN env var > config['auth']['token'].
    Empty strings from any source are treated as "not set".
    """
    if cli_token:
        return cli_token
    env_token = os.environ.get(ENV_VAR)
    if env_token:
        return env_token
    cfg_token = (config.get("auth") or {}).get("token")
    if cfg_token:
        return cfg_token
    return None


def redact_token(token: str | None) -> str:
    """Return a display-safe form of the token: `first4…last4`.

    Tokens shorter than 8 characters are fully redacted to avoid leaking
    a significant fraction of the secret.
    """
    if not token:
        return ""
    if len(token) < 8:
        return "…"
    return f"{token[:4]}…{token[-4:]}"


def decode_jwt_exp(token: str | None) -> int | None:
    """Extract the `exp` claim (unix seconds) from a JWT payload.

    Returns None for anything that isn't a parseable JWT with an integer
    `exp` claim: opaque tokens, malformed base64, bad JSON, missing claim.
    Never raises.
    """
    if not token:
        return None
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # base64url padding: len must be a multiple of 4
        padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes)
        exp = payload.get("exp")
        if isinstance(exp, int):
            return exp
        return None
    except Exception:
        return None


def warn_on_expiry(token: str | None, warn_window_seconds: int = 600) -> str | None:
    """Return a warning message if the token is expired or expiring soon.

    Returns None when the token is opaque, valid, or has no `exp` claim.
    The caller decides how to present the warning (print, log, etc.).
    """
    exp = decode_jwt_exp(token)
    if exp is None:
        return None
    now = int(time.time())
    if exp <= now:
        return f"Token expired {now - exp} seconds ago"
    remaining = exp - now
    if remaining <= warn_window_seconds:
        return f"Token expires in {remaining} seconds"
    return None


def should_send_auth(
    original_scheme: str, original_netloc: str, next_url: str
) -> bool:
    """Decide whether the Authorization header is safe to send to next_url.

    Returns True iff next_url has the same (scheme, hostname, port) as the
    original target. Default ports are resolved so `http://example.com` and
    `http://example.com:80` are treated as the same origin.

    This is used by the spider's manual redirect loop to prevent leaking
    bearer tokens to third-party hosts on cross-origin redirects.
    """
    if not next_url:
        return False
    try:
        orig = urlparse(f"{original_scheme}://{original_netloc}")
        nxt = urlparse(next_url)
        if not nxt.scheme or not nxt.hostname:
            return False
        orig_port = orig.port or _DEFAULT_PORTS.get(orig.scheme)
        nxt_port = nxt.port or _DEFAULT_PORTS.get(nxt.scheme)
        return (
            orig.scheme == nxt.scheme
            and (orig.hostname or "").lower() == (nxt.hostname or "").lower()
            and orig_port == nxt_port
        )
    except Exception:
        return False
