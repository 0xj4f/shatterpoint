"""
Authentication helpers for shatterpoint.

Pure functions for:
  - resolving a bearer token with CLI > env > config precedence
  - resolving arbitrary `-H "Name: value"` auth headers (covers Basic,
    Bearer, Digest, NTLM/Negotiate, API keys, Cookie, custom schemes)
  - redacting tokens / header values for safe display in logs/reports
  - decoding the `exp` claim from JWTs (best-effort)
  - warning when a JWT is expired or expiring soon
  - deciding whether auth material is safe to send to a given URL
    (used for redirect-strip logic so credentials never leak off-origin)
  - building an httpx request hook that strips every auth header when a
    request leaves the target origin (cross-origin redirect protection)

None of these helpers make network calls. None raise on bad input —
opaque or malformed tokens return None from the decode helpers so the
caller can treat the token as an opaque bearer.
"""

import base64
import json
import os
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    import httpx

ENV_VAR = "SHATTERPOINT_TOKEN"
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Authorization schemes whose credential we redact while keeping the
# scheme word visible (so "Bearer eyJ…" shows the scheme but not the secret).
_AUTH_SCHEMES = ("bearer", "basic", "digest", "negotiate", "ntlm", "token", "apikey")


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


def make_auth_strip_hook(
    scheme: str, netloc: str, auth_header_names: set[str]
):
    """Build an httpx request event hook that strips auth headers when a
    request leaves the target origin (e.g. a cross-origin redirect that
    httpx follows). httpx auto-strips `Authorization` cross-origin but NOT
    custom headers (X-API-Key, Cookie, ...), so this covers every -H header
    uniformly — matching the spider's per-hop origin scoping. Reuses
    `should_send_auth` for the origin check.
    """
    lowered = {n.lower() for n in auth_header_names}

    async def _strip(request: "httpx.Request") -> None:
        if not should_send_auth(scheme, netloc, str(request.url)):
            for hname in list(request.headers.keys()):
                if hname.lower() in lowered:
                    del request.headers[hname]

    return _strip


# ─── Arbitrary auth headers (-H "Name: value") ────────────────────────


def parse_header(raw: str) -> tuple[str, str] | None:
    """Parse a `-H "Name: value"` string into (name, value).

    Splits on the first colon (values may contain colons, e.g. a URL or
    `Bearer x:y`). Returns None if the input has no colon or an empty
    name, so the caller can warn on malformed input. The value may be
    empty (some headers are sent bare).
    """
    if not raw or ":" not in raw:
        return None
    name, _, value = raw.partition(":")
    name = name.strip()
    if not name:
        return None
    return name, value.strip()


def _set_ci(headers: dict, name: str, value: str) -> None:
    """Set headers[name]=value, replacing any existing key that matches
    case-insensitively (HTTP header names are case-insensitive)."""
    for existing in [h for h in headers if h.lower() == name.lower()]:
        headers.pop(existing)
    headers[name] = value


def resolve_headers(
    cli_headers: list[str] | None, config: dict
) -> tuple[dict[str, str], list[str]]:
    """Resolve arbitrary auth headers from CLI `-H` + config['auth']['headers'].

    Precedence: CLI `-H` overrides config on a case-insensitive name match.
    Returns (headers, errors) where `errors` lists the malformed `-H`
    strings so the caller can warn. Never raises.
    """
    headers: dict[str, str] = {}
    cfg = (config.get("auth") or {}).get("headers") or {}
    if isinstance(cfg, dict):
        for k, v in cfg.items():
            if k and v is not None:
                _set_ci(headers, str(k), str(v))

    errors: list[str] = []
    for raw in cli_headers or []:
        parsed = parse_header(raw)
        if parsed is None:
            errors.append(raw)
            continue
        _set_ci(headers, parsed[0], parsed[1])
    return headers, errors


def build_auth_headers(
    token: str | None, custom_headers: dict[str, str] | None
) -> dict[str, str]:
    """Combine the `--token` bearer header with arbitrary `-H` headers.

    The bearer token sets `Authorization: Bearer <token>` first; an
    explicit `-H "Authorization: ..."` then overrides it (the general
    mechanism wins over the convenience flag). Returns the full header
    dict applied to authenticated requests.
    """
    out: dict[str, str] = {}
    if token:
        out["Authorization"] = f"Bearer {token}"
    for name, value in (custom_headers or {}).items():
        _set_ci(out, name, value)
    return out


def redact_header_value(name: str, value: str) -> str:
    """Redact a header value for safe display, keeping an auth scheme word.

    "Bearer eyJ…xyz"  -> "Bearer eyJh…xyz9"  (scheme kept, credential redacted)
    "abc123secretkey" -> "abc1…tkey"          (whole value redacted)
    """
    if not value:
        return ""
    scheme, _, cred = value.partition(" ")
    if cred and scheme.lower() in _AUTH_SCHEMES:
        return f"{scheme} {redact_token(cred)}"
    return redact_token(value)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return {name: redacted_value} for banner/report display."""
    return {name: redact_header_value(name, value) for name, value in headers.items()}
