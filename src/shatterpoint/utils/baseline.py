"""
Content-baseline helper for path probing.

Many modern applications (especially SPA dev servers and Next.js
catch-all routers) return HTTP 200 with the same body for every URL,
including paths that don't exist. Without a baseline check, every
path probe "succeeds" and Phase 1.5 misclassifies a single React shell
as WordPress, Drupal, Joomla, Tomcat, and Apache simultaneously.

This module fetches a deliberately-random path at the start of a probe
batch and records two catch-all signatures:

  1. **Content baseline** — `(status_code, body_hash, body_length)` for
     servers that return HTTP 200 with the same body for every URL
     (SPA dev servers, Next.js fallback). Probes whose body matches are
     dropped.
  2. **Redirect baseline** — the location a bogus path 3xx-redirects to
     (e.g. GitLab sends every unknown path → `/users/sign_in`). Probes
     that 3xx to the *same* place are the app's "everything → login"
     handler, not real findings, so they're dropped too. Without this,
     a profile that fired by mistake would emit a flood of critical
     "findings" (observed live: the Laravel profile producing 20 bogus
     `/.env`, `/_ignition/*` hits on a GitLab target).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    import httpx

_REDIRECT_CODES = (301, 302, 303, 307, 308)


def _loc_path(location: str | None) -> str | None:
    """Normalise a Location header to its path component, so an absolute
    (`http://h/users/sign_in`) and a relative (`/users/sign_in`) redirect
    compare equal."""
    if not location:
        return None
    try:
        return urlparse(location).path or location
    except Exception:
        return location


@dataclass(frozen=True)
class Baseline:
    """Snapshot of how the target responds to a known-bogus path."""

    available: bool        # False if the baseline fetch itself failed
    status_code: int
    body_hash: str         # sha256 of response body
    body_length: int
    redirect_location: str | None = None   # path a bogus 3xx redirects to

    def matches(self, status_code: int, body: str) -> bool:
        """Return True if the given response looks like the content baseline.

        Match heuristic:
          - Identical body hash (exact catch-all router behaviour), OR
          - Same status code AND body length within ±5% of baseline
            (handles tiny timestamp/CSRF token variation in otherwise
            identical responses).
        """
        if not self.available:
            return False
        if not body:
            return status_code == self.status_code and self.body_length == 0
        candidate_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
        if candidate_hash == self.body_hash:
            return True
        if status_code == self.status_code and self.body_length > 0:
            ratio = abs(len(body) - self.body_length) / self.body_length
            if ratio < 0.05:
                return True
        return False

    def is_catchall_redirect(self, status_code: int, location: str | None) -> bool:
        """True if this 3xx goes to the same place a bogus path does —
        i.e. the app's catch-all "→ login" handler, not a real finding."""
        if not self.available or not self.redirect_location:
            return False
        if status_code not in _REDIRECT_CODES:
            return False
        return _loc_path(location) == self.redirect_location


async def fetch_baseline(client: httpx.AsyncClient, base_url: str) -> Baseline:
    """Fetch a deliberately-random path and snapshot the response.

    Uses a 32-char random hex segment under `/__shatterpoint_baseline_<token>__`
    to make accidental collisions with real application paths effectively
    impossible. Captures both the content baseline and the redirect
    baseline. Returns Baseline(available=False) if the request fails so
    callers degrade gracefully.
    """
    token = secrets.token_hex(16)
    probe_url = f"{base_url.rstrip('/')}/__shatterpoint_baseline_{token}__"
    import httpx as _httpx  # local import keeps this module test-friendly
    try:
        # First hop WITHOUT following — reveals a catch-all 3xx location.
        immediate = await client.get(
            probe_url, follow_redirects=False, timeout=_httpx.Timeout(8),
        )
    except Exception:
        return Baseline(available=False, status_code=0, body_hash="", body_length=0)

    redirect_location = None
    if immediate.status_code in _REDIRECT_CODES:
        redirect_location = _loc_path(immediate.headers.get("location"))
        # Also follow to capture the final body, so the content-baseline
        # still works for callers that follow redirects (fingerprint probes).
        try:
            followed = await client.get(
                probe_url, follow_redirects=True, timeout=_httpx.Timeout(8),
            )
            body = followed.text or ""
            status = followed.status_code
        except Exception:
            body, status = "", immediate.status_code
    else:
        body = immediate.text or ""
        status = immediate.status_code

    body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    return Baseline(
        available=True,
        status_code=status,
        body_hash=body_hash,
        body_length=len(body),
        redirect_location=redirect_location,
    )
