"""
Content-baseline helper for path probing.

Many modern applications (especially SPA dev servers and Next.js
catch-all routers) return HTTP 200 with the same body for every URL,
including paths that don't exist. Without a baseline check, every
path probe "succeeds" and Phase 1.5 misclassifies a single React shell
as WordPress, Drupal, Joomla, Tomcat, and Apache simultaneously.

This module fetches a deliberately-random path at the start of a probe
batch and records `(status_code, body_hash, body_length)`. Probes whose
response matches the baseline are treated as "not really found" and
skipped, regardless of HTTP status.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx


@dataclass(frozen=True)
class Baseline:
    """Snapshot of how the target responds to a known-bogus path."""

    available: bool        # False if the baseline fetch itself failed
    status_code: int
    body_hash: str         # sha256 of response body
    body_length: int

    def matches(self, status_code: int, body: str) -> bool:
        """Return True if the given response looks like the baseline.

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


async def fetch_baseline(client: httpx.AsyncClient, base_url: str) -> Baseline:
    """Fetch a deliberately-random path and snapshot the response.

    Uses a 32-char random hex segment under `/__shatterpoint_baseline_<token>__`
    to make accidental collisions with real application paths effectively
    impossible. Returns Baseline(available=False) if the request fails so
    callers can degrade gracefully (skip the de-noising and accept the
    pre-fix behaviour).
    """
    token = secrets.token_hex(16)
    probe_url = f"{base_url.rstrip('/')}/__shatterpoint_baseline_{token}__"
    try:
        import httpx as _httpx  # local import keeps this module test-friendly
        response = await client.get(
            probe_url,
            follow_redirects=True,
            timeout=_httpx.Timeout(8),
        )
    except Exception:
        return Baseline(available=False, status_code=0, body_hash="", body_length=0)
    body = response.text or ""
    body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    return Baseline(
        available=True,
        status_code=response.status_code,
        body_hash=body_hash,
        body_length=len(body),
    )
