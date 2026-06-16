"""
Framework deep recon.

When a supported framework is identified in the earlier fingerprint
phases, this module runs a framework-specific path-probe sweep that
goes beyond the generic /admin, /login, /backup list. The goal is to
surface the exposures that matter for that specific framework's
typical misconfigurations.

v1 supports Laravel only. Adding a new framework is purely additive:
add an entry to `_PROFILES` mapping the fingerprint id to a probe list,
and the existing orchestration handles the rest.

Mirrors the SPAAnalyzer pattern:
  - passive detection runs every scan (via the existing fingerprinter)
  - mining is opt-in via --framework-recon or
    config.framework_recon.enabled=true
  - results live in their own `results["framework_recon"]` block
  - the 404-baseline filter from utils.baseline keeps catch-all
    routers from poisoning the findings

Per project direction: **no CVE numbers in output.** We say "Ignition
debug handler exposed" and stop. The operator looks up the exposure
against their own knowledge / tooling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from shatterpoint.utils.baseline import fetch_baseline
from shatterpoint.utils.formatter import print_finding, print_status

if TYPE_CHECKING:
    from shatterpoint.utils.validator import URLValidator


@dataclass(frozen=True)
class Probe:
    """A single framework-aware path probe."""

    path: str
    severity: str       # "critical", "high", "medium", "info"
    note: str           # Human-readable why-it-matters string


# Laravel probe profile. Severity reflects the worst-case impact when
# the probe returns 200 (or 301/302 to something accessible). The
# operator decides what to do next.
_LARAVEL_PROBES: list[Probe] = [
    # ── Ignition / debug handlers ──
    Probe("/_ignition/health-check", "critical",
          "Ignition debug handler exposed — known RCE chain when version-vulnerable"),
    Probe("/_ignition/execute-solution", "critical",
          "Ignition RCE endpoint reachable (probe is GET-only, no payload sent)"),
    # ── Debug panels ──
    Probe("/telescope", "high",
          "Laravel Telescope debug panel — full request / query / exception log"),
    Probe("/horizon", "high",
          "Laravel Horizon queue dashboard — job inspection + tenant exposure"),
    Probe("/log-viewer", "high",
          "rap2hpoutre/laravel-log-viewer — full Laravel logs in browser"),
    Probe("/storage/logs/laravel.log", "high",
          "Raw Laravel log file (web-exposed misconfig)"),
    # ── Config / env leaks ──
    Probe("/.env", "critical",
          "Laravel env file — DB credentials, APP_KEY, mail SMTP, AWS keys"),
    Probe("/.env.bak", "critical", "Backup of Laravel env file"),
    Probe("/.env.example", "info", "Laravel env template (usually safe; confirms install)"),
    Probe("/.env.production", "critical", "Production Laravel env file"),
    Probe("/.env.local", "critical", "Local Laravel env file"),
    # ── Project markers ──
    Probe("/composer.json", "medium",
          "Composer manifest — dependency list (version intel)"),
    Probe("/composer.lock", "high",
          "Composer lock — exact Laravel + dependency versions for CVE lookup"),
    Probe("/artisan", "medium", "Laravel CLI entry point (should not be web-accessible)"),
    Probe("/server.php", "medium", "Laravel dev server entry point"),
    Probe("/package.json", "info", "Node package manifest if Mix/Vite is used"),
    # ── API / auth scaffolding ──
    Probe("/api/user", "info", "Sanctum / Passport authenticated user endpoint"),
    Probe("/sanctum/csrf-cookie", "info", "Confirms Laravel Sanctum is installed"),
    Probe("/livewire/livewire.js", "info", "Confirms Livewire is installed (extra attack surface)"),
]


_PROFILES: dict[str, list[Probe]] = {
    "laravel": _LARAVEL_PROBES,
}


@dataclass
class ProbeResult:
    """Outcome of a single framework probe."""

    path: str
    url: str
    status_code: int
    severity: str
    note: str
    content_length: int = 0
    redirect_to: str | None = None
    fetch_error: str | None = None


class FrameworkRecon:
    """Orchestrates framework-aware deep recon. Thin glue over the
    framework profiles, the existing baseline filter, and the shared
    httpx client. Mirrors SPAAnalyzer.should_run / analyze shape."""

    def __init__(self, config: dict, validator: URLValidator):
        cfg = config.get("framework_recon") or {}
        self.enabled: bool = bool(cfg.get("enabled", False))
        self.auto_when_detected: bool = bool(cfg.get("auto_when_detected", False))
        self.timeout: int = int(cfg.get("timeout", 8))
        self.validator = validator

    def should_run(self, detected_techs: list[dict]) -> list[str]:
        """Return the list of framework IDs to deep-recon, or []."""
        if not self.enabled and not self.auto_when_detected:
            return []
        present: list[str] = []
        for tech in detected_techs or []:
            tid = (tech.get("id") or "").lower()
            if tid in _PROFILES and tid not in present:
                present.append(tid)
        # If `enabled` is set, always run for any supported framework
        # that's present. If only `auto_when_detected`, same behaviour —
        # both flags share the "run when present" semantics.
        return present

    async def analyze(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        detected_techs: list[dict],
    ) -> dict:
        """Main entry point. Returns the `framework_recon` result block.

        The block always contains `detected_frameworks` so the operator
        sees which supported frameworks were found, even when mining
        was disabled (so the "rerun with --framework-recon" hint can
        fire). `frameworks_probed` only populates when mining ran.
        """
        result: dict = {
            "ran": False,
            "detected_frameworks": [],
            "frameworks_probed": [],
            "probes": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "info": 0},
        }

        # Always compute what we COULD probe, so the hint check can fire
        # even when mining is disabled.
        targets: list[str] = []
        for tech in detected_techs or []:
            tid = (tech.get("id") or "").lower()
            if tid in _PROFILES and tid not in targets:
                targets.append(tid)
        result["detected_frameworks"] = targets

        if not (self.enabled or self.auto_when_detected) or not targets:
            return result

        result["ran"] = True
        result["frameworks_probed"] = targets
        print_status(f"Framework recon: probing profiles → {', '.join(targets)}")

        baseline = await fetch_baseline(client, base_url)
        if baseline.available:
            print_status(
                f"Framework-recon baseline: status={baseline.status_code}, "
                f"len={baseline.body_length}"
            )

        baseline_drops = 0
        probed_paths: set[str] = set()

        for framework_id in targets:
            for probe in _PROFILES[framework_id]:
                if probe.path in probed_paths:
                    continue
                probed_paths.add(probe.path)
                outcome = await self._run_probe(client, base_url, probe, baseline)
                if outcome is None:
                    baseline_drops += 1
                    continue
                result["probes"].append(outcome.__dict__)
                if outcome.severity in result["summary"]:
                    result["summary"][outcome.severity] += 1
                # Surface findings live, severity-prefixed
                self._print_finding(framework_id, outcome)

        if baseline_drops:
            print_status(
                f"Framework recon: dropped {baseline_drops} probe(s) matching the 404 baseline"
            )

        return result

    async def _run_probe(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        probe: Probe,
        baseline,
    ) -> ProbeResult | None:
        """Issue one probe. Returns None if the response matches the
        404 baseline (treated as 'not really found')."""
        url = f"{base_url.rstrip('/')}{probe.path}"
        try:
            response = await client.get(
                url,
                follow_redirects=False,
                timeout=httpx.Timeout(self.timeout),
            )
        except httpx.TimeoutException:
            return ProbeResult(
                path=probe.path, url=url, status_code=0,
                severity=probe.severity, note=probe.note,
                fetch_error="timeout",
            )
        except Exception as e:
            return ProbeResult(
                path=probe.path, url=url, status_code=0,
                severity=probe.severity, note=probe.note,
                fetch_error=str(e)[:100],
            )

        body = response.text or ""
        # Catch-all baseline filter — only meaningful on 200s where the
        # server returns its index instead of the requested resource.
        if response.status_code == 200 and baseline.matches(response.status_code, body):
            return None

        # Only report status codes that meaningfully indicate presence:
        # 200 / 301 / 302 / 307 / 308 / 401 / 403. Skip 404 + 5xx noise.
        if response.status_code not in (200, 301, 302, 307, 308, 401, 403):
            return None

        return ProbeResult(
            path=probe.path,
            url=url,
            status_code=response.status_code,
            severity=probe.severity,
            note=probe.note,
            content_length=len(body),
            redirect_to=response.headers.get("location") if response.is_redirect else None,
        )

    def _print_finding(self, framework_id: str, outcome: ProbeResult) -> None:
        """Live finding output during the recon phase."""
        sev_marker = {
            "critical": "[CRITICAL]",
            "high": "[HIGH]",
            "medium": "[MED]",
            "info": "[INFO]",
        }.get(outcome.severity, "[?]")
        suffix = ""
        if outcome.redirect_to:
            suffix = f" → {outcome.redirect_to}"
        elif outcome.content_length:
            suffix = f" ({outcome.content_length} bytes)"
        print_finding(
            f"{framework_id.title()} Recon",
            f"{sev_marker} [{outcome.status_code}] {outcome.path}{suffix} — {outcome.note}",
        )
