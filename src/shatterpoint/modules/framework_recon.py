"""
Framework deep recon — CVE signal detection.

When a supported framework is identified in the earlier fingerprint
phases, this module runs a framework-specific path-probe sweep that
goes beyond the generic /admin, /login, /backup list. The goal is to
surface the exposures that map to known framework RCEs/critical CVEs.

SIGNAL-ONLY, NEVER EXPLOIT. Every probe is a GET with no payload. We
detect that a vulnerable endpoint / debug surface is *present*; we
never send an exploit, an auth-bypass header, or a SpEL/SSTI/JNDI
payload. CVEs that can only be confirmed by sending a crafted request
(Spring4Shell, Log4Shell, Jinja2 SSTI, Next.js middleware bypass,
Laravel env-manipulation) are surfaced as `_MANUAL_POINTERS`, never
auto-probed.

PRECISION FIRST. A bare HTTP 200 is not a signal — many servers return
200 for everything (catch-all routers). Probes that would otherwise
false-positive carry a `confirm_any` content gate: the response body
MUST contain one of those markers for the finding to count. This is
what keeps `/console`, `/admin/`, and the `/actuator/*` family from
firing on unrelated apps.

CVE DISPOSITION. Findings map to their CVE with a "verify manually"
disposition. The tool NEVER asserts "you are vulnerable" — version
gating and exploit conditions can't be confirmed without exploitation,
and a false "vulnerable" claim is the worst precision failure.

Mirrors the SPAAnalyzer pattern: passive detection runs every scan;
mining is opt-in via --framework-recon or config.framework_recon.enabled;
results live in results["framework_recon"]; the 404-baseline filter
keeps catch-all routers from poisoning the findings.
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
    """A single framework-aware GET probe.

    confirm_any: when the response is 200, the body must contain one of
        these (case-insensitive) markers for the finding to count.
        Empty tuple = no content gate (status code alone is the signal).
        Non-200 signal codes (301/302/401/403) bypass the gate — they
        indicate the route exists even when we can't read the body.
    escalate_any / escalate_cve / escalate_note: when the body contains
        one of `escalate_any`, the finding's CVE + note are upgraded
        (e.g. a reachable .env is critical; a .env that *contains*
        APP_KEY escalates to the CVE-2018-15133 deserialization chain).
    """

    path: str
    severity: str                          # "critical" | "high" | "medium" | "info"
    note: str
    cve: str | None = None
    confirm_any: tuple[str, ...] = ()
    escalate_any: tuple[str, ...] = ()
    escalate_cve: str | None = None
    escalate_note: str | None = None


# Shared escalation note for Laravel env files that leak APP_KEY.
_ENV_APPKEY_ESCALATE = (
    "Laravel env exposed WITH APP_KEY — CVE-2018-15133 deserialization RCE "
    "candidate (AndroxGh0st vector); verify cookie/session serialization & test manually"
)
_ENV_ESCALATE_MARKERS = ("app_key=base64:", "app_key=")


# ── Laravel ────────────────────────────────────────────────────────────
_LARAVEL_PROBES: list[Probe] = [
    # Ignition (CVE-2021-3129 RCE chain)
    Probe("/_ignition/health-check", "critical",
          "Ignition debug handler exposed — CVE-2021-3129 RCE chain when version-vulnerable; "
          "verify facade/ignition < 2.5.2 + APP_DEBUG=true & test manually",
          cve="CVE-2021-3129"),
    Probe("/_ignition/execute-solution", "critical",
          "Ignition solution endpoint reachable — CVE-2021-3129 RCE route "
          "(GET-only probe, no payload sent); verify & test manually",
          cve="CVE-2021-3129"),
    # Debug panels
    Probe("/telescope", "high",
          "Laravel Telescope debug panel — full request / query / exception log",
          confirm_any=("telescope", "laravel telescope")),
    Probe("/horizon", "high",
          "Laravel Horizon queue dashboard — job inspection + tenant exposure",
          confirm_any=("horizon", "laravel horizon")),
    Probe("/log-viewer", "high",
          "rap2hpoutre/laravel-log-viewer — full Laravel logs in browser",
          confirm_any=("log-viewer", "laravel.log", "log viewer")),
    Probe("/storage/logs/laravel.log", "high",
          "Raw Laravel log file (web-exposed misconfig)"),
    # Env / config leaks — escalate to CVE-2018-15133 when APP_KEY present
    Probe("/.env", "critical",
          "Laravel env file — DB credentials, APP_KEY, mail SMTP, AWS keys",
          escalate_any=_ENV_ESCALATE_MARKERS, escalate_cve="CVE-2018-15133",
          escalate_note=_ENV_APPKEY_ESCALATE),
    Probe("/.env.bak", "critical", "Backup of Laravel env file",
          escalate_any=_ENV_ESCALATE_MARKERS, escalate_cve="CVE-2018-15133",
          escalate_note=_ENV_APPKEY_ESCALATE),
    Probe("/.env.production", "critical", "Production Laravel env file",
          escalate_any=_ENV_ESCALATE_MARKERS, escalate_cve="CVE-2018-15133",
          escalate_note=_ENV_APPKEY_ESCALATE),
    Probe("/.env.local", "critical", "Local Laravel env file",
          escalate_any=_ENV_ESCALATE_MARKERS, escalate_cve="CVE-2018-15133",
          escalate_note=_ENV_APPKEY_ESCALATE),
    Probe("/.env.example", "info", "Laravel env template (usually safe; confirms install)"),
    # Project markers
    Probe("/composer.lock", "high",
          "Composer lock — exact Laravel + dependency versions for CVE lookup",
          confirm_any=("packages", "laravel/framework", "content-hash")),
    Probe("/composer.json", "medium",
          "Composer manifest — dependency list (version intel)",
          confirm_any=("require", "laravel/framework", "autoload")),
    Probe("/artisan", "medium", "Laravel CLI entry point (should not be web-accessible)"),
    Probe("/server.php", "medium", "Laravel dev server entry point"),
    # API / auth scaffolding
    Probe("/api/user", "info", "Sanctum / Passport authenticated user endpoint"),
    Probe("/sanctum/csrf-cookie", "info", "Confirms Laravel Sanctum is installed"),
    Probe("/livewire/livewire.js", "info",
          "Confirms Livewire is installed (extra attack surface)",
          confirm_any=("livewire", "window.livewire")),
]


# ── Django ─────────────────────────────────────────────────────────────
_DJANGO_PROBES: list[Probe] = [
    Probe("/admin/", "high",
          "Django admin login exposed — credential/brute-force surface",
          confirm_any=("django administration", "id=\"login-form\"", "csrfmiddlewaretoken")),
    Probe("/static/admin/css/base.css", "medium",
          "Django admin static assets served — confirms admin app installed",
          confirm_any=("djangoproject", "#admin", "body", "var(--")),
    Probe("/__debug__/", "medium",
          "Django Debug Toolbar exposed — SQL queries, settings, request internals",
          confirm_any=("djdebug", "django-debug-toolbar", "djdt")),
    Probe("/api/", "info",
          "Django REST Framework browsable API — enumerate endpoints",
          confirm_any=("django rest framework", "djangorestframework", "api root")),
]


# ── Flask / Werkzeug ───────────────────────────────────────────────────
_FLASK_PROBES: list[Probe] = [
    Probe("/console", "critical",
          "Werkzeug interactive debugger console reachable — CVE-2024-34069 / classic "
          "console RCE (PIN-gated unless disabled); verify & test manually",
          cve="CVE-2024-34069",
          confirm_any=("werkzeug", "__debugger__", "evalex", "console.png", "the console")),
]


# ── Spring Boot ────────────────────────────────────────────────────────
_SPRINGBOOT_PROBES: list[Probe] = [
    Probe("/actuator", "info",
          "Spring Boot Actuator index exposed — enumerate sub-endpoints",
          confirm_any=("_links", "\"actuator\"", "self")),
    Probe("/actuator/heapdump", "critical",
          "Actuator heap dump downloadable — full JVM memory (plaintext passwords, "
          "tokens, live session cookies); analyse with Eclipse MAT / VisualVM",
          confirm_any=("java profile",)),   # hprof magic header — binary-safe, zero false positive
    Probe("/actuator/gateway/routes", "critical",
          "Spring Cloud Gateway routes endpoint reachable — CVE-2022-22947 SpEL "
          "injection RCE; verify Gateway < 3.1.1 / 3.0.7 & test manually",
          cve="CVE-2022-22947",
          confirm_any=("route_id", "predicate", "\"uri\"", "filters")),
    Probe("/actuator/env", "high",
          "Actuator env endpoint — full config + (masked) secrets; values often "
          "reconstructable via /actuator/env/{property}",
          confirm_any=("propertysources", "activeprofiles", "systemproperties")),
    Probe("/actuator/jolokia", "high",
          "Jolokia JMX-over-HTTP exposed — MBean access can chain to RCE "
          "(e.g. logback reloadByURL → XXE/RCE); verify & test manually",
          confirm_any=("\"agent\"", "jolokia", "\"request\"")),
    Probe("/actuator/mappings", "medium",
          "Actuator mappings — full route map (hidden endpoints)",
          confirm_any=("dispatcherservlet", "\"mappings\"", "handler")),
    Probe("/actuator/threaddump", "medium",
          "Actuator thread dump — stack traces, internal class names",
          confirm_any=("threads", "threadname", "stacktrace")),
    Probe("/actuator/configprops", "medium",
          "Actuator configprops — bound configuration properties",
          confirm_any=("contexts", "\"beans\"", "prefix")),
]


# ── Voyager (Laravel admin package) ────────────────────────────────────
# The profile only runs once the `voyager` fingerprint has matched, so a
# 302-to-login on these Voyager-unique routes is still a real signal
# (stock Laravel has no /admin/compass or /admin/media route at all).
_VOYAGER_PROBES: list[Probe] = [
    Probe("/admin/compass", "high",
          "Voyager Compass endpoint — CVE-2024-55415 path traversal (arbitrary file "
          "read/delete) + CVE-2024-55416 reflected XSS; verify Voyager <= 1.8.0 & test manually",
          cve="CVE-2024-55415",
          confirm_any=("voyager", "compass")),
    Probe("/admin/media", "critical",
          "Voyager media manager — CVE-2024-55417 arbitrary file upload → RCE "
          "(authenticated, file-type check bypassable); verify Voyager <= 1.8.0 & test manually",
          cve="CVE-2024-55417",
          confirm_any=("voyager", "media")),
    Probe("/admin/login", "info",
          "Voyager admin login panel — credential/brute-force surface",
          confirm_any=("voyager",)),
]


# ── Innoshop (Laravel e-commerce app) ──────────────────────────────────
# The CVE-2025-52921 File Manager RCE is authenticated and lives in the
# admin panel; the exact endpoint is verified in-app. Detection here is
# "Innoshop is present" (via the fingerprint), with the CVE surfaced as a
# manual pointer rather than a fabricated endpoint probe (precision).
_INNOSHOP_PROBES: list[Probe] = []


# ── Next.js (server-side React) ────────────────────────────────────────
_NEXTJS_PROBES: list[Probe] = [
    Probe("/api/auth/providers", "info",
          "NextAuth.js providers endpoint — enumerate configured auth providers",
          confirm_any=("oauth", "credentials", "\"signinurl\"", "\"callbackurl\"")),
    Probe("/api/auth/session", "info",
          "NextAuth.js session endpoint — confirms NextAuth in use",
          confirm_any=("user", "expires", "{}")),
]


# ── Jenkins / GitLab (fingerprint-only CVEs — non-GET vectors) ──────────
# Their flagship CVEs are NOT passive GET signals (Jenkins CLI file-read;
# GitLab image-upload POST), so there are no probes — detection is "product
# present" via the fingerprint, with the CVE surfaced as a manual pointer.
_JENKINS_PROBES: list[Probe] = []
_GITLAB_PROBES: list[Probe] = []


_PROFILES: dict[str, list[Probe]] = {
    "laravel": _LARAVEL_PROBES,
    "django": _DJANGO_PROBES,
    "flask": _FLASK_PROBES,
    "springboot": _SPRINGBOOT_PROBES,
    "nextjs": _NEXTJS_PROBES,
    "voyager": _VOYAGER_PROBES,
    "innoshop": _INNOSHOP_PROBES,
    "jenkins": _JENKINS_PROBES,
    "gitlab": _GITLAB_PROBES,
}


# CVEs / vuln classes that CANNOT be confirmed without sending a payload.
# We surface these as guidance so the operator knows what to test by
# hand — we never auto-probe them (that would be exploitation).
_MANUAL_POINTERS: dict[str, tuple[str, ...]] = {
    "laravel": (
        "CVE-2024-52301 (env manipulation via register_argc_argv) — needs a crafted "
        "?--env= query string; test manually.",
    ),
    "django": (
        "DEBUG=True → SECRET_KEY / settings leak → pickle-session RCE when "
        "SESSION_SERIALIZER=PickleSerializer; verify serializer manually.",
        "ORM SQLi (CVE-2024-42005, CVE-2025-57833, CVE-2025-64459) — code-level; "
        "Django version is not exposed by default, so not recon-detectable.",
    ),
    "flask": (
        "Jinja2 SSTI → RCE — needs a template-injection payload in a reflected "
        "input; test manually.",
    ),
    "springboot": (
        "Spring4Shell CVE-2022-22965 — data-binding RCE; needs a payload. Test if "
        "running Spring MVC on Tomcat + JDK 9+ (WAR deploy).",
        "Log4Shell CVE-2021-44228 — needs a JNDI payload + outbound callback; test manually.",
        "Spring Cloud Function CVE-2022-22963 — needs a crafted POST routing header; test manually.",
    ),
    "nextjs": (
        "CVE-2025-29927 middleware auth bypass — confirmation needs the "
        "x-middleware-subrequest header (active; NOT auto-sent). Vulnerable if "
        "Next.js < 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3.",
        "Run shatterpoint with --spa for bundle / source-map / baked-secret mining "
        "of the React/Next client.",
    ),
    "voyager": (
        "CVE-2024-55415 + CVE-2024-55416 + CVE-2024-55417 chain → one-click RCE on "
        "Voyager <= 1.8.0: trick an authed admin into a malicious /admin/compass link "
        "(XSS) to drive a media upload (web shell). Authenticated; verify version & "
        "test manually. No patch as of disclosure.",
    ),
    "innoshop": (
        "CVE-2025-52921 (CVSS 9.9) — Innoshop <= 0.4.1 admin File Manager RCE: upload a "
        "file then rename it to .php (frontend-only validation, bypass in Burp), then GET "
        "it. Authenticated; verify in the admin panel & test manually.",
    ),
    "jenkins": (
        "CVE-2024-23897 (CVSS 9.8) — Jenkins <= 2.441 / LTS <= 2.426.2 arbitrary file read "
        "via the built-in CLI '@<path>' argument expansion (unauthenticated reads the first "
        "line; full read with Overall/Read). Chains to RCE (decrypt secrets, resource-root "
        "deserialization). CLI/websocket vector — not an HTTP GET; test manually.",
    ),
    "gitlab": (
        "CVE-2021-22205 (CVSS 10.0) — GitLab CE/EE 11.9 to < 13.8.8 / 13.9.6 / 13.10.3 "
        "unauthenticated RCE: a crafted uploaded image reaches a vulnerable ExifTool "
        "(CVE-2021-22204). POST upload vector — not an HTTP GET; test manually.",
    ),
}


@dataclass
class ProbeResult:
    """Outcome of a single framework probe."""

    path: str
    url: str
    status_code: int
    severity: str
    note: str
    cve: str | None = None
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
        return present

    async def analyze(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        detected_techs: list[dict],
    ) -> dict:
        """Main entry point. Returns the `framework_recon` result block.

        `detected_frameworks` is always populated (so the "rerun with
        --framework-recon" hint can fire even when mining is disabled).
        `frameworks_probed`, `probes`, and `manual_pointers` populate
        only when mining ran.
        """
        result: dict = {
            "ran": False,
            "detected_frameworks": [],
            "frameworks_probed": [],
            "probes": [],
            "manual_pointers": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "info": 0},
        }

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
                self._print_finding(framework_id, outcome)

            # Surface manual-test guidance for CVEs we deliberately don't probe.
            pointers = _MANUAL_POINTERS.get(framework_id, ())
            if pointers:
                result["manual_pointers"][framework_id] = list(pointers)
                for pointer in pointers:
                    print_finding(f"{framework_id.title()} (manual)", pointer)

        if baseline_drops:
            print_status(
                f"Framework recon: dropped {baseline_drops} probe(s) "
                "(404 baseline or content-confirm gate)"
            )

        return result

    async def _run_probe(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        probe: Probe,
        baseline,
    ) -> ProbeResult | None:
        """Issue one GET probe. Returns None when the response is not a
        real signal (matches 404 baseline, uninteresting status, or
        fails the content-confirm gate)."""
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
                severity=probe.severity, note=probe.note, cve=probe.cve,
                fetch_error="timeout",
            )
        except Exception as e:
            return ProbeResult(
                path=probe.path, url=url, status_code=0,
                severity=probe.severity, note=probe.note, cve=probe.cve,
                fetch_error=str(e)[:100],
            )

        body = response.text or ""
        body_lower = body.lower()

        # Catch-all baseline filter — only meaningful on 200s.
        if response.status_code == 200 and baseline.matches(response.status_code, body):
            return None

        # Only report status codes that meaningfully indicate presence.
        if response.status_code not in (200, 301, 302, 307, 308, 401, 403):
            return None

        # Content-confirm gate: a 200 that lacks every marker is NOT the
        # framework-specific resource (precision guard). Non-200 signal
        # codes bypass the gate — the route clearly exists.
        if response.status_code == 200 and probe.confirm_any:
            if not any(marker.lower() in body_lower for marker in probe.confirm_any):
                return None

        # Escalation: reachable resource whose body proves a worse finding.
        cve = probe.cve
        note = probe.note
        if probe.escalate_any and any(m.lower() in body_lower for m in probe.escalate_any):
            cve = probe.escalate_cve or cve
            note = probe.escalate_note or note

        return ProbeResult(
            path=probe.path,
            url=url,
            status_code=response.status_code,
            severity=probe.severity,
            note=note,
            cve=cve,
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
        cve_tag = f" {outcome.cve}" if outcome.cve else ""
        print_finding(
            f"{framework_id.title()} Recon",
            f"{sev_marker} [{outcome.status_code}] {outcome.path}{suffix}{cve_tag} — {outcome.note}",
        )
