"""
Stack-trace miner.

Scans HTTP response bodies for stack-trace shapes (PHP/Laravel/Python/Java)
and extracts the high-value pentest intel that error pages routinely leak:

  - Whether debug mode is on (production-misconfiguration finding)
  - Framework and version (from vendor paths in the trace)
  - Filesystem install path (from absolute paths in the trace)
  - Ignition error-handler exposure (Laravel-specific)
  - Emails, internal IPs, internal hostnames, AWS IDs, DB URIs that
    only appear because the page rendered an exception

This module is pure (no network), fixture-tested, and the master entry
point `mine_response(body)` returns `{}` for pages with no stack-trace
signal so the crawler can fold it into Phase 3 cheaply.

Credentials found inside DB URIs are redacted via the existing
`redact_token` helper, preserving the leak signal without re-leaking
the secret through shatterpoint's own report.
"""

from __future__ import annotations

import re

from shatterpoint.utils.auth import redact_token

# ─── Stack-trace shape detection ──────────────────────────────────────
#
# Any of these patterns appearing in a response body means an exception
# was rendered to the client — i.e. debug mode is on.

_STACKTRACE_SHAPES = [
    re.compile(r'^#\d+\s+/', re.MULTILINE),                  # PHP / Laravel: #0 /var/www/...
    re.compile(r'\bat line \d+\b'),                          # generic "at line N"
    re.compile(r"\bin file ['\"]?[^'\"\s]+['\"]? on line \d+"),  # PHP errors
    re.compile(r'Traceback \(most recent call last\)'),       # Python
    re.compile(r'\bat [\w.$]+\([\w.]+:\d+\)'),                # Java
    re.compile(r'<title>Whoops'),                             # Laravel Whoops/Ignition page title
]

# ─── Framework markers (v1: Laravel only) ─────────────────────────────

_LARAVEL_NAMESPACES = [
    re.compile(r'\bIlluminate\\\\'),                          # double-escaped in HTML
    re.compile(r'\bIlluminate\\'),
    re.compile(r'/vendor/laravel/framework/'),
    re.compile(r'Symfony\\\\Component\\\\HttpKernel'),
    re.compile(r'Symfony\\Component\\HttpKernel'),
]

# Framework version (extracted from the vendor path's tagged dir, e.g.
# /vendor/laravel/framework/v10.4.2/...). Most Laravel installs DON'T
# version-tag the vendor dir, so this often returns None — that's fine,
# the FrameworkRecon module can probe /composer.lock as a fallback.
_LARAVEL_VERSION = re.compile(r'/vendor/laravel/framework/v?(\d+\.\d+(?:\.\d+)?)')
_PHP_VERSION = re.compile(r'PHP[/ ]v?(\d+\.\d+\.\d+)')

# ─── Other framework debug-page markers (precise, not generic) ────────
#
# These attribute a leaked error page to a framework. Markers are chosen
# to be framework-distinctive: a bare "DEBUG = True" would false-positive
# on random JS, so Django uses the exact technical-500 template phrasing
# and the django.* module namespace that only appears in real tracebacks.

_DJANGO_MARKERS = [
    re.compile(r'DEBUG = True</code>', re.IGNORECASE),         # exact technical_500 template text
    re.compile(r'Django Version', re.IGNORECASE),              # debug-page header row
    re.compile(r'\bdjango\.(?:core|db|http|urls|template|contrib|middleware)\.'),  # traceback module paths
    re.compile(r'DisallowedHost', re.IGNORECASE),
]
_DJANGO_VERSION = re.compile(r'Django Version[^0-9]{0,40}(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE | re.DOTALL)

_FLASK_MARKERS = [
    re.compile(r'Werkzeug Debugger', re.IGNORECASE),
    re.compile(r'__debugger__'),
    re.compile(r'werkzeug\.debug', re.IGNORECASE),
    re.compile(r'\bWerkzeug/\d', re.IGNORECASE),
]
_WERKZEUG_VERSION = re.compile(r'Werkzeug/(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)

_SPRING_MARKERS = [
    re.compile(r'Whitelabel Error Page', re.IGNORECASE),
    re.compile(r'\bat org\.springframework\.'),
    re.compile(r'\borg\.springframework\.\w'),
]

# ─── Ignition (Laravel debug handler) ─────────────────────────────────

_IGNITION_MARKERS = [
    re.compile(r'flareapp\.io/docs/ignition', re.IGNORECASE),
    re.compile(r'spatie/laravel-ignition', re.IGNORECASE),
    re.compile(r'facade/ignition', re.IGNORECASE),
    re.compile(r'/_ignition/[a-z_-]+', re.IGNORECASE),
]

# ─── Filesystem paths ─────────────────────────────────────────────────
#
# Absolute paths that commonly show up in stack traces. We strip trailing
# punctuation so "/var/www/html/lavita/foo.php:" becomes "/var/www/html/lavita/foo.php".

_FILESYSTEM_PATHS = [
    re.compile(r'/var/[\w./-]+'),
    re.compile(r'/home/[\w./-]+'),
    re.compile(r'/opt/[\w./-]+'),
    re.compile(r'/usr/local/[\w./-]+'),
    re.compile(r'/srv/[\w./-]+'),
    re.compile(r'[A-Z]:\\\\[\w\\\\.-]+'),                     # Windows paths in HTML (escaped backslashes)
    re.compile(r'[A-Z]:\\[\w\\.-]+'),                         # Windows paths raw
]

# When figuring out the install root, look for paths that contain one of
# these Laravel/PHP-app conventional subdirs and strip from there inward.
_INSTALL_MARKER = re.compile(r'^(.+?)/(?:vendor|public|storage|app|bootstrap|config|resources|database)(?:/|$)')

# ─── PII / leak patterns ──────────────────────────────────────────────

# RFC 1918 only — public IPs don't tell the operator anything they didn't
# already know (they connected to one).
_RFC1918 = re.compile(
    r'\b(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r')\b'
)

# Internal-looking hostnames. These TLDs / suffixes are reserved or
# conventional for non-routable services.
_INTERNAL_HOSTNAME = re.compile(
    r'\b[a-z0-9][\w-]*(?:\.[\w-]+)*\.'
    r'(?:internal|local|localdomain|lan|home|corp|intranet|svc\.cluster\.local|cluster\.local)'
    r'\b',
    re.IGNORECASE,
)

# AWS access key (long-term) — 20 chars starting AKIA, ASIA (temp), AGPA (group), AROA (role), AIPA (instance profile)
_AWS_ACCESS_KEY = re.compile(r'\b(?:AKIA|ASIA|AGPA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b')
# account-id segment may be empty (e.g. S3 bucket ARNs: arn:aws:s3:::bucket/key)
_AWS_ARN = re.compile(r'\barn:aws:[\w-]+:[\w-]*:[\w-]*:[\w/.:*-]+')
_AWS_INSTANCE_ID = re.compile(r'\bi-[0-9a-f]{8,17}\b')

# Database connection URIs. Capture user/password/host/port/db so we can
# rebuild a redacted version while preserving the host topology intel.
_DB_URI = re.compile(
    r'\b(mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|mariadb|mssql)://'
    r'(?:([^:@/\s]+)(?::([^@/\s]+))?@)?'                     # optional user:password@
    r'([^:/\s?#]+)'                                          # host (required)
    r'(?::(\d{1,5}))?'                                       # optional :port
    r'(?:/([^\s?#]+))?',                                     # optional /db
    re.IGNORECASE,
)

# Basic email regex. We only emit emails that appear WITHIN stack-trace
# context (see extract_emails_in_context); the generic email extraction
# stays in HTMLParser.
_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')

# Proximity window in characters: an email within this distance of a
# stack-trace marker is considered "in context".
_PROXIMITY_WINDOW = 500


# ─── Public helpers ───────────────────────────────────────────────────


def has_stack_trace(body: str) -> bool:
    """True if the body shows any stack-trace shape — i.e. an exception
    was rendered. Strong indicator of debug mode being enabled."""
    if not body:
        return False
    return any(p.search(body) for p in _STACKTRACE_SHAPES)


def detect_framework(body: str) -> tuple[str | None, str | None]:
    """Return (framework_name, framework_version) inferred from the body.

    Recognises Laravel (Illuminate / Symfony HttpKernel / vendor path),
    Django (technical-500 page / django.* traceback modules), Flask
    (Werkzeug debugger), and Spring Boot (Whitelabel / org.springframework
    stack frames). Returns the display name + version (when extractable),
    or (None, None) if no framework signal. Laravel is checked first as
    its markers are the most specific.
    """
    if not body:
        return None, None
    if any(p.search(body) for p in _LARAVEL_NAMESPACES):
        version_match = _LARAVEL_VERSION.search(body)
        return "Laravel", (version_match.group(1) if version_match else None)
    if any(p.search(body) for p in _DJANGO_MARKERS):
        version_match = _DJANGO_VERSION.search(body)
        return "Django", (version_match.group(1) if version_match else None)
    if any(p.search(body) for p in _FLASK_MARKERS):
        version_match = _WERKZEUG_VERSION.search(body)
        return "Flask", (version_match.group(1) if version_match else None)
    if any(p.search(body) for p in _SPRING_MARKERS):
        return "Spring Boot", None
    return None, None


def detect_php_version(body: str) -> str | None:
    """Extract a PHP version string if visible in the body."""
    if not body:
        return None
    match = _PHP_VERSION.search(body)
    return match.group(1) if match else None


def detect_ignition(body: str) -> bool:
    """True if Laravel's Ignition error handler is exposed.

    Note: we report the exposure as a finding but never reference CVE
    numbers in the output (per project direction). The operator looks
    up the exposure against their own knowledge / tooling.
    """
    if not body:
        return False
    return any(p.search(body) for p in _IGNITION_MARKERS)


def extract_filesystem_paths(body: str) -> list[str]:
    """Return deduped absolute filesystem paths from body."""
    if not body:
        return []
    seen: set[str] = set()
    paths: list[str] = []
    for pattern in _FILESYSTEM_PATHS:
        for match in pattern.finditer(body):
            raw = match.group(0).rstrip(".,;:!?)\"'(")
            if len(raw) < 5 or raw in seen:
                continue
            seen.add(raw)
            paths.append(raw)
    return paths


def infer_install_path(filesystem_paths: list[str]) -> str | None:
    """Given a list of filesystem paths, infer the app install root.

    Looks for the longest common prefix that ends before one of the
    conventional Laravel/PHP-app subdirs (vendor, public, storage, …).
    Returns the shortest such candidate so we don't over-deepen.
    """
    candidates: set[str] = set()
    for p in filesystem_paths:
        match = _INSTALL_MARKER.match(p)
        if match:
            candidates.add(match.group(1))
    if not candidates:
        return None
    return min(candidates, key=len)


def extract_internal_ips(body: str) -> list[str]:
    """Return deduped RFC 1918 IPs found anywhere in the body."""
    if not body:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for match in _RFC1918.finditer(body):
        ip = match.group(0)
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def extract_internal_hostnames(body: str) -> list[str]:
    """Return deduped internal-suffix hostnames (.internal/.local/etc)."""
    if not body:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for match in _INTERNAL_HOSTNAME.finditer(body):
        host = match.group(0).lower()
        if host not in seen:
            seen.add(host)
            out.append(host)
    return out


def extract_cloud_ids(body: str) -> list[dict]:
    """Return cloud-identifier findings: AWS access keys (redacted),
    AWS ARNs (kept verbatim — they're identifiers, not secrets), and
    EC2 instance IDs."""
    if not body:
        return []
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for match in _AWS_ACCESS_KEY.finditer(body):
        value = match.group(0)
        key = ("AWS_ACCESS_KEY", value)
        if key in seen:
            continue
        seen.add(key)
        findings.append({"type": "AWS_ACCESS_KEY", "value_redacted": redact_token(value)})
    for match in _AWS_ARN.finditer(body):
        value = match.group(0).rstrip(".,;:!?)\"'")
        key = ("AWS_ARN", value)
        if key in seen:
            continue
        seen.add(key)
        findings.append({"type": "AWS_ARN", "value": value})
    for match in _AWS_INSTANCE_ID.finditer(body):
        value = match.group(0)
        key = ("AWS_INSTANCE_ID", value)
        if key in seen:
            continue
        seen.add(key)
        findings.append({"type": "AWS_INSTANCE_ID", "value": value})
    return findings


def extract_db_uris(body: str) -> list[dict]:
    """Return DB connection URIs found in body, with credentials
    redacted to scheme://user:***@host:port/db (and the password also
    surfaced separately in first4…last4 form for the operator's notes).
    """
    if not body:
        return []
    findings: list[dict] = []
    seen: set[str] = set()
    for match in _DB_URI.finditer(body):
        scheme = match.group(1).lower()
        user = match.group(2)
        password = match.group(3)
        host = match.group(4)
        port = match.group(5)
        dbname = match.group(6)
        if not host:
            continue
        # Skip obvious junk hostnames (e.g. matching part of a comment)
        if len(host) < 2 or host in ("user", "username"):
            continue
        # Build redacted URI
        if user and password:
            creds_part = f"{user}:***@"
            password_redacted = redact_token(password)
        elif user:
            creds_part = f"{user}@"
            password_redacted = None
        else:
            creds_part = ""
            password_redacted = None
        port_part = f":{port}" if port else ""
        db_part = f"/{dbname}" if dbname else ""
        redacted_uri = f"{scheme}://{creds_part}{host}{port_part}{db_part}"
        if redacted_uri in seen:
            continue
        seen.add(redacted_uri)
        findings.append({
            "scheme": scheme,
            "host": host,
            "port": int(port) if port else None,
            "database": dbname,
            "user": user,
            "password_redacted": password_redacted,
            "redacted_uri": redacted_uri,
        })
    return findings


def extract_emails_in_context(body: str) -> list[str]:
    """Return emails that appear WITHIN stack-trace context.

    The crawler's HTMLParser already pulls emails from page text. This
    helper exists to surface emails that ONLY appear because of an
    error — those are usually operator/dev/notification addresses that
    a normal page wouldn't expose.

    "In context" = within _PROXIMITY_WINDOW characters of a stack-trace
    shape marker.
    """
    if not body or not has_stack_trace(body):
        return []
    marker_positions: list[int] = []
    for pattern in _STACKTRACE_SHAPES:
        for match in pattern.finditer(body):
            marker_positions.append(match.start())
    if not marker_positions:
        return []
    marker_positions.sort()
    seen: set[str] = set()
    out: list[str] = []
    for match in _EMAIL.finditer(body):
        email = match.group(0)
        if email in seen:
            continue
        pos = match.start()
        if any(abs(pos - mp) < _PROXIMITY_WINDOW for mp in marker_positions):
            seen.add(email)
            out.append(email)
    return out


# ─── Master entry point ───────────────────────────────────────────────


def mine_response(body: str) -> dict:
    """Mine a single response body for stack-trace findings.

    Returns an empty dict if there's no debug/framework/ignition signal
    in the body — keeps the per-page cost near-zero on clean responses.

    The shape of the returned dict matches what `results["debug_exposure"]`
    will store (one slice per response — `merge_findings` aggregates
    them across the whole crawl).
    """
    if not body:
        return {}

    debug_mode = has_stack_trace(body)
    framework, framework_version = detect_framework(body)
    ignition = detect_ignition(body)

    # If none of the three top-level signals fire, this page is clean.
    if not (debug_mode or framework or ignition):
        return {}

    fs_paths = extract_filesystem_paths(body)
    return {
        "debug_mode": debug_mode,
        "framework": framework,
        "framework_version": framework_version,
        "php_version": detect_php_version(body),
        "ignition_exposed": ignition,
        "install_path": infer_install_path(fs_paths),
        "filesystem_paths": fs_paths,
        "leaked_emails": extract_emails_in_context(body),
        "leaked_internal_ips": extract_internal_ips(body),
        "leaked_hostnames": extract_internal_hostnames(body),
        "leaked_cloud_ids": extract_cloud_ids(body),
        "leaked_db_uris": extract_db_uris(body),
    }


def merge_findings(per_page_findings: list[tuple[str, dict]]) -> dict:
    """Aggregate per-page findings into the final `debug_exposure` block.

    Input: list of (url, findings_dict). Findings with empty body are
    expected to be filtered before calling.

    Output schema:
        {
          "debug_mode": bool,
          "framework": str | None,
          "framework_version": str | None,
          "php_version": str | None,
          "ignition_exposed": bool,
          "install_path": str | None,
          "filesystem_paths": [str, ...],
          "leaked_emails": [str, ...],
          "leaked_internal_ips": [str, ...],
          "leaked_hostnames": [str, ...],
          "leaked_cloud_ids": [{type, value/value_redacted}, ...],
          "leaked_db_uris": [{scheme, host, ...}, ...],
          "evidence_urls": [str, ...]    # URLs whose response contained findings
        }
    """
    merged: dict = {
        "debug_mode": False,
        "framework": None,
        "framework_version": None,
        "php_version": None,
        "ignition_exposed": False,
        "install_path": None,
        "filesystem_paths": [],
        "leaked_emails": [],
        "leaked_internal_ips": [],
        "leaked_hostnames": [],
        "leaked_cloud_ids": [],
        "leaked_db_uris": [],
        "evidence_urls": [],
    }
    if not per_page_findings:
        return merged

    seen_paths: set[str] = set()
    seen_emails: set[str] = set()
    seen_ips: set[str] = set()
    seen_hosts: set[str] = set()
    seen_cloud: set[tuple] = set()
    seen_db: set[str] = set()
    seen_urls: set[str] = set()

    for url, f in per_page_findings:
        if not f:
            continue
        if url and url not in seen_urls:
            seen_urls.add(url)
            merged["evidence_urls"].append(url)

        merged["debug_mode"] = merged["debug_mode"] or f.get("debug_mode", False)
        merged["ignition_exposed"] = merged["ignition_exposed"] or f.get("ignition_exposed", False)

        # First non-None wins for the scalar fields
        for scalar in ("framework", "framework_version", "php_version", "install_path"):
            if f.get(scalar) and not merged[scalar]:
                merged[scalar] = f[scalar]

        for p in f.get("filesystem_paths", []):
            if p not in seen_paths:
                seen_paths.add(p)
                merged["filesystem_paths"].append(p)
        for e in f.get("leaked_emails", []):
            if e not in seen_emails:
                seen_emails.add(e)
                merged["leaked_emails"].append(e)
        for ip in f.get("leaked_internal_ips", []):
            if ip not in seen_ips:
                seen_ips.add(ip)
                merged["leaked_internal_ips"].append(ip)
        for h in f.get("leaked_hostnames", []):
            if h not in seen_hosts:
                seen_hosts.add(h)
                merged["leaked_hostnames"].append(h)
        for c in f.get("leaked_cloud_ids", []):
            key = (c.get("type"), c.get("value") or c.get("value_redacted"))
            if key not in seen_cloud:
                seen_cloud.add(key)
                merged["leaked_cloud_ids"].append(c)
        for d in f.get("leaked_db_uris", []):
            key = d.get("redacted_uri")
            if key and key not in seen_db:
                seen_db.add(key)
                merged["leaked_db_uris"].append(d)

    return merged
