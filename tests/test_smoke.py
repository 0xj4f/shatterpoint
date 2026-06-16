"""Quick smoke test for all modules."""

import base64
import json
import time

from shatterpoint.modules.extractor import Extractor
from shatterpoint.modules.fingerprint import (
    Fingerprinter,
    dedup_technologies,
    resolve_conflicts,
)
from shatterpoint.modules.parser import HTMLParser
from shatterpoint.modules.recon import ReconModule
from shatterpoint.modules.spa import (
    detect_framework,
    enumerate_bundles,
    extract_chunks,
    extract_routes,
    extract_secrets,
    extract_source_map_url,
    extract_state_dumps,
    parse_source_map,
)
from shatterpoint.modules.spider import Spider
from shatterpoint.utils.auth import (
    decode_jwt_exp,
    redact_token,
    resolve_token,
    should_send_auth,
    warn_on_expiry,
)
from shatterpoint.utils.baseline import Baseline
from shatterpoint.utils.stacktrace import (
    detect_framework as st_detect_framework,
)
from shatterpoint.utils.stacktrace import (
    detect_ignition,
    detect_php_version,
    extract_cloud_ids,
    extract_db_uris,
    extract_emails_in_context,
    extract_filesystem_paths,
    extract_internal_hostnames,
    extract_internal_ips,
    has_stack_trace,
    infer_install_path,
    merge_findings,
    mine_response,
)
from shatterpoint.utils.validator import URLValidator


def test_imports():
    """Verify all modules can be imported."""
    assert Spider is not None
    assert HTMLParser is not None
    assert Extractor is not None
    assert Fingerprinter is not None
    assert ReconModule is not None


def test_validator_scope():
    v = URLValidator("http://10.10.10.1")
    assert v.base_url == "http://10.10.10.1"
    assert v.is_in_scope("http://10.10.10.1/admin") is True
    assert v.is_in_scope("http://evil.com/test") is False


def test_validator_normalize():
    v = URLValidator("http://10.10.10.1")
    assert v.normalize("/page", "http://10.10.10.1/") == "http://10.10.10.1/page"
    assert v.normalize("javascript:void(0)") is None
    assert v.normalize("mailto:a@b.com") is None


def test_validator_file_detection():
    v = URLValidator("http://10.10.10.1")
    assert v.is_static_resource("http://10.10.10.1/img.png") is True
    assert v.is_static_resource("http://10.10.10.1/page.php") is False
    assert v.is_interesting_file("http://10.10.10.1/backup.sql") is True
    assert v.is_interesting_file("http://10.10.10.1/style.css") is False


def test_parser_forms():
    p = HTMLParser()
    html = """
    <html><body>
    <form action="/login" method="POST">
      <input type="text" name="user">
      <input type="password" name="pass">
      <input type="hidden" name="csrf_token" value="abc123">
      <input type="file" name="avatar">
    </form>
    </body></html>
    """
    forms = p.extract_forms(html, "http://test.com")
    assert len(forms) == 1
    assert forms[0]["has_file_upload"] is True
    assert forms[0]["has_password_field"] is True
    assert forms[0]["has_csrf_token"] is True
    assert forms[0]["method"] == "POST"


def test_parser_comments():
    p = HTMLParser()
    html = """
    <html><body>
    <!-- TODO: remove debug endpoint /api/debug -->
    <!-- password: admin123 -->
    </body></html>
    """
    comments = p.extract_comments(html, "http://test.com")
    assert len(comments) >= 1
    assert any("todo" in c.get("keywords", []) or "debug" in c.get("keywords", []) for c in comments)


def test_parser_links():
    p = HTMLParser()
    html = '<html><body><a href="/admin">Admin</a><a href="/api/users">API</a></body></html>'
    links = p.extract_links(html)
    assert "/admin" in links
    assert "/api/users" in links


def test_parser_emails():
    p = HTMLParser()
    emails = p.extract_emails("Contact us at admin@test.com or info@test.com")
    assert "admin@test.com" in emails
    assert "info@test.com" in emails


def test_extractor_js_endpoints():
    e = Extractor()
    js_code = """
    fetch('/api/v1/users');
    axios.get('/api/v2/data');
    var endpoint = '/rest/config';
    """
    eps = e.extract_js_endpoints(js_code, "http://test.com")
    found = [ep["url"] for ep in eps]
    assert "/api/v1/users" in found
    assert "/api/v2/data" in found


def test_extractor_parameters():
    e = Extractor()
    params = e.extract_url_parameters(["http://test.com/search?q=hello&page=1"])
    assert len(params) == 1
    assert "q" in params[0]["params"]
    assert "page" in params[0]["params"]


def test_fingerprinter():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True,
            "check_cookies": True,
            "check_meta": True,
            "check_scripts": True,
        }
    })
    assert len(fp.signatures) > 0
    detections = fp.fingerprint_from_response(
        "http://test.com",
        {"server": "Apache/2.4.41", "x-powered-by": "PHP/7.4.3"},
        "<html></html>",
    )
    names = [d["name"] for d in detections]
    assert "Apache HTTP Server" in names
    assert "PHP" in names


def _make_jwt(payload: dict) -> str:
    """Build a JWT-shaped string with the given payload. Signature is fake."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.signature"


def test_redact_token_typical():
    token = "eyJhbGci" + "X" * 40 + "6Dc1"
    redacted = redact_token(token)
    assert redacted.startswith("eyJh")
    assert redacted.endswith("6Dc1")
    assert "…" in redacted
    assert "X" * 40 not in redacted


def test_redact_token_short():
    # Tokens shorter than 8 chars are fully redacted
    assert redact_token("abc") == "…"
    assert redact_token("1234567") == "…"
    assert redact_token("") == ""
    assert redact_token(None) == ""


def test_redact_token_boundary():
    # Exactly 8 chars is the smallest length where first4/last4 is shown
    assert redact_token("12345678") == "1234…5678"


def test_resolve_token_cli_wins(monkeypatch):
    monkeypatch.setenv("SHATTERPOINT_TOKEN", "env-tok")
    assert resolve_token("cli-tok", {"auth": {"token": "cfg-tok"}}) == "cli-tok"


def test_resolve_token_env_over_config(monkeypatch):
    monkeypatch.setenv("SHATTERPOINT_TOKEN", "env-tok")
    assert resolve_token(None, {"auth": {"token": "cfg-tok"}}) == "env-tok"


def test_resolve_token_config_fallback(monkeypatch):
    monkeypatch.delenv("SHATTERPOINT_TOKEN", raising=False)
    assert resolve_token(None, {"auth": {"token": "cfg-tok"}}) == "cfg-tok"


def test_resolve_token_none(monkeypatch):
    monkeypatch.delenv("SHATTERPOINT_TOKEN", raising=False)
    assert resolve_token(None, {}) is None
    assert resolve_token("", {}) is None
    assert resolve_token(None, {"auth": {"token": ""}}) is None


def test_jwt_exp_parse_valid():
    token = _make_jwt({"sub": "u", "exp": 1776412517})
    assert decode_jwt_exp(token) == 1776412517


def test_jwt_exp_parse_opaque():
    assert decode_jwt_exp("opaque-random-string") is None
    assert decode_jwt_exp("") is None
    assert decode_jwt_exp(None) is None


def test_jwt_exp_parse_malformed():
    assert decode_jwt_exp("not.enough") is None
    bad_b64 = "!!!notbase64!!!"
    assert decode_jwt_exp(f"hdr.{bad_b64}.sig") is None
    not_json = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
    assert decode_jwt_exp(f"hdr.{not_json}.sig") is None


def test_jwt_exp_missing_claim():
    token = _make_jwt({"sub": "u"})
    assert decode_jwt_exp(token) is None


def test_warn_on_expiry_past():
    token = _make_jwt({"exp": int(time.time()) - 100})
    msg = warn_on_expiry(token)
    assert msg is not None
    assert "expired" in msg.lower()


def test_warn_on_expiry_soon():
    token = _make_jwt({"exp": int(time.time()) + 60})
    msg = warn_on_expiry(token, warn_window_seconds=600)
    assert msg is not None
    assert "expires in" in msg.lower()


def test_warn_on_expiry_fresh():
    token = _make_jwt({"exp": int(time.time()) + 86400})
    assert warn_on_expiry(token, warn_window_seconds=600) is None


def test_warn_on_expiry_opaque():
    assert warn_on_expiry("opaque-token") is None
    assert warn_on_expiry(None) is None


def test_should_send_auth_same_origin():
    assert should_send_auth("http", "localhost:3001", "http://localhost:3001/api/x")


def test_should_send_auth_different_host():
    assert not should_send_auth("http", "localhost:3001", "http://evil.com/x")


def test_should_send_auth_different_port():
    assert not should_send_auth("http", "localhost:3001", "http://localhost:3002/x")


def test_should_send_auth_different_scheme():
    assert not should_send_auth("http", "localhost:3001", "https://localhost:3001/x")


def test_should_send_auth_default_ports():
    # http://example.com == http://example.com:80
    assert should_send_auth("http", "example.com", "http://example.com:80/x")
    assert should_send_auth("http", "example.com:80", "http://example.com/x")
    # https://example.com == https://example.com:443
    assert should_send_auth("https", "example.com", "https://example.com:443/x")


def test_should_send_auth_subdomain():
    assert not should_send_auth("http", "example.com", "http://api.example.com/x")


def test_should_send_auth_empty_and_garbage():
    assert not should_send_auth("http", "example.com", "")
    assert not should_send_auth("http", "example.com", "not-a-url")


# ─── Auth vs security-header taxonomy split ───────────────────────────


def _make_recon():
    # Minimal ReconModule for taxonomy tests — config defaults are fine
    return ReconModule({}, "http://target.test")


def test_auth_detection_returns_only_auth():
    r = _make_recon()
    headers = {
        "www-authenticate": 'Basic realm="protected"',
        "x-content-type-options": "nosniff",
        "x-xss-protection": "1; mode=block",
        "strict-transport-security": "max-age=31536000",
    }
    auth = r.detect_auth_mechanisms("http://target.test/admin", headers, "", [])
    types = {a["type"] for a in auth}
    # Auth mechanism is present:
    assert "HTTP Basic Auth" in types
    # Security headers must NOT leak into auth list:
    assert not any("Security Header" in t for t in types)
    assert not any("Content-Type-Options" in t for t in types)


def test_auth_detection_picks_up_login_form():
    r = _make_recon()
    forms = [{
        "found_on": "http://target.test/login",
        "action": "/api/auth/login",
        "method": "POST",
        "has_password_field": True,
        "has_csrf_token": True,
    }]
    auth = r.detect_auth_mechanisms("http://target.test/login", {}, "", forms)
    assert any(a["type"] == "Login Form" for a in auth)


def test_security_headers_returns_only_security_headers():
    r = _make_recon()
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=63072000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "x-xss-protection": "1; mode=block",
        # Non-security header — must be ignored
        "server": "nginx/1.25.3",
        "www-authenticate": "Bearer",
    }
    sh = r.detect_security_headers("http://target.test/", headers)
    names = {h["name"] for h in sh}
    assert "Content Security Policy" in names
    assert "HSTS" in names
    assert "X-Content-Type-Options" in names
    assert "X-Frame-Options" in names
    assert "X-XSS-Protection" in names
    # Auth header didn't leak in
    assert not any("auth" in n.lower() for n in names)


def test_security_headers_empty_when_none_present():
    r = _make_recon()
    assert r.detect_security_headers("http://target.test/", {"server": "x"}) == []


# ─── Fingerprint body matching tests ──────────────────────────────────


def test_fingerprint_body_word_boundary_matches_standalone():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True,
            "check_cookies": True,
            "check_meta": True,
            "check_scripts": True,
        }
    })
    # Standalone "react" token in body → should fire React detection
    detections = fp.fingerprint_from_response(
        "http://test.com",
        {},
        '<html><body><script>var react = require("react");</script></body></html>',
    )
    names = {d["name"] for d in detections}
    assert "React" in names


def test_fingerprint_body_word_boundary_rejects_substring():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True,
            "check_cookies": True,
            "check_meta": True,
            "check_scripts": True,
        }
    })
    # Substring-only case in isolation:
    detections2 = fp.fingerprint_from_response(
        "http://test.com",
        {},
        "<html><body>wordpresslike framework, very wordpressy.</body></html>",
    )
    names2 = {d["name"] for d in detections2}
    assert "WordPress" not in names2, (
        "word-boundary matcher leaked: 'wordpresslike' should not match 'wordpress'"
    )


def test_fingerprint_body_word_boundary_hyphenated_pattern():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True,
            "check_cookies": True,
            "check_meta": True,
            "check_scripts": True,
        }
    })
    # ng-version is a hyphenated pattern; must still match in Angular markup
    detections = fp.fingerprint_from_response(
        "http://test.com",
        {},
        '<html><body><app-root ng-version="14.2.0"></app-root></body></html>',
    )
    names = {d["name"] for d in detections}
    assert "Angular" in names


# ─── Technology dedup tests ───────────────────────────────────────────


def test_dedup_technologies_merges_by_id():
    def _m(method, detail):
        return [{"method": method, "detail": detail}]

    techs = [
        {"id": "wordpress", "name": "WordPress", "matched_on": _m("path_probe", "/wp-login.php returned 200")},
        {"id": "wordpress", "name": "WordPress", "matched_on": _m("path_probe", "/wp-admin/ returned 200")},
        {"id": "wordpress", "name": "WordPress", "matched_on": _m("header", "x-powered-by: WordPress")},
    ]
    deduped = dedup_technologies(techs)
    assert len(deduped) == 1
    assert deduped[0]["id"] == "wordpress"
    assert len(deduped[0]["matched_on"]) == 3


def test_dedup_technologies_preserves_distinct_ids():
    techs = [
        {"id": "wordpress", "name": "WordPress", "matched_on": []},
        {"id": "drupal", "name": "Drupal", "matched_on": []},
        {"id": "wordpress", "name": "WordPress", "matched_on": []},
    ]
    deduped = dedup_technologies(techs)
    assert {t["id"] for t in deduped} == {"wordpress", "drupal"}
    assert len(deduped) == 2


def test_dedup_technologies_keeps_non_empty_version():
    techs = [
        {"id": "nginx", "name": "Nginx", "version": None, "matched_on": []},
        {"id": "nginx", "name": "Nginx", "version": "1.25.3", "matched_on": []},
    ]
    deduped = dedup_technologies(techs)
    assert deduped[0]["version"] == "1.25.3"


def test_dedup_technologies_picks_highest_confidence():
    techs = [
        {"id": "react", "name": "React", "confidence": "low", "matched_on": []},
        {"id": "react", "name": "React", "confidence": "high", "matched_on": []},
        {"id": "react", "name": "React", "confidence": "medium", "matched_on": []},
    ]
    deduped = dedup_technologies(techs)
    assert deduped[0]["confidence"] == "high"


def test_dedup_technologies_dedups_matched_on_entries():
    # Same evidence reported twice should collapse to one entry
    techs = [
        {"id": "x", "name": "X", "matched_on": [{"method": "header", "detail": "server: X"}]},
        {"id": "x", "name": "X", "matched_on": [{"method": "header", "detail": "server: X"}]},
    ]
    deduped = dedup_technologies(techs)
    assert len(deduped[0]["matched_on"]) == 1


def test_dedup_technologies_empty():
    assert dedup_technologies([]) == []


# ─── Audit regressions (catch the bugs the confidence audit found) ───


def test_laravel_body_marker_matches_single_backslash_namespace():
    """Regression: the original YAML had `Illuminate\\\\\\\\` which parsed to a
    Python string requiring TWO literal backslashes — real Laravel error
    pages render single-backslash namespaces. This test exercises a
    realistic Laravel HTML body and confirms detection fires."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    # Real Laravel Ignition output: namespaces rendered with single backslash
    body = (
        '<html><body><pre>'
        'Illuminate\\Routing\\AbstractRouteCollection->methodNotAllowed()\n'
        'Illuminate\\Foundation\\Http\\Kernel->handle()'
        '</pre></body></html>'
    )
    detections = fp.fingerprint_from_response(
        "http://target/error", {}, body, cookies=None,
    )
    laravel = next((d for d in detections if d["name"] == "Laravel"), None)
    assert laravel is not None, (
        "Laravel must be detected from single-backslash Illuminate\\Routing "
        "and Illuminate\\Foundation namespace markers"
    )


def test_bootstrap_does_not_fire_on_laravel_bootstrap_path():
    """Regression: bare 'bootstrap' substring used to match Laravel's
    `/app/bootstrap/app.php` filename in stack traces, producing a CSS
    Framework false-positive on every Laravel error page."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    # Simulated Laravel stack trace mentioning bootstrap/app.php
    body = (
        '<html><body>'
        '#0 /var/www/html/lavita/bootstrap/app.php(17): '
        'Illuminate\\Foundation\\Application->__construct()'
        '</body></html>'
    )
    detections = fp.fingerprint_from_response(
        "http://target/error", {}, body, cookies=None,
    )
    names = {d["name"] for d in detections}
    assert "Bootstrap" not in names, (
        "Bootstrap sig must require CSS-specific evidence "
        "(class names, bootstrap.min.css), not bare 'bootstrap' substring"
    )


def test_framework_recon_fires_when_laravel_only_in_body():
    """Regression: framework_recon used to run BEFORE landing-page body
    detection, so production Laravel targets (no Ignition path probe
    hit) had Laravel detected only via cookies/body — too late for
    Phase 1.7. After the reorder, the body-detected Laravel must be
    visible to framework_recon.should_run()."""
    from shatterpoint.modules.framework_recon import FrameworkRecon
    v = URLValidator("http://prod.test")
    fr = FrameworkRecon({"framework_recon": {"enabled": True}}, v)
    # Simulate the state after Phase 1.6 (body detection added Laravel)
    detected_techs = [
        {"id": "laravel", "name": "Laravel", "matched_on": [
            {"method": "cookie", "detail": "laravel_session"},
            {"method": "body", "detail": "Illuminate\\Routing"},
        ]}
    ]
    assert fr.should_run(detected_techs) == ["laravel"]


def test_bootstrap_still_fires_on_real_bootstrap_site():
    """Confirm tightening didn't kill legitimate Bootstrap detection."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    body = (
        '<html><head>'
        '<link rel="stylesheet" href="/css/bootstrap.min.css">'
        '</head><body>'
        '<nav class="navbar"><button class="navbar-toggler">menu</button></nav>'
        '<div class="container-fluid"><button data-bs-toggle="modal">open</button></div>'
        '</body></html>'
    )
    detections = fp.fingerprint_from_response(
        "http://target/", {}, body, cookies=None,
    )
    names = {d["name"] for d in detections}
    assert "Bootstrap" in names


# ─── FrameworkRecon module ────────────────────────────────────────────


def test_framework_recon_should_run_when_laravel_detected():
    from shatterpoint.modules.framework_recon import FrameworkRecon
    v = URLValidator("http://target.test")
    fr = FrameworkRecon({"framework_recon": {"enabled": True}}, v)
    techs = [{"id": "laravel", "name": "Laravel"}]
    assert fr.should_run(techs) == ["laravel"]


def test_framework_recon_skips_when_not_enabled():
    from shatterpoint.modules.framework_recon import FrameworkRecon
    v = URLValidator("http://target.test")
    fr = FrameworkRecon({"framework_recon": {"enabled": False}}, v)
    techs = [{"id": "laravel", "name": "Laravel"}]
    assert fr.should_run(techs) == []


def test_framework_recon_auto_when_detected_fires():
    from shatterpoint.modules.framework_recon import FrameworkRecon
    v = URLValidator("http://target.test")
    fr = FrameworkRecon(
        {"framework_recon": {"enabled": False, "auto_when_detected": True}}, v,
    )
    techs = [{"id": "laravel", "name": "Laravel"}]
    assert fr.should_run(techs) == ["laravel"]


def test_framework_recon_skips_unsupported_framework():
    from shatterpoint.modules.framework_recon import FrameworkRecon
    v = URLValidator("http://target.test")
    fr = FrameworkRecon({"framework_recon": {"enabled": True}}, v)
    techs = [{"id": "phpmyadmin", "name": "phpMyAdmin"}]
    assert fr.should_run(techs) == []


def test_framework_recon_laravel_profile_has_critical_probes():
    """Spot-check that the Laravel profile covers the must-have probes."""
    from shatterpoint.modules.framework_recon import _LARAVEL_PROBES
    paths = {p.path for p in _LARAVEL_PROBES}
    must_have = {
        "/_ignition/health-check",
        "/_ignition/execute-solution",
        "/telescope",
        "/horizon",
        "/.env",
        "/.env.bak",
        "/composer.lock",
        "/storage/logs/laravel.log",
    }
    missing = must_have - paths
    assert not missing, f"Laravel profile missing critical probes: {missing}"


def test_framework_recon_no_cve_numbers_in_notes():
    """Per project direction: no CVE numbers surface in the output."""
    from shatterpoint.modules.framework_recon import _LARAVEL_PROBES
    for probe in _LARAVEL_PROBES:
        assert "CVE-" not in probe.note, (
            f"Probe {probe.path} leaks CVE number: {probe.note}"
        )


# ─── Signature tightening regression tests ───────────────────────────


def test_rails_does_not_fire_on_csrf_meta_alone():
    """Regression: the actual Laravel scan produced a Rails false-positive
    because Rails sig used to match `<meta name="csrf-token">` blanket.
    After tightening, Rails should require Rails-specific evidence."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    # Laravel page: csrf-token meta + Laravel cookie
    detections = fp.fingerprint_from_response(
        "http://target/",
        {"set-cookie": "XSRF-TOKEN=abc; HttpOnly"},
        '<html><head><meta name="csrf-token" content="abc"></head><body>laravel</body></html>',
        cookies={"XSRF-TOKEN": "abc"},
    )
    names = {d["name"] for d in detections}
    assert "Laravel" in names
    assert "Ruby on Rails" not in names


def test_rails_still_fires_on_real_rails_evidence():
    """Confirm Rails tightening didn't break legitimate Rails detection."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    detections = fp.fingerprint_from_response(
        "http://target/",
        {"x-runtime": "0.024531", "set-cookie": "_session_id=abc"},
        '<html><body><script src="rails-ujs.js"></script>Started GET</body></html>',
        cookies={"_session_id": "abc"},
    )
    names = {d["name"] for d in detections}
    assert "Ruby on Rails" in names


def test_grafana_does_not_fire_on_login_alone():
    """Regression: Grafana sig used to include `/login` in its paths list,
    producing false-positives on every framework that exposes /login."""
    # Path-probe behaviour: we can't easily simulate this without httpx,
    # but the YAML edit removed /login from grafana.paths. Confirm via
    # signature inspection.
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    grafana_paths = fp.signatures.get("grafana", {}).get("paths", [])
    assert "/login" not in grafana_paths
    assert "/api/datasources" in grafana_paths  # new Grafana-specific probe


def test_laravel_signature_has_form_fields():
    """Laravel sig should now include _token / _method form fields."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    laravel_form_fields = fp.signatures.get("laravel", {}).get("form_fields", [])
    assert "_token" in laravel_form_fields
    assert "_method" in laravel_form_fields


def test_laravel_signature_declares_conflicts():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    laravel_conflicts = fp.signatures.get("laravel", {}).get("incompatible_with", [])
    assert "rails" in laravel_conflicts


def test_laravel_multi_evidence_stack():
    """End-to-end: a Laravel page with cookies + form _token + vendor path
    in body should fire Laravel with multiple matched_on entries."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    body = (
        '<html><body>laravel framework error in '
        '/var/www/html/x/vendor/laravel/framework/src/Illuminate/Routing</body></html>'
    )
    forms = [{
        "found_on": "http://target/login",
        "inputs": [
            {"name": "_token", "type": "hidden", "tag": "input"},
            {"name": "email", "type": "email", "tag": "input"},
        ],
    }]
    detections = fp.fingerprint_from_response(
        "http://target/login",
        {"set-cookie": "laravel_session=abc; HttpOnly"},
        body,
        cookies={"laravel_session": "abc"},
        forms=forms,
    )
    laravel = next((d for d in detections if d["name"] == "Laravel"), None)
    assert laravel is not None
    methods = {m["method"] for m in laravel["matched_on"]}
    # Expect at least 3 distinct evidence types
    assert len(methods) >= 3, f"Expected 3+ evidence types, got: {methods}"


# ─── Conflict resolution tests ────────────────────────────────────────


def _tech(tech_id: str, methods: int, confidence: str = "medium") -> dict:
    """Build a fake tech detection with N distinct matched_on methods."""
    method_names = ["header", "cookie", "body", "meta", "script", "path_probe", "form_field"]
    matched = [
        {"method": method_names[i], "detail": f"{tech_id} via {method_names[i]}"}
        for i in range(methods)
    ]
    return {
        "id": tech_id,
        "name": tech_id.title(),
        "matched_on": matched,
        "confidence": confidence,
    }


def test_resolve_conflicts_stronger_wins():
    sigs = {
        "laravel": {"incompatible_with": ["rails"]},
        "rails": {"incompatible_with": ["laravel"]},
    }
    techs = [
        _tech("laravel", methods=4, confidence="high"),
        _tech("rails", methods=1, confidence="medium"),
    ]
    result = resolve_conflicts(techs, sigs)
    ids = {t["id"] for t in result}
    assert "laravel" in ids
    assert "rails" not in ids


def test_resolve_conflicts_tie_keeps_both():
    sigs = {
        "laravel": {"incompatible_with": ["rails"]},
        "rails": {"incompatible_with": ["laravel"]},
    }
    techs = [
        _tech("laravel", methods=2, confidence="medium"),
        _tech("rails", methods=2, confidence="medium"),
    ]
    result = resolve_conflicts(techs, sigs)
    ids = {t["id"] for t in result}
    # Tie → both kept; operator decides
    assert ids == {"laravel", "rails"}


def test_resolve_conflicts_no_incompatibility_declared():
    sigs = {"laravel": {}, "rails": {}}
    techs = [
        _tech("laravel", methods=4, confidence="high"),
        _tech("rails", methods=1, confidence="medium"),
    ]
    result = resolve_conflicts(techs, sigs)
    # Without an incompatibility declaration, both stay
    assert len(result) == 2


def test_resolve_conflicts_drops_only_the_weaker_one_in_chain():
    # Laravel beats Rails; Rails beats Django. Both Rails and Django
    # should be dropped (Laravel wins via direct comparison; Django
    # never gets compared but it's also not incompatible with Laravel
    # in this fixture, so Django survives).
    sigs = {
        "laravel": {"incompatible_with": ["rails"]},
        "rails": {"incompatible_with": ["laravel", "django"]},
        "django": {"incompatible_with": ["rails"]},
    }
    techs = [
        _tech("laravel", methods=4, confidence="high"),
        _tech("rails", methods=1, confidence="low"),
        _tech("django", methods=2, confidence="medium"),
    ]
    result = resolve_conflicts(techs, sigs)
    ids = {t["id"] for t in result}
    assert "laravel" in ids
    assert "rails" not in ids
    assert "django" in ids


def test_resolve_conflicts_empty():
    assert resolve_conflicts([], {}) == []
    assert resolve_conflicts([_tech("x", 1)], {}) == [_tech("x", 1)]


# ─── form_fields signature channel ────────────────────────────────────


def test_fingerprint_form_field_match_laravel():
    """A signature with `form_fields: [_token]` should match a Laravel form."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True,
            "check_cookies": True,
            "check_meta": True,
            "check_scripts": True,
        }
    })
    # Inject a custom signature inline
    fp.signatures["__test_laravel"] = {
        "name": "TestLaravel",
        "category": "Framework",
        "form_fields": ["_token", "_method"],
    }
    forms = [{
        "found_on": "http://test.com/login",
        "inputs": [
            {"tag": "input", "type": "hidden", "name": "_token", "value": "abc"},
            {"tag": "input", "type": "email", "name": "email", "value": ""},
        ],
    }]
    detections = fp.fingerprint_from_response(
        "http://test.com/login", {}, "<html></html>", cookies=None, forms=forms,
    )
    names = {d["name"] for d in detections}
    assert "TestLaravel" in names


def test_fingerprint_form_field_no_match():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    fp.signatures["__test_only_laravel"] = {
        "name": "TestOnlyLaravel",
        "category": "Framework",
        "form_fields": ["_token"],
    }
    # Django CSRF field, not Laravel's _token
    forms = [{
        "found_on": "http://test.com/",
        "inputs": [{"name": "csrfmiddlewaretoken", "type": "hidden", "tag": "input"}],
    }]
    detections = fp.fingerprint_from_response(
        "http://test.com/", {}, "<html></html>", cookies=None, forms=forms,
    )
    names = {d["name"] for d in detections}
    assert "TestOnlyLaravel" not in names


def test_fingerprint_form_field_without_forms_passed():
    """If `forms` isn't passed, form_fields silently skip — no crash."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    fp.signatures["__test_form_only"] = {
        "name": "TestFormOnly",
        "category": "Framework",
        "form_fields": ["_token"],
    }
    # No forms parameter → no detection, no exception
    detections = fp.fingerprint_from_response(
        "http://test.com/", {}, "<html></html>",
    )
    names = {d["name"] for d in detections}
    assert "TestFormOnly" not in names


# ─── Stack-trace miner tests ──────────────────────────────────────────


# Real-looking fixture pulled from the actual Laravel target the user
# scanned (sanitised values).
_LARAVEL_TRACE_FIXTURE = (
    "Symfony\\Component\\HttpKernel\\Exception\\MethodNotAllowedHttpException: "
    "The GET method is not supported for this route. Supported methods: POST. "
    "in file /var/www/html/lavita/vendor/laravel/framework/src/Illuminate/Routing/AbstractRouteCollection.php "
    "on line 117\n\n"
    "#0 /var/www/html/lavita/vendor/laravel/framework/src/Illuminate/Routing/AbstractRouteCollection.php(103): "
    "Illuminate\\Routing\\AbstractRouteCollection->methodNotAllowed()\n"
    "#1 /var/www/html/lavita/vendor/laravel/framework/src/Illuminate/Routing/RouteCollection.php(190): "
    "Illuminate\\Routing\\AbstractRouteCollection->getRouteForMethods()\n"
    "Notify: admin@lavita.internal — see flareapp.io/docs/ignition-for-laravel "
    "running on db.internal:3306 via mysql://laravel_user:s3cretP4ss@db.internal:3306/lavita_prod"
)


def test_has_stack_trace_php():
    assert has_stack_trace(_LARAVEL_TRACE_FIXTURE) is True


def test_has_stack_trace_python():
    body = "Traceback (most recent call last):\n  File 'x.py', line 1\nValueError"
    assert has_stack_trace(body) is True


def test_has_stack_trace_java():
    body = "at com.example.Foo.bar(Foo.java:42)"
    assert has_stack_trace(body) is True


def test_has_stack_trace_clean_page():
    body = "<html><body><h1>Welcome</h1><p>Some normal page text.</p></body></html>"
    assert has_stack_trace(body) is False


def test_detect_framework_laravel():
    fw, version = st_detect_framework(_LARAVEL_TRACE_FIXTURE)
    assert fw == "Laravel"
    # No version-tagged vendor dir → version is None
    assert version is None


def test_detect_framework_laravel_with_versioned_vendor():
    body = "stuff /vendor/laravel/framework/v10.4.2/src/Illuminate/x.php"
    fw, version = st_detect_framework(body)
    assert fw == "Laravel"
    assert version == "10.4.2"


def test_detect_framework_no_match():
    assert st_detect_framework("just a normal page") == (None, None)


def test_detect_php_version():
    assert detect_php_version("Powered by PHP/8.1.12") == "8.1.12"
    assert detect_php_version("PHP 7.4.33 detected") == "7.4.33"
    assert detect_php_version("no version here") is None


def test_detect_ignition():
    assert detect_ignition(_LARAVEL_TRACE_FIXTURE) is True
    assert detect_ignition("ignition is not a thing here") is False


def test_detect_ignition_path_marker():
    body = "GET /_ignition/execute-solution returned 405"
    assert detect_ignition(body) is True


def test_extract_filesystem_paths():
    paths = extract_filesystem_paths(_LARAVEL_TRACE_FIXTURE)
    # Should include the Laravel vendor path
    assert any("vendor/laravel/framework" in p for p in paths)
    assert any("/var/www/html/lavita" in p for p in paths)
    # Trailing punctuation stripped
    assert not any(p.endswith(":") for p in paths)


def test_infer_install_path():
    paths = [
        "/var/www/html/lavita/vendor/laravel/framework/src/Illuminate/Routing/X.php",
        "/var/www/html/lavita/public/index.php",
        "/var/www/html/lavita/storage/logs/laravel.log",
    ]
    assert infer_install_path(paths) == "/var/www/html/lavita"


def test_infer_install_path_empty():
    assert infer_install_path([]) is None


def test_extract_internal_ips_rfc1918():
    body = "Calling 10.0.5.12 and 192.168.1.1 and 172.20.3.4 from public 8.8.8.8"
    ips = extract_internal_ips(body)
    assert "10.0.5.12" in ips
    assert "192.168.1.1" in ips
    assert "172.20.3.4" in ips
    # Public IP excluded
    assert "8.8.8.8" not in ips


def test_extract_internal_ips_172_boundary():
    # 172.15 and 172.32 are NOT in RFC 1918
    body = "172.15.1.1 172.16.1.1 172.31.255.255 172.32.0.0"
    ips = extract_internal_ips(body)
    assert "172.16.1.1" in ips
    assert "172.31.255.255" in ips
    assert "172.15.1.1" not in ips
    assert "172.32.0.0" not in ips


def test_extract_internal_hostnames():
    body = "Connecting to db.internal, cache.local, k8s-svc.svc.cluster.local, public.com"
    hosts = extract_internal_hostnames(body)
    assert "db.internal" in hosts
    assert "cache.local" in hosts
    assert "k8s-svc.svc.cluster.local" in hosts
    assert "public.com" not in hosts


def test_extract_cloud_ids_aws_key():
    body = "Got error from AKIAIOSFODNN7EXAMPLE"
    findings = extract_cloud_ids(body)
    assert any(f["type"] == "AWS_ACCESS_KEY" for f in findings)
    aws = next(f for f in findings if f["type"] == "AWS_ACCESS_KEY")
    assert aws["value_redacted"].startswith("AKIA")
    # Middle of the key not visible
    assert "IOSFODNN7" not in aws["value_redacted"]


def test_extract_cloud_ids_arn():
    body = "Trying arn:aws:s3:::my-bucket/key"
    findings = extract_cloud_ids(body)
    assert any(f["type"] == "AWS_ARN" for f in findings)


def test_extract_cloud_ids_instance():
    body = "Failed on instance i-0abc123def4567890"
    findings = extract_cloud_ids(body)
    assert any(f["type"] == "AWS_INSTANCE_ID" for f in findings)


def test_extract_db_uris_redacts_password():
    body = "DSN: mysql://laravel_user:s3cretP4ss@db.internal:3306/lavita_prod"
    findings = extract_db_uris(body)
    assert len(findings) == 1
    f = findings[0]
    assert f["scheme"] == "mysql"
    assert f["host"] == "db.internal"
    assert f["port"] == 3306
    assert f["database"] == "lavita_prod"
    assert f["user"] == "laravel_user"
    assert "s3cretP4ss" not in f["redacted_uri"]
    assert "***" in f["redacted_uri"]
    # Password surfaced separately as first4…last4
    assert f["password_redacted"].startswith("s3cr")
    assert f["password_redacted"].endswith("P4ss")


def test_extract_db_uris_no_creds():
    body = "redis://cache.internal:6379/0"
    findings = extract_db_uris(body)
    assert len(findings) == 1
    assert findings[0]["redacted_uri"] == "redis://cache.internal:6379/0"
    assert findings[0]["user"] is None
    assert findings[0]["password_redacted"] is None


def test_extract_db_uris_postgres():
    body = "postgresql://app:hunter2pass@pg.internal:5432/main"
    findings = extract_db_uris(body)
    assert findings[0]["scheme"] == "postgresql"
    assert "hunter2pass" not in findings[0]["redacted_uri"]


def test_extract_emails_in_context_yes():
    emails = extract_emails_in_context(_LARAVEL_TRACE_FIXTURE)
    assert "admin@lavita.internal" in emails


def test_extract_emails_in_context_no_trace():
    # Page with emails but no stack-trace shape → no emails returned
    body = "<html><body>Contact support@example.com</body></html>"
    assert extract_emails_in_context(body) == []


def test_extract_emails_in_context_far_from_trace():
    # Stack trace AND an email, but the email is far from any marker.
    body = (
        "support@example.com" + (" " * 2000) +
        "#0 /var/www/x.php(1): foo()\n"
    )
    # 2000 chars of separation > _PROXIMITY_WINDOW (500) → not in context
    assert extract_emails_in_context(body) == []


def test_mine_response_full_fixture():
    result = mine_response(_LARAVEL_TRACE_FIXTURE)
    assert result["debug_mode"] is True
    assert result["framework"] == "Laravel"
    assert result["ignition_exposed"] is True
    assert result["install_path"] == "/var/www/html/lavita"
    assert "admin@lavita.internal" in result["leaked_emails"]
    assert "db.internal" in result["leaked_hostnames"]
    assert any(d["scheme"] == "mysql" for d in result["leaked_db_uris"])


def test_mine_response_clean_page():
    body = "<html><body>Just a normal page, no errors here.</body></html>"
    assert mine_response(body) == {}


def test_mine_response_empty_input():
    assert mine_response("") == {}
    assert mine_response(None) == {}


def test_merge_findings_dedup():
    p1 = mine_response(_LARAVEL_TRACE_FIXTURE)
    p2 = mine_response(_LARAVEL_TRACE_FIXTURE)  # Same content
    merged = merge_findings([
        ("http://target/page1", p1),
        ("http://target/page2", p2),
    ])
    # Both URLs recorded as evidence
    assert len(merged["evidence_urls"]) == 2
    # But findings are deduped
    assert len([e for e in merged["leaked_emails"] if e == "admin@lavita.internal"]) == 1
    assert merged["framework"] == "Laravel"
    assert merged["install_path"] == "/var/www/html/lavita"


def test_merge_findings_empty():
    assert merge_findings([])["debug_mode"] is False
    assert merge_findings([])["filesystem_paths"] == []


# ─── Baseline helper tests ────────────────────────────────────────────


def _make_baseline(body: str, status: int = 200) -> Baseline:
    import hashlib
    return Baseline(
        available=True,
        status_code=status,
        body_hash=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        body_length=len(body),
    )


def test_baseline_unavailable_never_matches():
    b = Baseline(available=False, status_code=0, body_hash="", body_length=0)
    assert b.matches(200, "anything") is False
    assert b.matches(404, "") is False


def test_baseline_matches_identical_body():
    b = _make_baseline("<html><body>Not found</body></html>")
    assert b.matches(200, "<html><body>Not found</body></html>") is True


def test_baseline_rejects_different_body():
    b = _make_baseline("<html><body>Not found</body></html>")
    assert b.matches(200, "<html><body>WordPress admin login</body></html>") is False


def test_baseline_matches_near_identical_length():
    # SPA catch-all that includes a CSRF token: same shape, tiny variation
    base = "x" * 1000
    b = _make_baseline(base)
    candidate = "x" * 1010  # 1% longer — within 5% tolerance
    assert b.matches(200, candidate) is True


def test_baseline_rejects_different_status_when_length_close():
    b = _make_baseline("payload", status=200)
    assert b.matches(401, "payload") is True   # same body wins regardless
    assert b.matches(401, "different") is False  # different body + different status


def test_baseline_empty_body_matches_when_baseline_empty():
    b = Baseline(available=True, status_code=200, body_hash="", body_length=0)
    assert b.matches(200, "") is True
    assert b.matches(200, "real content") is False


# ─── SPA analyzer tests ───────────────────────────────────────────────

def test_spa_detect_from_techs():
    techs = [{"id": "react", "name": "React"}]
    html = '<div id="root"></div>'
    fw, shell = detect_framework(techs, html)
    assert fw == "React"
    assert shell is True


def test_spa_detect_no_framework():
    techs = [{"id": "jquery", "name": "jQuery"}]
    fw, shell = detect_framework(techs, "<html><body>hello</body></html>")
    assert fw is None
    assert shell is False


def test_spa_detect_nextjs_from_html_only():
    # No tech detection, but __NEXT_DATA__ in HTML → detected from shell patterns
    html = '<html><script id="__NEXT_DATA__" type="application/json">{}</script></html>'
    fw, shell = detect_framework([], html)
    assert fw == "Next.js"
    assert shell is True


def test_spa_detect_nuxt_from_html_only():
    html = '<html><script>window.__NUXT__ = {foo:1};</script></html>'
    fw, shell = detect_framework([], html)
    assert fw == "Nuxt"
    assert shell is True


def test_spa_enumerate_bundles_in_scope():
    html = """
    <html><body>
    <script src="/static/js/main.abc.js"></script>
    <script src="https://target.test/static/js/vendor.def.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/react@18/umd/react.js"></script>
    <script>console.log("inline")</script>
    </body></html>
    """
    v = URLValidator("http://target.test")
    parser = HTMLParser()
    bundles = enumerate_bundles(html, "http://target.test/", v, parser)
    assert "http://target.test/static/js/main.abc.js" in bundles
    assert "https://target.test/static/js/vendor.def.js" in bundles
    assert not any("cdn.jsdelivr" in b for b in bundles)


def test_spa_extract_routes_react_router_v6():
    # Minified-ish React Router v6 shape
    bundle = 'a.jsx(c,{path:"/admin",element:d}),a.jsx(c,{path:"/users/:id",element:e})'
    routes = extract_routes(bundle, "React")
    paths = {r["path"] for r in routes}
    assert "/admin" in paths
    assert "/users/:id" in paths


def test_spa_extract_routes_react_jsx_unminified():
    bundle = '<Route path="/dashboard" element={<Dashboard/>} />'
    routes = extract_routes(bundle, "React")
    assert any(r["path"] == "/dashboard" for r in routes)


def test_spa_extract_routes_vue_router():
    bundle = "const routes=[{path:'/home',component:H},{path:'/about',component:A}]"
    routes = extract_routes(bundle, "Vue.js")
    paths = {r["path"] for r in routes}
    assert "/home" in paths
    assert "/about" in paths


def test_spa_extract_routes_angular():
    bundle = "RouterModule.forRoot([{path:'admin',component:A},{path:'login',component:L}])"
    routes = extract_routes(bundle, "Angular")
    paths = {r["path"] for r in routes}
    # Angular paths lack leading slash; normaliser adds it
    assert "/admin" in paths
    assert "/login" in paths


def test_spa_extract_routes_filters_blocklist():
    bundle = 'path:"/",path:"*",path:"/valid"'
    routes = extract_routes(bundle, "React")
    paths = {r["path"] for r in routes}
    assert paths == {"/valid"}


def test_spa_extract_source_map_url_from_comment():
    bundle = "var a=1;\n//# sourceMappingURL=main.abc.js.map"
    url = extract_source_map_url(bundle, "http://t.test/js/main.abc.js")
    assert url == "http://t.test/js/main.abc.js.map"


def test_spa_extract_source_map_url_fallback():
    bundle = "var a=1; // no source map comment"
    url = extract_source_map_url(bundle, "http://t.test/js/main.js")
    assert url == "http://t.test/js/main.js.map"


def test_spa_extract_source_map_url_rejects_data_uri():
    bundle = "//# sourceMappingURL=data:application/json;base64,eyJ2Ijoz"
    assert extract_source_map_url(bundle, "http://t.test/x.js") is None


def test_spa_parse_source_map_valid():
    sm = json.dumps({
        "version": 3,
        "sources": ["src/App.tsx", "src/api.ts"],
        "sourcesContent": [
            "import React from 'react';\nfetch('/api/users');\n// content of App",
            "export const API='/api/v1'; // content of api",
        ],
    })
    parsed = parse_source_map(sm, preview_chars=30)
    assert parsed is not None
    assert parsed["sources_count"] == 2
    assert parsed["sources"] == ["src/App.tsx", "src/api.ts"]
    # Previews truncated
    assert len(parsed["sources_preview"][0]["preview"]) <= 30


def test_spa_parse_source_map_invalid():
    assert parse_source_map("") is None
    assert parse_source_map("not json") is None
    assert parse_source_map(json.dumps({"no": "sources"})) is None
    assert parse_source_map(json.dumps({"sources": "not a list"})) is None


def test_spa_extract_chunks_webpack():
    runtime = 'e.p+"static/js/"+({0:"abc123",1:"def456",2:"ghi789"}[t]||t)+".chunk.js"'
    chunks = extract_chunks(runtime)
    assert set(chunks) == {"abc123", "def456", "ghi789"}


def test_spa_extract_secrets_aws_access_key():
    bundle = 'const k="AKIAIOSFODNN7EXAMPLE";'
    found = extract_secrets(bundle, "http://t.test/main.js")
    types = {s["type"] for s in found}
    assert "AWS_ACCESS_KEY" in types
    # Redaction format
    aws = [s for s in found if s["type"] == "AWS_ACCESS_KEY"][0]
    assert aws["value_redacted"].startswith("AKIA")
    assert "IOSFODNN7" not in aws["value_redacted"]


def test_spa_extract_secrets_stripe_live():
    # pk_live_ + 24+ chars
    bundle = 'stripe("pk_live_abcdefghij1234567890xyzA");'
    found = extract_secrets(bundle, "http://t.test/main.js")
    assert any(s["type"] == "STRIPE_LIVE_PUB" for s in found)


def test_spa_extract_secrets_generic_api_key():
    bundle = 'const API_KEY = "super_secret_16_chars_minimum"'
    found = extract_secrets(bundle, "http://t.test/main.js")
    assert any(s["type"] == "GENERIC_API_KEY" for s in found)


def test_spa_extract_secrets_firebase():
    # Google API keys are exactly 39 chars: AIza + 35
    bundle = 'firebaseConfig={apiKey:"AIzaSyDOCAbCdEfGhIjKlMnOpQrStUvWxYz0123"}'
    found = extract_secrets(bundle, "http://t.test/main.js")
    types = {s["type"] for s in found}
    assert "FIREBASE_CONFIG_APIKEY" in types or "GOOGLE_API_KEY" in types


def test_spa_extract_state_next_data():
    html = '<script id="__NEXT_DATA__" type="application/json">{"props":{"user":"alice"}}</script>'
    dumps = extract_state_dumps(html, preview_chars=50)
    assert "__NEXT_DATA__" in dumps
    assert "alice" in dumps["__NEXT_DATA__"]["preview"]


def test_spa_extract_state_nuxt():
    html = '<script>window.__NUXT__ = {"foo":"bar","baz":42};</script>'
    dumps = extract_state_dumps(html)
    assert "__NUXT__" in dumps
    assert "foo" in dumps["__NUXT__"]["preview"]


def test_spa_extract_state_none():
    assert extract_state_dumps("<html><body>nothing</body></html>") == {}


def test_fingerprinter_version_extraction():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True,
            "check_cookies": True,
            "check_meta": True,
            "check_scripts": True,
        }
    })
    detections = fp.fingerprint_from_response(
        "http://test.com",
        {"server": "Apache/2.4.41"},
        "<html></html>",
    )
    apache = [d for d in detections if d["name"] == "Apache HTTP Server"]
    assert len(apache) == 1
    assert apache[0]["version"] == "2.4.41"
