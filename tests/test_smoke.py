"""Quick smoke test for all modules."""

import base64
import json
import time
import warnings

from bs4 import XMLParsedAsHTMLWarning

from shatterpoint.crawler import CrawlOrchestrator
from shatterpoint.modules.extractor import Extractor
from shatterpoint.modules.fingerprint import (
    Fingerprinter,
    dedup_technologies,
    finalize_technologies,
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
    build_auth_headers,
    decode_jwt_exp,
    parse_header,
    redact_header_value,
    redact_headers,
    redact_token,
    resolve_headers,
    resolve_token,
    should_send_auth,
    warn_on_expiry,
)
from shatterpoint.utils.baseline import Baseline
from shatterpoint.utils.proxy import normalize_proxy, resolve_proxy
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


def _names(detections):
    return {d["name"] for d in detections}


def test_fingerprint_react_requires_real_marker_not_bare_substring():
    # Precision-first: a bare "react" token in a script/body must NOT fire
    # React (it appears in any bundle referencing react.*); a real React
    # DOM-root marker must.
    fp = Fingerprinter({})
    bare = fp.fingerprint_from_response(
        "http://t", {},
        '<html><body><script>var react = require("react");</script></body></html>',
    )
    assert "React" not in _names(bare)
    real = fp.fingerprint_from_response(
        "http://t", {}, '<html><body><div id="root" data-reactroot=""></div></body></html>',
    )
    assert "React" in _names(real)


def test_fingerprint_vue_requires_real_marker_not_bare_substring():
    fp = Fingerprinter({})
    bare = fp.fingerprint_from_response(
        "http://t", {}, "<html><body><!-- built with Vue.js --></body></html>",
    )
    assert "Vue.js" not in _names(bare)
    real = fp.fingerprint_from_response(
        "http://t", {}, "<html><body><div data-v-app></div><span v-cloak></span></body></html>",
    )
    assert "Vue.js" in _names(real)


def test_fingerprint_jquery_requires_script_src_not_bare_word():
    fp = Fingerprinter({})
    bare = fp.fingerprint_from_response(
        "http://t", {}, "<html><body><script>jquery.fn.extend({});</script></body></html>",
    )
    assert "jQuery" not in _names(bare)
    # Real <script src> includes — WordPress (?ver=), Drupal (?v=), CDN forms
    for src in (
        "/wp-includes/js/jquery/jquery.min.js?ver=3.5.1",
        "/core/assets/vendor/jquery/jquery.min.js?v=3.2.1",
        "https://code.jquery.com/jquery-3.6.0.min.js",
    ):
        det = fp.fingerprint_from_response(
            "http://t", {}, f'<html><head><script src="{src}"></script></head></html>',
        )
        assert "jQuery" in _names(det), src


def test_fingerprint_jenkins_not_from_bare_word_but_header_or_crumb():
    fp = Fingerprinter({})
    # A page merely naming Jenkins (e.g. GitLab's CI-integration label) → no FP
    bare = fp.fingerprint_from_response(
        "http://t", {}, "<html><body>Configure your Jenkins server URL here</body></html>",
    )
    assert "Jenkins" not in _names(bare)
    via_header = fp.fingerprint_from_response("http://t", {"x-jenkins": "2.441"}, "")
    assert "Jenkins" in _names(via_header)
    via_crumb = fp.fingerprint_from_response(
        "http://t", {}, '<html><body><div data-crumb-header="Jenkins-Crumb"></div></body></html>',
    )
    assert "Jenkins" in _names(via_crumb)


def test_fingerprint_gitlab_not_from_bare_word_but_header():
    fp = Fingerprinter({})
    bare = fp.fingerprint_from_response(
        "http://t", {}, "<html><body>this is a mirror of the gitlab repository</body></html>",
    )
    assert "GitLab" not in _names(bare)
    via_header = fp.fingerprint_from_response(
        "http://t", {"x-gitlab-feature-category": "projects"}, "",
    )
    assert "GitLab" in _names(via_header)


def test_fingerprint_content_type_gate_skips_non_html_bodies():
    # A JSON API response whose body contains framework substrings must NOT
    # produce body/script detections via the crawl aggregate; an HTML body
    # with a real marker must. (headers/cookies still apply on any type.)
    from types import SimpleNamespace
    fp = Fingerprinter({})

    json_resp = SimpleNamespace(
        error=None,
        headers={"content-type": "application/json"},
        content_type="application/json",
        body='{"a":"data-reactroot","b":"jquery.min.js","c":"gitlab"}',
        set_cookies=None,
    )
    assert {t["id"] for t in fp.fingerprint_aggregate({"http://t/api": json_resp})} == set()

    html_resp = SimpleNamespace(
        error=None,
        headers={"content-type": "text/html"},
        content_type="text/html; charset=utf-8",
        body="<html><body><div data-reactroot></div></body></html>",
        set_cookies=None,
    )
    assert "react" in {t["id"] for t in fp.fingerprint_aggregate({"http://t/": html_resp})}


def test_fingerprint_springboot_requires_boot_not_bare_spring():
    # Jenkins bundles spring-security (org.springframework.security.*) — the
    # bare "org.springframework" marker FP'd Spring Boot on it. Require
    # org.springframework.BOOT, or the Whitelabel error page.
    fp = Fingerprinter({})
    jenkins_like = fp.fingerprint_from_response(
        "http://t", {},
        "<html><body>org.springframework.security.web.FilterChainProxy</body></html>",
    )
    assert "Spring Boot" not in _names(jenkins_like)
    real_boot = fp.fingerprint_from_response(
        "http://t", {},
        "<html><body>at org.springframework.boot.web.servlet.support.ErrorPageFilter</body></html>",
    )
    assert "Spring Boot" in _names(real_boot)
    whitelabel = fp.fingerprint_from_response(
        "http://t", {}, "<html><body><h1>Whitelabel Error Page</h1></body></html>",
    )
    assert "Spring Boot" in _names(whitelabel)


def test_apache_signature_dropped_path_probes():
    # /.htaccess + /server-status FP'd on nginx (nginx 403s dotfiles) and on
    # PHP dev servers serving .htaccess as 200. Apache = Server banner only.
    assert _sig("apache").get("paths", []) == []
    assert any(h.get("header") == "server" for h in _sig("apache").get("headers", []))


def test_gitlab_signature_dropped_path_probes():
    # /api/v4/ + /users/sign_in aren't GitLab-unique (Grafana 401s /api/v4/).
    assert _sig("gitlab").get("paths", []) == []
    assert "x-gitlab-feature-category" in [
        h.get("header") for h in _sig("gitlab").get("headers", [])
    ]


def test_tomcat_signature_dropped_generic_paths():
    # /docs/ + /examples/ aren't Tomcat-unique (Cacti ships a /docs/ dir →
    # a Tomcat false-positive). Manager paths + "Apache Tomcat" body remain.
    paths = _sig("tomcat").get("paths", [])
    assert "/docs/" not in paths and "/examples/" not in paths
    assert "/manager/html" in paths
    assert any("Apache Tomcat" in b for b in _sig("tomcat").get("body", []))


def test_probe_known_paths_catchall_suppressed():
    # A catch-all server (every path → 200) with a FAILED baseline would
    # otherwise produce a path-probe FP cascade. The catch-all heuristic must
    # suppress: ≥4 unrelated techs matched by path alone → drop them all.
    import asyncio

    import httpx

    from shatterpoint.utils.baseline import Baseline
    fp = Fingerprinter({})

    def handler(request):
        return httpx.Response(200, text="<html>home</html>")  # answers everything

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            # baseline unavailable (simulating the transient fetch failure) →
            # no baseline drop; the heuristic must still catch it.
            b = Baseline(available=False, status_code=0, body_hash="", body_length=0)
            return await fp.probe_known_paths(c, "http://t", baseline=b)

    dets = asyncio.run(go())
    assert dets == [], f"catch-all not suppressed: {[d['id'] for d in dets]}"


def test_probe_known_paths_single_tech_not_suppressed():
    # Control: only WordPress paths 200 → 1 tech → heuristic must NOT fire.
    import asyncio

    import httpx

    from shatterpoint.utils.baseline import Baseline
    fp = Fingerprinter({})

    def handler(request):
        p = request.url.path
        if p.startswith("/wp-") or p == "/xmlrpc.php":
            return httpx.Response(200, text="<html>wp</html>")
        return httpx.Response(404, text="nope")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            b = Baseline(available=False, status_code=0, body_hash="", body_length=0)
            return await fp.probe_known_paths(c, "http://t", baseline=b)

    ids = {d["id"] for d in asyncio.run(go())}
    assert "wordpress" in ids and len(ids) < 4, ids


def test_fetch_baseline_retries_transient_failure():
    # One transient connect error must NOT make the baseline unavailable (that
    # would disable the whole catch-all filter). Retry then succeed.
    import asyncio

    import httpx

    from shatterpoint.utils.baseline import fetch_baseline
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise httpx.ConnectError("transient")
        return httpx.Response(200, text="ok")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await fetch_baseline(c, "http://t")

    b = asyncio.run(go())
    assert b.available is True and calls["n"] >= 3, (b.available, calls["n"])


def test_new_product_signatures_detect_via_markers():
    # The batch-2 depth additions: each product must be NAMED via its FP-safe
    # marker (definitive header/cookie, or a specific title/body string).
    fp = Fingerprinter({})
    cases = [
        ("Webmin", {"server": "MiniServ/1.920"}, "", None),
        ("Apache CouchDB", {"server": "CouchDB/3.3 (Erlang OTP/24)"}, "", None),
        ("Strapi", {"x-powered-by": "Strapi <strapi.io>"}, "", None),
        ("Atlassian Confluence", {"x-confluence-request-time": "1"}, "", None),
        ("Craft CMS", {"x-powered-by": "Craft CMS"}, "", None),
        ("Bludit", {"x-powered-by": "Bludit"}, "", None),
        ("ThinkPHP", {}, "<html><body>built on ThinkPHP</body></html>", None),
        ("Nagios XI", {}, "<title>Nagios XI</title>", None),
        ("Cacti", {}, "", {"Cacti": "abc"}),
        ("OpenNetAdmin", {}, "", {"ona_context_name": "DEFAULT"}),
    ]
    for name, headers, body, cookies in cases:
        names = _names(fp.fingerprint_from_response("http://t", headers, body, cookies))
        assert name in names, (name, names)


def test_framework_recon_fingerprint_only_profiles_have_manual_pointers():
    # Every fingerprint-only profile (empty probe list) must carry a manual
    # CVE pointer — that's the whole point of registering it (signal-only
    # "take a look"), and it keeps _PROFILES / _MANUAL_POINTERS in sync.
    from shatterpoint.modules.framework_recon import _MANUAL_POINTERS, _PROFILES
    for fid, probes in _PROFILES.items():
        if not probes:
            assert fid in _MANUAL_POINTERS, f"{fid} profile has no manual CVE pointer"


def test_paths_200_only_detects_when_reachable():
    # paths_200 (exploit-file presence): a 200 (reachable → vulnerable) detects;
    # a 403 (blocked, e.g. Drupal .htaccess over /vendor) must NOT — that would
    # be a false CVE-2017-9841 lead.
    import asyncio

    import httpx

    from shatterpoint.utils.baseline import Baseline
    fp = Fingerprinter({})
    evalpath = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"

    def make(code):
        def handler(request):
            return httpx.Response(code if request.url.path == evalpath else 404, text="x")
        return handler

    async def run(code):
        async with httpx.AsyncClient(transport=httpx.MockTransport(make(code))) as c:
            b = Baseline(available=True, status_code=404, body_hash="zz", body_length=1)
            return await fp.probe_known_paths(c, "http://t", baseline=b)

    assert "phpunit" in {d["id"] for d in asyncio.run(run(200))}
    assert "phpunit" not in {d["id"] for d in asyncio.run(run(403))}


def test_batch3_product_signatures_detect():
    fp = Fingerprinter({})
    cases = [
        ("Gitea", {}, "", {"i_like_gitea": "x"}),
        ("MinIO", {"server": "MinIO"}, "", None),
        ("Apache Flink", {}, "<title>Apache Flink Web Dashboard</title>", None),
        ("GLPI", {}, "<title>Setup GLPI</title>", None),
        ("Apache Superset", {}, '<script>{"SUPERSET_WEBSERVER_TIMEOUT":60}</script>', None),
    ]
    for name, headers, body, cookies in cases:
        names = _names(fp.fingerprint_from_response("http://t", headers, body, cookies))
        assert name in names, (name, names)


def _html_pages(body, headers, n):
    from types import SimpleNamespace
    return {
        f"http://t/p{i}": SimpleNamespace(
            error=None,
            headers={"content-type": "text/html", **headers},
            content_type="text/html",
            set_cookies=None,
            body=body,
        )
        for i in range(n)
    }


def test_confidence_cap_body_only_capped_at_medium():
    # A single body marker seen across many pages must NOT inflate to HIGH on
    # page-count alone — body/script-only detections cap at medium.
    fp = Fingerprinter({})
    crawl = _html_pages('<nav class="navbar-toggler"></nav>', {}, 6)
    bs = [t for t in fp.fingerprint_aggregate(crawl) if t["id"] == "bootstrap"]
    assert bs and bs[0]["confidence"] == "medium", bs


def test_confidence_cap_preserves_strong_channel_high():
    # Same page count, but via a header (strong channel) → stays HIGH; proves
    # the cap only touches body/script-only detections.
    fp = Fingerprinter({})
    crawl = _html_pages("<html></html>", {"server": "nginx/1.25"}, 6)
    ng = [t for t in fp.fingerprint_aggregate(crawl) if t["id"] == "nginx"]
    assert ng and ng[0]["confidence"] == "high", ng


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


# ─── Wave A regression tests ──────────────────────────────────────────


def test_laravel_does_not_fire_on_bare_php_powered_by():
    """Regression: my earlier Laravel sig had
        headers:
          - header: "x-powered-by"
            pattern: "(?i)PHP"
    which matched every PHP site (WordPress, Drupal, phpMyAdmin, …).
    Confirmed false-positive on the WordPress lab. The Laravel sig
    must require Laravel-specific evidence — cookies/body/forms — not
    a bare PHP banner."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    # A WordPress-like response: PHP banner + WordPress body + no
    # Laravel-specific signals.
    detections = fp.fingerprint_from_response(
        "http://wp.test/",
        {"x-powered-by": "PHP/8.3.31"},
        "<html><body>Welcome to WordPress</body></html>",
        cookies=None,
    )
    names = {d["name"] for d in detections}
    assert "Laravel" not in names, (
        "Laravel must not fire on bare PHP/X.Y.Z X-Powered-By — that's "
        "emitted by every PHP framework"
    )
    # Sanity: PHP itself should still be detected
    assert "PHP" in names


def test_detect_auth_mechanisms_handles_multiple_set_cookies():
    """Regression (Wave A A2): when a server sends multiple Set-Cookie
    headers (Laravel apps send XSRF-TOKEN + laravel_session), the old
    code iterated `headers.items()` and only saw the first/last after
    dict() collapsed duplicates. Now we pass the per-cookie list."""
    recon = ReconModule({}, "http://target.test")

    # Two separate Set-Cookie response headers
    set_cookies = [
        "XSRF-TOKEN=abc123; HttpOnly; SameSite=Lax",
        "laravel_session=def456; HttpOnly; Secure",
    ]
    auth = recon.detect_auth_mechanisms(
        url="http://target.test/",
        headers={},
        body="",
        forms=[],
        set_cookies=set_cookies,
    )
    cookie_findings = [a for a in auth if a["type"] == "Session Cookie"]
    cookie_names = {a["detail"].split("Cookie: ")[1].split(" ")[0] for a in cookie_findings}
    assert "XSRF-TOKEN" in cookie_names, "XSRF-TOKEN session cookie should be detected"
    assert "laravel_session" in cookie_names, "laravel_session should also be detected"


def test_extract_cookies_handles_multiple_set_cookies():
    """Companion to the auth test — fingerprint.py's _extract_cookies
    must also see all Set-Cookie values when given the list."""
    fp = Fingerprinter({"fingerprint": {}})
    cookies = fp._extract_cookies(
        headers={},
        set_cookies=[
            "XSRF-TOKEN=abc; HttpOnly",
            "laravel_session=def; HttpOnly",
        ],
    )
    assert "XSRF-TOKEN" in cookies
    assert "laravel_session" in cookies


def test_load_config_valid_yaml(tmp_path):
    """Regression (Wave A A1): valid YAML loads as a dict."""
    from shatterpoint.crawler import load_config

    cfg = tmp_path / "config.yaml"
    cfg.write_text("target:\n  url: http://x.test\ncrawler:\n  max_depth: 5\n")
    result = load_config(str(cfg))
    assert result["target"]["url"] == "http://x.test"
    assert result["crawler"]["max_depth"] == 5


def test_load_config_malformed_yaml_exits(tmp_path, capsys):
    """Regression (Wave A A1): malformed YAML must exit loudly (non-zero),
    not silently fall back to {} as the original code did."""
    import pytest

    from shatterpoint.crawler import load_config

    cfg = tmp_path / "bad.yaml"
    cfg.write_text("target:\n  url: http://x.test\n  : invalid : yaml :\n")
    with pytest.raises(SystemExit) as exc:
        load_config(str(cfg))
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "YAML syntax errors" in captured.out


def test_load_config_explicit_missing_file_exits(tmp_path, capsys):
    """Regression (Wave A A1): an explicit -c path pointing at a missing
    file must exit loudly rather than silently using defaults."""
    import pytest

    from shatterpoint.crawler import load_config

    with pytest.raises(SystemExit) as exc:
        load_config(str(tmp_path / "does-not-exist.yaml"))
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "config file not found" in captured.out


def test_load_config_default_missing_is_silent(tmp_path, monkeypatch):
    """No -c passed AND no config.yaml in CWD must be silent (running
    without a config is a valid mode)."""
    from shatterpoint.crawler import load_config

    monkeypatch.chdir(tmp_path)  # tmp_path has no config.yaml
    result = load_config(None)
    assert result == {}


def test_parse_robots_extracts_full_sitemap_url():
    """Regression (Wave A A4): parse_robots used to split lines on `:`
    and mangle `Sitemap: https://example.com/x.xml` into
    `//example.com/x.xml` (lost the scheme). Fix splits on the
    `Sitemap:` prefix only."""
    import asyncio

    import httpx

    robots_body = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Sitemap: https://example.com/sitemap.xml\n"
        "Sitemap: https://example.com/news-sitemap.xml\n"
        "Sitemap:/relative-sitemap.xml\n"  # no space — edge case
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            text=robots_body,
        )

    async def run() -> dict:
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            recon = ReconModule({}, "http://example.com")
            return await recon.parse_robots(client)

    result = asyncio.run(run())
    assert result["found"] is True
    assert "/admin/" in result["disallowed"]
    # Full URLs preserved
    assert "https://example.com/sitemap.xml" in result["sitemaps"]
    assert "https://example.com/news-sitemap.xml" in result["sitemaps"]
    # Edge case: no space after "Sitemap:" still works
    assert "/relative-sitemap.xml" in result["sitemaps"]
    # No mangled URLs
    assert not any(s.startswith("//") for s in result["sitemaps"])


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


# ─── Framework CVE signal-recon (precision guards) ────────────────────


def _run_probe_sync(probe, status, body, headers=None):
    """Drive FrameworkRecon._run_probe against a mocked response."""
    import asyncio

    import httpx

    from shatterpoint.modules.framework_recon import FrameworkRecon
    from shatterpoint.utils.baseline import Baseline

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body, headers=headers or {})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            fr = FrameworkRecon({"framework_recon": {"enabled": True}}, URLValidator("http://t.test"))
            # available=False → baseline never matches, so we isolate the
            # confirm_any / escalation logic under test.
            baseline = Baseline(available=False, status_code=0, body_hash="", body_length=0)
            return await fr._run_probe(client, "http://t.test", probe, baseline)

    return asyncio.run(go())


def test_framework_probes_are_passive_get_only():
    """Passivity guard: the Probe dataclass must not carry any field that
    could turn a probe into an exploit (HTTP method override, request
    body, payload). This is the machine-enforced 'we don't exploit'."""
    import dataclasses

    from shatterpoint.modules.framework_recon import Probe

    fields = {f.name for f in dataclasses.fields(Probe)}
    forbidden = {"method", "data", "payload", "json", "body", "headers", "params"}
    leaked = fields & forbidden
    assert not leaked, f"Probe must stay GET-only signal-checks; forbidden fields present: {leaked}"


def test_framework_probes_use_only_get_at_runtime():
    """Runtime passivity guard: running every profile against a mock
    server must issue GET requests only — never POST/PUT/etc."""
    import asyncio

    import httpx

    from shatterpoint.modules.framework_recon import _PROFILES, FrameworkRecon

    methods_seen = set()

    def handler(request: httpx.Request) -> httpx.Response:
        methods_seen.add(request.method)
        return httpx.Response(404, text="not found")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            fr = FrameworkRecon({"framework_recon": {"enabled": True}}, URLValidator("http://t.test"))
            techs = [{"id": fid} for fid in _PROFILES]
            await fr.analyze(client, "http://t.test", techs)

    asyncio.run(go())
    assert methods_seen == {"GET"}, f"framework recon must be GET-only, saw: {methods_seen}"


def test_shared_baseline_is_passed_through_not_refetched(monkeypatch):
    """Wave A2: when the orchestrator threads a baseline in, the path-probe
    modules must USE it and not fetch their own. We monkeypatch each
    module's fetch_baseline to blow up, then confirm a call WITH baseline
    completes — proving the redundant per-module fetch was skipped."""
    import asyncio

    import httpx

    from shatterpoint.modules import fingerprint as fp_mod
    from shatterpoint.modules import framework_recon as fr_mod
    from shatterpoint.modules import recon as recon_mod
    from shatterpoint.modules.fingerprint import Fingerprinter
    from shatterpoint.modules.framework_recon import FrameworkRecon
    from shatterpoint.modules.recon import ReconModule
    from shatterpoint.utils.baseline import Baseline

    async def _boom(*a, **k):
        raise AssertionError("fetch_baseline must NOT run when a baseline is provided")

    monkeypatch.setattr(fp_mod, "fetch_baseline", _boom)
    monkeypatch.setattr(fr_mod, "fetch_baseline", _boom)
    monkeypatch.setattr(recon_mod, "fetch_baseline", _boom)

    shared = Baseline(available=True, status_code=404, body_hash="x", body_length=4)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="nope")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            fr = FrameworkRecon(
                {"framework_recon": {"enabled": True}}, URLValidator("http://t.test")
            )
            await fr.analyze(client, "http://t.test", [{"id": "laravel"}], baseline=shared)

            fpr = Fingerprinter({"fingerprint": {}})
            await fpr.probe_known_paths(client, "http://t.test", baseline=shared)

            rc = ReconModule(
                {"recon": {"common_paths": True, "robots_txt": False,
                           "sitemap_xml": False, "security_txt": False,
                           "auth_detection": False}},
                "http://t.test",
            )
            await rc.run_all(client, baseline=shared)

    asyncio.run(go())  # raises via _boom if any module re-fetched the baseline


def test_framework_probe_cve_format():
    """Every CVE reference across all profiles must be a well-formed CVE ID."""
    import re

    from shatterpoint.modules.framework_recon import _PROFILES

    cve_re = re.compile(r"^CVE-\d{4}-\d{4,}$")
    for fid, probes in _PROFILES.items():
        for probe in probes:
            for cve in (probe.cve, probe.escalate_cve):
                if cve is not None:
                    assert cve_re.match(cve), f"{fid} probe {probe.path} has malformed CVE: {cve}"


def test_confirm_any_gate_drops_200_without_marker():
    """Precision: a 200 lacking every confirm_any marker is NOT the
    framework resource and must be dropped (no false positive)."""
    from shatterpoint.modules.framework_recon import Probe

    probe = Probe("/console", "critical", "Werkzeug debugger",
                  cve="CVE-2024-34069", confirm_any=("werkzeug", "__debugger__"))
    # Generic 200 with no Werkzeug marker → dropped
    assert _run_probe_sync(probe, 200, "<html>generic app page</html>") is None


def test_confirm_any_gate_keeps_200_with_marker():
    from shatterpoint.modules.framework_recon import Probe

    probe = Probe("/console", "critical", "Werkzeug debugger",
                  cve="CVE-2024-34069", confirm_any=("werkzeug", "__debugger__"))
    result = _run_probe_sync(probe, 200, "<title>Werkzeug Debugger</title>")
    assert result is not None
    assert result.status_code == 200
    assert result.cve == "CVE-2024-34069"


def test_confirm_any_bypassed_on_non_200_signal_code():
    """A 403/401 means the route exists but is protected — that's still a
    signal, so the content gate is bypassed for non-200 codes."""
    from shatterpoint.modules.framework_recon import Probe

    probe = Probe("/console", "critical", "Werkzeug debugger",
                  confirm_any=("werkzeug",))
    result = _run_probe_sync(probe, 403, "")
    assert result is not None
    assert result.status_code == 403


def test_env_escalates_to_cve_when_app_key_present():
    """The .env probe escalates to CVE-2018-15133 only when APP_KEY is in
    the body — a reachable .env without it stays a plain critical."""
    from shatterpoint.modules.framework_recon import Probe

    env_probe = Probe(
        "/.env", "critical", "Laravel env file",
        escalate_any=("app_key=base64:", "app_key="),
        escalate_cve="CVE-2018-15133", escalate_note="env with APP_KEY",
    )
    # With APP_KEY → escalated
    leaked = _run_probe_sync(env_probe, 200, "APP_NAME=demo\nAPP_KEY=base64:abc123==\nDB_PASS=x")
    assert leaked is not None
    assert leaked.cve == "CVE-2018-15133"
    assert leaked.note == "env with APP_KEY"
    # Without APP_KEY → base finding, no CVE
    plain = _run_probe_sync(env_probe, 200, "APP_NAME=demo\nDB_HOST=localhost")
    assert plain is not None
    assert plain.cve is None


def test_springboot_profile_covers_critical_endpoints():
    from shatterpoint.modules.framework_recon import _PROFILES

    paths = {p.path for p in _PROFILES["springboot"]}
    for must in ("/actuator/heapdump", "/actuator/gateway/routes", "/actuator/env"):
        assert must in paths, f"Spring Boot profile missing {must}"
    # Gateway routes must carry the SpEL RCE CVE
    gw = next(p for p in _PROFILES["springboot"] if p.path == "/actuator/gateway/routes")
    assert gw.cve == "CVE-2022-22947"


def test_framework_recon_springboot_actuator_end_to_end():
    """Integration (substitutes for the heavy Spring Boot lab): drive the
    full analyze() flow against a simulated actuator target and assert the
    high-value findings + CVE mapping fire, gated by content confirmation."""
    import asyncio

    import httpx

    from shatterpoint.modules.framework_recon import FrameworkRecon

    responses = {
        "/actuator": (200, '{"_links":{"self":{"href":"http://t/actuator"}}}'),
        "/actuator/heapdump": (200, "JAVA PROFILE 1.0.2\x00binaryheapdumpdata"),
        "/actuator/gateway/routes": (200, '[{"route_id":"r1","predicate":"Paths","uri":"lb://svc","filters":[]}]'),
        "/actuator/env": (200, '{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties"}]}'),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        s_b = responses.get(request.url.path)
        if s_b:
            return httpx.Response(s_b[0], text=s_b[1])
        return httpx.Response(404, text="<html>Whitelabel Error Page</html>")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            fr = FrameworkRecon({"framework_recon": {"enabled": True}}, URLValidator("http://t.test"))
            return await fr.analyze(client, "http://t.test", [{"id": "springboot"}])

    result = asyncio.run(go())
    by_path = {p["path"]: p for p in result["probes"]}
    assert "/actuator/gateway/routes" in by_path
    assert by_path["/actuator/gateway/routes"]["cve"] == "CVE-2022-22947"
    assert by_path["/actuator/gateway/routes"]["severity"] == "critical"
    assert "/actuator/heapdump" in by_path           # JAVA PROFILE magic confirmed
    assert "/actuator/env" in by_path                # propertySources confirmed
    assert result["manual_pointers"].get("springboot")  # Spring4Shell/Log4Shell guidance


def test_framework_recon_springboot_no_false_positive_on_catchall():
    """Precision: a catch-all server that 200s everything with the SAME
    body must NOT produce actuator findings (baseline + confirm_any)."""
    import asyncio

    import httpx

    from shatterpoint.modules.framework_recon import FrameworkRecon

    def handler(request: httpx.Request) -> httpx.Response:
        # Every path returns an identical generic SPA shell
        return httpx.Response(200, text="<html><body><div id=root></div></body></html>")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            fr = FrameworkRecon({"framework_recon": {"enabled": True}}, URLValidator("http://t.test"))
            return await fr.analyze(client, "http://t.test", [{"id": "springboot"}])

    result = asyncio.run(go())
    # No actuator JSON markers present anywhere → zero probe findings
    assert result["probes"] == [], f"catch-all should yield no findings, got {result['probes']}"


def test_manual_pointers_present_for_each_framework():
    """The non-recon-detectable CVEs (Spring4Shell, Log4Shell, SSTI, etc.)
    must be surfaced as manual-test guidance, not silently dropped."""
    from shatterpoint.modules.framework_recon import _MANUAL_POINTERS, _PROFILES

    for fid in _PROFILES:
        assert fid in _MANUAL_POINTERS, f"{fid} has no manual-test pointers"
    # Spring4Shell + Log4Shell must be named (they're famous, exam-relevant)
    spring_text = " ".join(_MANUAL_POINTERS["springboot"])
    assert "CVE-2022-22965" in spring_text  # Spring4Shell
    assert "CVE-2021-44228" in spring_text  # Log4Shell


# ─── Precision pass: FP fixes from the VSN lab scan ───────────────────


def _sig(name):
    from pathlib import Path as _P

    import yaml
    return yaml.safe_load(_P("src/shatterpoint/signatures/fingerprints.yaml").read_text()).get(name, {})


def test_django_fingerprint_has_no_generic_admin_paths():
    """Regression: Django `/admin/` + `/static/admin/` fingerprint paths
    caused redirect-FPs on Voyager/GitLab (the fingerprinter follows
    redirects). Django must detect via cookies/body, not /admin paths."""
    paths = _sig("django").get("paths", [])
    assert paths == [], f"Django fingerprint must not carry /admin paths; got {paths}"
    # And the weak x-frame-options:DENY header is gone
    assert _sig("django").get("headers", []) == []


def test_django_still_detected_via_cookies_and_body():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    detections = fp.fingerprint_from_response(
        "http://dj.test/",
        {"set-cookie": "csrftoken=abc; Path=/"},
        '<form><input name="csrfmiddlewaretoken" value="x"></form>',
        cookies={"csrftoken": "abc"},
    )
    assert "Django" in {d["name"] for d in detections}


def test_jenkins_fingerprint_drops_generic_login_path():
    paths = _sig("jenkins").get("paths", [])
    assert "/login" not in paths
    # X-Jenkins header is the definitive signal and must remain
    hdrs = [h.get("header") for h in _sig("jenkins").get("headers", [])]
    assert "x-jenkins" in hdrs


def test_spring_stacktrace_requires_boot_not_bare_springframework():
    """Bare org.springframework (e.g. Jenkins' bundled spring-security)
    must NOT attribute Spring Boot; spring.boot / Whitelabel must."""
    # Jenkins-like page referencing spring-security only → not Spring Boot
    fw, _ = st_detect_framework("at org.springframework.security.web.FilterChainProxy")
    assert fw != "Spring Boot"
    # Real Spring Boot markers still attribute
    assert st_detect_framework("Whitelabel Error Page")[0] == "Spring Boot"
    assert st_detect_framework("at org.springframework.boot.SpringApplication.run")[0] == "Spring Boot"


# ─── Redirect-baseline (catch-all → login) ────────────────────────────


def test_baseline_is_catchall_redirect():
    from shatterpoint.utils.baseline import Baseline

    b = Baseline(available=True, status_code=302, body_hash="", body_length=0,
                 redirect_location="/users/sign_in")
    # Same login target (absolute or relative) → catch-all, drop
    assert b.is_catchall_redirect(302, "/users/sign_in") is True
    assert b.is_catchall_redirect(302, "http://gitlab.test/users/sign_in") is True
    # Different target → a real redirect, keep
    assert b.is_catchall_redirect(302, "/admin/") is False
    # Non-redirect status → not applicable
    assert b.is_catchall_redirect(200, "/users/sign_in") is False
    # No redirect baseline captured → never a catch-all
    b2 = Baseline(available=True, status_code=404, body_hash="", body_length=0)
    assert b2.is_catchall_redirect(302, "/users/sign_in") is False


def test_framework_recon_drops_catchall_login_redirects():
    """Integration: a GitLab-style target that 302s every path to
    /users/sign_in must yield ZERO framework-recon findings even if a
    profile is (mistakenly) triggered."""
    import asyncio

    import httpx

    from shatterpoint.modules.framework_recon import FrameworkRecon

    def handler(request: httpx.Request) -> httpx.Response:
        # Everything → 302 /users/sign_in (the bogus baseline path too)
        return httpx.Response(302, headers={"location": "/users/sign_in"})

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            fr = FrameworkRecon({"framework_recon": {"enabled": True}}, URLValidator("http://gl.test"))
            return await fr.analyze(client, "http://gl.test", [{"id": "laravel"}])

    result = asyncio.run(go())
    assert result["probes"] == [], f"catch-all login redirects must be dropped, got {result['probes']}"


# ─── Voyager / Innoshop product CVE detection ─────────────────────────


def test_voyager_fingerprint_matches_voyager_admin():
    """Voyager admin page (voyager-assets / thecontrolgroup markers) → detected."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    body = (
        '<html><head><link href="/voyager-assets/css/app.css">'
        '<script src="/voyager-assets/js/voyager.js"></script></head>'
        '<body>thecontrolgroup/voyager admin</body></html>'
    )
    detections = fp.fingerprint_from_response("http://t/admin/login", {}, body, cookies=None)
    names = {d["name"] for d in detections}
    assert "Voyager (Laravel Admin)" in names


def test_voyager_profile_maps_cves():
    from shatterpoint.modules.framework_recon import _PROFILES

    by_path = {p.path: p for p in _PROFILES["voyager"]}
    assert by_path["/admin/compass"].cve == "CVE-2024-55415"
    assert by_path["/admin/media"].cve == "CVE-2024-55417"
    assert by_path["/admin/media"].severity == "critical"


def test_voyager_fingerprint_has_no_generic_admin_paths():
    """Precision regression: the Voyager FINGERPRINT must not carry
    /admin/* paths. The fingerprinter follows redirects, so a framework
    whose /admin/* 302s to a 200 login (Django, etc.) would falsely
    match Voyager. /admin/compass lives in the framework_recon profile
    (content-gated) instead."""
    from pathlib import Path as _P

    import yaml

    sig_path = _P("src/shatterpoint/signatures/fingerprints.yaml")
    sigs = yaml.safe_load(sig_path.read_text())
    voyager_paths = sigs.get("voyager", {}).get("paths", [])
    assert voyager_paths == [], (
        f"Voyager fingerprint must rely on body markers, not /admin paths; got {voyager_paths}"
    )


def test_innoshop_fingerprint_and_cve_pointer():
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    body = '<html><body><footer>Powered by Innoshop</footer></body></html>'
    detections = fp.fingerprint_from_response("http://t/", {}, body, cookies=None)
    assert "Innoshop" in {d["name"] for d in detections}

    from shatterpoint.modules.framework_recon import _MANUAL_POINTERS
    assert any("CVE-2025-52921" in p for p in _MANUAL_POINTERS["innoshop"])


def test_voyager_innoshop_do_not_fire_on_plain_laravel():
    """PRECISION: a plain Laravel page (no Voyager/Innoshop markers) must
    NOT be fingerprinted as Voyager or Innoshop — these CVEs only apply
    when the specific product is present."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    body = (
        '<html><body>laravel app, Illuminate\\Routing in a stack trace, '
        '/vendor/laravel/framework/ path</body></html>'
    )
    detections = fp.fingerprint_from_response(
        "http://t/", {"set-cookie": "laravel_session=x"}, body, cookies={"laravel_session": "x"},
    )
    names = {d["name"] for d in detections}
    assert "Laravel" in names
    assert "Voyager (Laravel Admin)" not in names
    assert "Innoshop" not in names


def test_voyager_runtime_probe_fires_on_compass():
    """End-to-end: a Voyager target (compass returns Voyager content) →
    CVE-2024-55415 finding; the catch-all/no-marker case is dropped."""
    from shatterpoint.modules.framework_recon import _PROFILES

    compass = next(p for p in _PROFILES["voyager"] if p.path == "/admin/compass")
    hit = _run_probe_sync(compass, 200, "<html>Voyager Compass dashboard</html>")
    assert hit is not None and hit.cve == "CVE-2024-55415"
    # Generic 200 without Voyager markers → gated out (no false positive)
    assert _run_probe_sync(compass, 200, "<html>unrelated 200 page</html>") is None


# ─── Multi-framework debug detection (stacktrace) ─────────────────────


def test_stacktrace_detects_django_debug_page():
    body = (
        "<h1>ValueError at /boom/</h1>"
        "<table><tr><th>Django Version:</th><td>4.2.11</td></tr></table>"
        "<p>You're seeing this error because you have <code>DEBUG = True</code></p>"
        "Traceback (most recent call last): django.core.handlers.exception"
    )
    fw, version = st_detect_framework(body)
    assert fw == "Django"
    assert version == "4.2.11"


def test_stacktrace_detects_flask_werkzeug_debugger():
    body = '<title>Werkzeug Debugger</title><script src="?__debugger__=yes">Werkzeug/3.0.1</script>'
    fw, version = st_detect_framework(body)
    assert fw == "Flask"
    assert version == "3.0.1"


def test_stacktrace_detects_springboot_whitelabel():
    body = (
        "<h1>Whitelabel Error Page</h1><p>There was an unexpected error</p>"
        "at org.springframework.web.servlet.DispatcherServlet"
    )
    fw, version = st_detect_framework(body)
    assert fw == "Spring Boot"
    assert version is None


def test_stacktrace_framework_clean_page_no_false_positive():
    # A normal page mentioning "debug" loosely must NOT be attributed
    body = "<html><body>Welcome. Toggle debug mode in settings.</body></html>"
    fw, version = st_detect_framework(body)
    assert fw is None


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


def test_grafana_detected_by_strong_signals_no_path_probes():
    """Grafana is detected by its definitive header / cookie / body only.
    ALL path probes were removed: `/login` false-fired on every app with a
    login, and `/api/health` + `/api/datasources` collided with any app
    exposing an /api/* health endpoint (Metabase, ActiveMQ → a Grafana
    false-positive)."""
    fp = Fingerprinter({})
    g = fp.signatures.get("grafana", {})
    assert g.get("paths", []) == [], "grafana must have no path probes"
    assert any(h.get("header") == "x-grafana-org-id" for h in g.get("headers", []))
    assert "grafana_session" in g.get("cookies", [])
    # still detects a real Grafana via its definitive header
    assert "Grafana" in _names(fp.fingerprint_from_response("http://t", {"x-grafana-org-id": "1"}, ""))


def test_batch6_precision_and_detection():
    fp = Fingerprinter({})
    # confluence: the bare word "Confluence" in body (a doc link) must NOT fire;
    # the definitive X-Confluence-Request-Time header must.
    assert "Atlassian Confluence" not in _names(
        fp.fingerprint_from_response("http://t", {}, "<a href='x'>Confluence docs</a>"))
    assert "Atlassian Confluence" in _names(
        fp.fingerprint_from_response("http://t", {"x-confluence-request-time": "1"}, ""))
    # new Java products
    assert "Metabase" in _names(fp.fingerprint_from_response("http://t", {}, "", {"metabase.DEVICE": "x"}))
    assert "Apache Solr" in _names(fp.fingerprint_from_response("http://t", {}, "<title>Solr Admin</title>"))
    assert "Apache ActiveMQ" in _names(fp.fingerprint_from_response("http://t", {}, "<h1>Apache ActiveMQ</h1>"))


def test_laravel_signature_form_fields_token_only():
    """Laravel sig keeps the Laravel-specific `_token` form field but NOT
    `_method` — `_method` is shared by Rails/Symfony and was triggering a
    false-positive Laravel-profile cascade on GitLab (a Rails app)."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    laravel_form_fields = fp.signatures.get("laravel", {}).get("form_fields", [])
    assert "_token" in laravel_form_fields
    assert "_method" not in laravel_form_fields


def test_laravel_does_not_fire_on_rails_method_field():
    """Regression (GitLab cascade): a Rails form with `_method` +
    `authenticity_token` must NOT fingerprint as Laravel."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    forms = [{
        "found_on": "http://gitlab.test/",
        "inputs": [
            {"name": "_method", "type": "hidden", "tag": "input"},
            {"name": "authenticity_token", "type": "hidden", "tag": "input"},
        ],
    }]
    detections = fp.fingerprint_from_response(
        "http://gitlab.test/", {}, "<html>GitLab</html>", cookies=None, forms=forms,
    )
    assert "Laravel" not in {d["name"] for d in detections}


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


def test_finalize_technologies_dedups_then_resolves():
    # finalize_technologies must equal resolve_conflicts(dedup_technologies(x))
    # — collapse the duplicate laravel entries first (so its merged evidence
    # is strongest), THEN drop the conflicting weaker rails. Order matters:
    # resolving before dedup would compare an un-merged laravel against rails.
    sigs = {
        "laravel": {"incompatible_with": ["rails"]},
        "rails": {"incompatible_with": ["laravel"]},
    }
    techs = [
        _tech("laravel", methods=2, confidence="medium"),
        {  # second laravel hit via a different method → merges to 3 methods
            "id": "laravel",
            "name": "Laravel",
            "matched_on": [{"method": "path_probe", "detail": "/_ignition"}],
            "confidence": "medium",
        },
        _tech("rails", methods=2, confidence="medium"),
    ]
    result = finalize_technologies(techs, sigs)
    ids = [t["id"] for t in result]
    # laravel deduped to a single, stronger entry; rails dropped as weaker
    assert ids == ["laravel"]
    assert result == resolve_conflicts(dedup_technologies(techs), sigs)


def test_finalize_technologies_empty():
    assert finalize_technologies([], {}) == []


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


def test_fingerprint_form_field_requires_hidden_type():
    """Regression (Wave A audit A3): visible <input name="_token"> on an
    unrelated app must NOT fire a Laravel-style form_fields detection.
    Only type=hidden inputs count as CSRF-token evidence."""
    fp = Fingerprinter({
        "fingerprint": {
            "check_headers": True, "check_cookies": True,
            "check_meta": True, "check_scripts": True,
        }
    })
    fp.signatures["__test_hidden_only"] = {
        "name": "TestHiddenOnly",
        "category": "Framework",
        "form_fields": ["_token"],
    }
    # Visible text input named _token — should NOT match
    forms_visible = [{
        "found_on": "http://other.test/",
        "inputs": [
            {"tag": "input", "type": "text", "name": "_token", "value": ""},
        ],
    }]
    detections = fp.fingerprint_from_response(
        "http://other.test/", {}, "<html></html>", cookies=None, forms=forms_visible,
    )
    names = {d["name"] for d in detections}
    assert "TestHiddenOnly" not in names, (
        "form_fields must require type=hidden; visible inputs should not match"
    )

    # Hidden input — should match
    forms_hidden = [{
        "found_on": "http://target.test/",
        "inputs": [
            {"tag": "input", "type": "hidden", "name": "_token", "value": "abc"},
        ],
    }]
    detections = fp.fingerprint_from_response(
        "http://target.test/", {}, "<html></html>", cookies=None, forms=forms_hidden,
    )
    names = {d["name"] for d in detections}
    assert "TestHiddenOnly" in names


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


# ─── Arbitrary auth headers (-H) ──────────────────────────────────────


def test_parse_header_basic():
    assert parse_header("X-API-Key: abc123") == ("X-API-Key", "abc123")


def test_parse_header_value_with_colons():
    # Value may contain colons (Bearer x:y, URLs, cookies) — split on first only
    assert parse_header("Authorization: Bearer a.b:c") == ("Authorization", "Bearer a.b:c")
    assert parse_header("Cookie: session=1; path=/") == ("Cookie", "session=1; path=/")


def test_parse_header_malformed():
    assert parse_header("no-colon") is None
    assert parse_header(": empty-name") is None
    assert parse_header("") is None


def test_resolve_headers_cli_overrides_config_case_insensitive():
    config = {"auth": {"headers": {"X-API-Key": "from-config", "X-Tenant": "acme"}}}
    headers, errors = resolve_headers(["x-api-key: from-cli", "bad-header"], config)
    # CLI wins on case-insensitive name match; config-only header kept
    assert headers.get("x-api-key") == "from-cli"
    assert "X-API-Key" not in headers  # old-case key removed by CI override
    assert headers.get("X-Tenant") == "acme"
    assert errors == ["bad-header"]


def test_resolve_headers_empty():
    headers, errors = resolve_headers(None, {})
    assert headers == {}
    assert errors == []


def test_build_auth_headers_bearer_plus_custom():
    out = build_auth_headers("tok", {"X-API-Key": "k"})
    assert out["Authorization"] == "Bearer tok"
    assert out["X-API-Key"] == "k"


def test_build_auth_headers_explicit_authorization_overrides_token():
    # -H "Authorization: Basic ..." must win over the --token bearer
    out = build_auth_headers("tok", {"Authorization": "Basic dXNlcjpwYXNz"})
    assert out["Authorization"] == "Basic dXNlcjpwYXNz"
    assert len([k for k in out if k.lower() == "authorization"]) == 1


def test_redact_header_value_preserves_scheme():
    assert redact_header_value("Authorization", "Bearer " + "x" * 40).startswith("Bearer ")
    assert "x" * 40 not in redact_header_value("Authorization", "Bearer " + "x" * 40)
    # Non-scheme value redacted whole
    r = redact_header_value("X-API-Key", "supersecretapikeyvalue")
    assert "supersecretapikey" not in r


def test_redact_headers_dict():
    red = redact_headers({"X-API-Key": "supersecretapikeyvalue", "X-Tenant": "acme"})
    assert "supersecretapikey" not in red["X-API-Key"]


def test_auth_strip_hook_strips_custom_headers_cross_origin():
    """CRITICAL precision/safety: the recon-client origin-strip hook must
    remove custom auth headers on a cross-origin redirect (httpx only
    auto-strips Authorization, not X-API-Key / Cookie). Empirically drives
    the hook against a MockTransport that 302s off-origin."""
    import asyncio

    import httpx

    from shatterpoint.utils.auth import make_auth_strip_hook

    seen: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[str(request.url)] = {
            k.lower(): v for k, v in request.headers.items()
        }
        if request.url.host == "target.test":
            # redirect off-origin to a third party
            return httpx.Response(302, headers={"location": "http://evil.test/landing"})
        return httpx.Response(200, text="ok")

    hook = make_auth_strip_hook("http", "target.test", {"Authorization", "X-API-Key", "Cookie"})

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer secret", "X-API-Key": "apikey", "Cookie": "s=1"},
            event_hooks={"request": [hook]},
        ) as client:
            await client.get("http://target.test/start", follow_redirects=True)

    asyncio.run(go())
    # On-origin request keeps the auth headers
    on = seen["http://target.test/start"]
    assert on.get("x-api-key") == "apikey"
    assert on.get("authorization") == "Bearer secret"
    # Off-origin redirect target must have ALL auth headers stripped
    off = seen["http://evil.test/landing"]
    assert "x-api-key" not in off, "custom header leaked off-origin!"
    assert "cookie" not in off, "cookie leaked off-origin!"
    assert "authorization" not in off, "authorization leaked off-origin!"


def test_spider_auth_headers_combined_and_origin_scoped():
    """Spider._auth_headers_for returns bearer + custom for same-origin,
    nothing for cross-origin."""
    cfg = {
        "target": {"url": "http://target.test"},
        "auth": {"token": "tok", "headers": {"X-API-Key": "k", "Cookie": "s=1"}},
    }
    v = URLValidator("http://target.test")
    sp = Spider(cfg, v)
    same = sp._auth_headers_for("http://target.test/admin")
    assert same["Authorization"] == "Bearer tok"
    assert same["X-API-Key"] == "k"
    assert same["Cookie"] == "s=1"
    # cross-origin → nothing
    assert sp._auth_headers_for("http://evil.test/x") == {}


# ─── Proxy resolution + plumbing tests ────────────────────────────────


def test_normalize_proxy_bare_hostport_defaults_to_http():
    """A bare host:port (Burp / mitmproxy) gets an http:// scheme."""
    url, err = normalize_proxy("127.0.0.1:8080")
    assert err is None
    assert url == "http://127.0.0.1:8080"


def test_normalize_proxy_preserves_socks5h():
    """socks5h (TOR — DNS resolved through the proxy) is preserved verbatim."""
    url, err = normalize_proxy("socks5h://127.0.0.1:9050")
    assert err is None
    assert url == "socks5h://127.0.0.1:9050"


def test_normalize_proxy_preserves_explicit_http_and_https():
    assert normalize_proxy("http://10.0.0.1:8080") == ("http://10.0.0.1:8080", None)
    assert normalize_proxy("https://10.0.0.1:8443") == ("https://10.0.0.1:8443", None)


def test_normalize_proxy_empty_is_no_proxy():
    """Empty / blank / None means 'no proxy requested' — not an error."""
    assert normalize_proxy(None) == (None, None)
    assert normalize_proxy("") == (None, None)
    assert normalize_proxy("   ") == (None, None)


def test_normalize_proxy_rejects_bad_scheme():
    url, err = normalize_proxy("ftp://127.0.0.1:21")
    assert url is None
    assert err and "scheme" in err


def test_normalize_proxy_rejects_missing_host():
    url, err = normalize_proxy("http://")
    assert url is None
    assert err and "host" in err


def test_resolve_proxy_cli_beats_config():
    """CLI --proxy overrides config['proxy']['url']."""
    cfg = {"proxy": {"url": "http://config-proxy:8080"}}
    assert resolve_proxy("socks5h://127.0.0.1:9050", cfg) == ("socks5h://127.0.0.1:9050", None)


def test_resolve_proxy_falls_back_to_config():
    cfg = {"proxy": {"url": "127.0.0.1:8080"}}
    assert resolve_proxy(None, cfg) == ("http://127.0.0.1:8080", None)


def test_resolve_proxy_none_when_unset():
    assert resolve_proxy(None, {}) == (None, None)
    assert resolve_proxy(None, {"proxy": {"url": None}}) == (None, None)


def test_resolve_proxy_propagates_error():
    """A malformed proxy is surfaced as an error so the caller aborts —
    it must never silently fall back to a direct (deanonymising) connection."""
    url, err = resolve_proxy(None, {"proxy": {"url": "ftp://x:1"}})
    assert url is None
    assert err


def test_proxy_plumbed_into_orchestrator_and_spider():
    """A resolved proxy reaches BOTH httpx clients: the recon client (via
    CrawlOrchestrator.proxy_url) and the crawl client (via Spider.proxy_url).
    This is what guarantees ALL traffic is routed through the proxy."""
    cfg = {
        "target": {"url": "http://t.test"},
        "proxy": {"url": "socks5h://127.0.0.1:9050"},
    }
    orch = CrawlOrchestrator(cfg)
    assert orch.proxy_url == "socks5h://127.0.0.1:9050"
    assert orch.spider.proxy_url == "socks5h://127.0.0.1:9050"


def test_proxy_absent_by_default():
    """No proxy config → both clients connect directly (proxy_url is None)."""
    orch = CrawlOrchestrator({"target": {"url": "http://t.test"}})
    assert orch.proxy_url is None
    assert orch.spider.proxy_url is None


def test_spider_reads_proxy_from_config():
    """Spider picks the proxy straight out of config['proxy']['url']."""
    cfg = {"target": {"url": "http://t.test"}, "proxy": {"url": "http://127.0.0.1:8080"}}
    sp = Spider(cfg, URLValidator("http://t.test"))
    assert sp.proxy_url == "http://127.0.0.1:8080"


# ─── XML-aware parsing tests (no XMLParsedAsHTMLWarning) ──────────────

_SITEMAP_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    '<url><loc>https://example.com/a/</loc></url>'
    '<url><loc>https://example.com/b/</loc></url>'
    '</urlset>'
)
_RSS_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<rss version="2.0"><channel><title>Feed</title>'
    '<item><link>https://example.com/post/1</link></item></channel></rss>'
)
_OEMBED_XML = (
    # WordPress oembed: XML root <oembed> but contains an <html> CHILD (the
    # escaped embed markup). Routing must key on the root, not "<html> present".
    '<?xml version="1.0"?>'
    '<oembed><type>rich</type><version>1.0</version>'
    '<html>&lt;iframe src="https://example.com/embed"&gt;&lt;/iframe&gt;</html>'
    '</oembed>'
)
_HTML_DOC = (
    '<!DOCTYPE html><html><head><title>Hi</title></head><body>'
    '<a href="/x">x</a><form action="/login" method="post">'
    '<input type="password" name="pwd"></form></body></html>'
)
_XHTML_DOC = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml">'
    '<head><title>X</title></head><body>'
    '<form action="/go" method="post"><input name="q"></form></body></html>'
)


def _emits_xml_warning(fn) -> bool:
    """Run fn() with all filters reset and report whether bs4 raised an
    XMLParsedAsHTMLWarning (so this tests the parser fix itself, not the
    process-wide filterwarnings backstop installed by crawler.py)."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        fn()
    return any(isinstance(w.message, XMLParsedAsHTMLWarning) for w in caught)


def test_make_soup_no_warning_on_sitemap():
    p = HTMLParser()
    assert not _emits_xml_warning(lambda: p.extract_links(_SITEMAP_XML, "https://example.com"))


def test_make_soup_no_warning_on_rss():
    p = HTMLParser()
    assert not _emits_xml_warning(lambda: p.extract_links(_RSS_XML, "https://example.com"))


def test_make_soup_no_warning_on_oembed():
    p = HTMLParser()
    # extract_forms + extract_comments also fed the HTML parser before the fix.
    assert not _emits_xml_warning(lambda: p.extract_forms(_OEMBED_XML, "https://example.com"))
    assert not _emits_xml_warning(lambda: p.extract_comments(_OEMBED_XML, "https://example.com"))


def test_make_soup_html_path_intact():
    """HTML still parses correctly — no behaviour regression on real pages."""
    p = HTMLParser()
    links = p.extract_links(_HTML_DOC, "https://example.com")
    assert "/x" in links
    forms = p.extract_forms(_HTML_DOC, "https://example.com")
    assert len(forms) == 1
    assert forms[0]["has_password_field"] is True


def test_make_soup_xhtml_prolog_is_html():
    """XHTML carries an <?xml?> prolog but has an <html> root → parse as HTML
    so its form is still extracted (the prolog must not divert it to XML)."""
    p = HTMLParser()
    forms = p.extract_forms(_XHTML_DOC, "https://example.com")
    assert len(forms) == 1
    assert forms[0]["action"] == "/go"


def test_make_soup_malformed_xml_degrades():
    """Truncated / junk XML must not raise or warn."""
    p = HTMLParser()
    assert not _emits_xml_warning(
        lambda: p.extract_links("<?xml version='1.0'?><urlset><url><loc>htt", "x")
    )
    assert p.extract_forms("<?xml broken <<<", "x") == []


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
