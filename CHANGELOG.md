# Changelog

All notable changes to **shatterpoint** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version numbers are produced at release time from the GitHub Actions
`MAJOR_VERSION` and `MINOR_VERSION` variables; the patch component
auto-increments. See [README — Release process](README.md) for details.

## [Unreleased]

### Added
- **Framework CVE signal-recon** across Laravel, Django, Flask, Spring Boot, and Next.js. The `--framework-recon` profiles now map detected exposures to their CVEs with a "verify manually" disposition. **Signal-only — never exploit**: every probe is a content-gated GET, enforced by a CI passivity-guard test. Source-verified CVE catalog (2018–2025): Laravel Ignition **CVE-2021-3129** + APP_KEY **CVE-2018-15133**; Spring Cloud Gateway **CVE-2022-22947** + actuator heapdump/env/jolokia; Flask Werkzeug debugger **CVE-2024-34069**; Django admin/debug-toolbar + DEBUG→pickle chain; Next.js **CVE-2025-29927** (version note).
  - `Probe` gained `cve`, `confirm_any` (body-content precision gate so a generic `/console` or `/admin/` 200 can't false-positive), and escalation fields (a reachable `.env` escalates to CVE-2018-15133 when `APP_KEY` is present).
  - `_MANUAL_POINTERS`: CVEs that need a payload to confirm (Spring4Shell **CVE-2022-22965**, Log4Shell **CVE-2021-44228**, Jinja2 SSTI, Next.js middleware bypass, Laravel env-manipulation) are surfaced as manual-test guidance, **never auto-probed**.
  - New `springboot` fingerprint signature; multi-framework debug-page attribution in the stack-trace miner (Django technical-500, Werkzeug debugger, Spring Whitelabel).
  - CVE column in the framework-recon report table + manual-pointers tree.
- **Three new Docker labs** (`labs/django`, `labs/flask`, `labs/springboot`) on ports 8084–8086, wired into `docker-compose.yml` + `Makefile`. All six labs verified end-to-end, including a WordPress/Rails cross-check proving zero framework bleed.

### Changed
- **`MAJOR_VERSION` / `MINOR_VERSION` hardcoded in `release.yml`** (was GitHub repo Variables) so the version line is monitored in the codebase and reviewed via PR. Also fixes the cause of the first release run not tagging.

### Fixed
- **Drupal false-positive on Django (and other framework) targets.** Drupal's signature listed the non-Drupal-specific paths `/user/login` and `/admin/content`; Django's admin redirects `/admin/content` → 302, producing a phantom Drupal detection. Tightened to Drupal-unique paths (`/core/misc/drupal.js`, `/core/CHANGELOG.txt`, `/sites/default/`, `/core/install.php`). Surfaced by the new Django lab.
- **Framework deep recon** (`--framework-recon`). New Phase 1.7 module that runs framework-specific path probes when a supported framework is detected. v1 ships a **Laravel intel pack**: `/_ignition/health-check`, `/_ignition/execute-solution`, `/telescope`, `/horizon`, `/log-viewer`, `/storage/logs/laravel.log`, `/.env` (+ `.bak` / `.example` / `.production` / `.local` variants), `/composer.json`, `/composer.lock`, `/artisan`, `/server.php`, `/api/user`, `/sanctum/csrf-cookie`, `/livewire/livewire.js`. Severity-tagged. 404-baseline filtered. **No CVE numbers in output** — surfaces the exposure and stops there.
- **Stack-trace miner** (`utils/stacktrace.py`). Runs on every crawled response. Extracts: debug-mode flag (when exceptions render to the client), framework + version (Laravel via Illuminate / Symfony / vendor-path markers), filesystem install path, Ignition exposure flag, PHP version. PII pass: leaked emails (within stack-trace context), RFC 1918 internal IPs, internal hostnames (`*.internal` / `*.local` / `*.svc.cluster.local`), AWS access keys (redacted) / ARNs / EC2 instance IDs, database connection URIs with credentials redacted to `scheme://user:***@host:port/db`.
- **Conflict resolution** for fingerprints (`resolve_conflicts`). Signatures can declare `incompatible_with:`; when mutually exclusive techs both fire, strongest evidence wins (most distinct methods, then most matches, then highest confidence). Ties keep both.
- **Form-field signature channel** (`form_fields:` in fingerprints.yaml). Frameworks with characteristic hidden form field names (Laravel `_token`, `_method`) now contribute fingerprint evidence.
- **`framework_recon` + `debug_exposure` sections** in the JSON report and Rich CLI summary. Severity-tagged table for framework-recon probes; tree view for debug exposures.
- 41 new unit tests covering the stack-trace miner, conflict resolution, form-field signatures, FrameworkRecon orchestration, and the false-positive fixes below.

### Changed
- **Rails signature tightened**: removed blanket `<meta name="csrf-token">` match (collided with Laravel and every other CSRF-using framework). Now requires Rails-specific evidence: `x-runtime` header, `_session_id` / `_rails_session` cookie, `rails-ujs` / `data-turbo` / `Started GET` body markers. Declares `incompatible_with: [laravel, django, symfony]`.
- **Grafana signature tightened**: removed `/login` (every framework has /login). Now requires Grafana-specific evidence: `x-grafana-org-id` header, `grafana_session` cookie, `grafana-app` / `grafanaBootData` body markers, `/api/datasources` or `/public/build/runtime` paths.
- **Laravel signature strengthened**: added `Illuminate\\` namespace marker, `/vendor/laravel/framework/` body string, `Symfony\\Component\\HttpKernel` marker, `_token` / `_method` form fields, `/_ignition/health-check` path. Declares `incompatible_with: [rails, django, symfony]`.

### Fixed
- **Laravel false-positive on every PHP site.** The Laravel signature included `x-powered-by: PHP` as a header match — that's emitted by WordPress, Drupal, Joomla, phpMyAdmin, and basically anything PHP. Surfaced by scanning the new WordPress lab. The header check is removed; Laravel detection now requires Laravel-specific evidence (cookies, body, form fields, paths). Regression test added so this can't regress quietly.
- **Lab/Laravel Composer build broke on advisory-affected packages.** Composer 2.7+ refuses to install packages with active security advisories, which is the exact opposite of what an intentionally-vulnerable lab wants. The Laravel lab now sets `composer config policy.advisories.block false` for the builder stage.
- **Lab/Rails build broke on the `psych` gem.** Missing `libyaml-dev` system dep. Added.
- **Multiple `Set-Cookie` headers were collapsed.** `dict(httpx.Headers)` merges duplicate headers into a single comma-joined string, so a Laravel app sending `XSRF-TOKEN` + `laravel_session` as separate Set-Cookie headers was only producing one session-cookie finding. CrawlResult now carries a `set_cookies: list[str]` populated via `httpx.Headers.get_list("set-cookie")`; both `detect_auth_mechanisms` and `Fingerprinter._extract_cookies` accept it and iterate per-cookie. Both cookies now surface.
- **Silent config errors.** `load_config()` used to return `{}` whenever the file was missing or malformed — operators passing `-c custom.yaml` could be running with defaults and never know. Now: explicit `-c` with a missing file exits 2 with a clear error; any `yaml.YAMLError` exits 2 with the parser's line/column message; missing-by-default still silent (running without a config is a valid mode).
- **`form_fields:` signature channel matched visible inputs.** A non-hidden `<input name="_token">` was firing Laravel detection. Now requires `type="hidden"` to count as CSRF-token evidence.
- **`parse_robots` mangled sitemap URLs.** `line.split(":", 1)[1]` on `Sitemap: https://example.com/sitemap.xml` dropped the scheme, producing `//example.com/sitemap.xml`. Fixed by stripping the `Sitemap:` prefix instead of splitting on `:`.
- **Dead code removed.** `Extractor.find_interesting_paths` (never called) and its companion `INTERESTING_PATHS` regex.
- **Pipeline ordering bug**: framework_recon ran BEFORE the landing-page body detection that's the only way to identify Laravel on production targets with Ignition disabled. New Phase 1.6 fetches the landing HTML and runs body/cookie/form-field detection (and re-runs dedup + conflict resolution) BEFORE Phase 1.7. SPA analysis now reuses the already-fetched landing HTML in Phase 1.8.
- **Silent `--framework-recon` no-op**: as a consequence of the ordering bug, `--framework-recon` would silently do nothing on production Laravel targets despite being explicitly enabled by the user. Fixed by the pipeline reorder above.
- **Laravel body pattern never matched real Laravel output**: YAML double-escaping (`"Illuminate\\\\"`) parsed to a Python string requiring two literal backslashes, but real Laravel error pages render `Illuminate\Routing` with single backslashes. Patterns corrected to `"Illuminate\\Routing"` / `"Illuminate\\Foundation"` / `"Symfony\\Component\\HttpKernel"`.
- **Bootstrap false-positive on Laravel error pages**: bare `bootstrap` substring matched Laravel's `/bootstrap/app.php` filename in stack traces. Bootstrap signature now requires CSS-framework-specific evidence (`bootstrap.min.css`, `navbar-toggler`, `container-fluid`, `data-bs-toggle`).
- Three pre-existing E501 lint errors (long lines in `crawler.py`, `extractor.py`, `recon.py`) that were blocking the initial CI run.

### Internal
- **`labs/` directory with Docker-based test targets**. Real frameworks in known states, orchestrated via a single `docker compose` + `Makefile` so the deep-recon paths can be exercised end-to-end without an OSCP VPN.
  - `labs/laravel/` — intentionally vulnerable Laravel 10 (PHP 8.4): `APP_DEBUG=true`, `/_ignition/*` reachable, `/.env` leaked to web root, `/trigger-error` route renders a full Ignition stack trace. End-to-end verified: framework_recon + debug_exposure + stack-trace mining all light up correctly.
  - `labs/rails/` — plain Rails 7 install for the false-positive regression check (the Rails signature tightening must still detect real Rails).
  - `labs/wordpress/` — official `wordpress:6` image + MariaDB 10.11 sidecar, fresh install. Exercises CMS path probing + 404-baseline filter on a real-world catch-all-style server.
  - `labs/Makefile` — `make up / down / scan-laravel / scan-laravel-recon / scan-rails / scan-wordpress / scan-all`.
  - All three on adjacent ports (8081/8082/8083) to avoid the common 80xx range.

---

## [1.0.0] - 2026-05-17

First public release. The `1.0` line covers the full initial feature set: web reconnaissance pipeline, authenticated crawling, SPA bundle mining, and the release-engineering infrastructure that ships it. Subsequent `1.0.x` patches accumulate here until the project ships `1.1.0`.

### Added

#### Core crawl pipeline
- **Async crawler** with httpx + asyncio. Configurable concurrency (default 15), depth limit, page cap, manual redirect-chain tracking, strict single-domain scope enforcement.
- **HTML extraction**: forms with `has_file_upload` / `has_password_field` / `has_csrf_token` flags, comments with keyword tagging, emails, meta tags, inline + external scripts.
- **API endpoint extraction** from URL patterns, response content types, and inline JS via 7 regex shapes (`fetch`, `axios`, `XMLHttpRequest.open`, jQuery AJAX, `url: "..."` assignments, quoted absolute paths).
- **Reconnaissance modules**: `robots.txt` and `sitemap.xml` parsing, `security.txt` (RFC 9116) check, 78-path common-paths probe, passive auth-mechanism detection (Basic / Digest / NTLM / Kerberos / Bearer / login forms / session cookies).

#### Technology fingerprinting
- **27 technology signatures** — CMS (WordPress, Drupal, Joomla), web servers (Apache, Nginx, IIS, Tomcat), languages (PHP, ASP.NET), frameworks (Flask, Django, Express, Rails, Laravel, Angular, React, Vue.js, Next.js, Nuxt), libraries (jQuery, Bootstrap), tools (phpMyAdmin, Webmin, Grafana, Jenkins, GitLab), CDN/WAF (Cloudflare).
- Multi-method detection (headers, cookies, meta, body, scripts, paths) with `high` / `medium` / `low` confidence scoring.
- **Content-baseline noise suppression** for path probing. Both `ReconModule.probe_common_paths` and `Fingerprinter.probe_known_paths` fetch a known-404 baseline and drop probes whose response matches it (sha256 hash or ±5% body length). Eliminates the false-positive flood on SPA catch-all routers.
- **Technology dedup** across pipeline phases via `dedup_technologies()` — merges by id, concatenates `matched_on`, prefers non-empty versions, promotes to highest confidence.
- **Word-boundary fingerprint matching** — body patterns use `(?<!\w)…(?!\w)` so `"wordpress"` no longer false-fires on `"wordpresslike"` or minified bundle content.

#### Authenticated crawling (`--token`)
- `--token <jwt>` sends `Authorization: Bearer <token>` to same-origin requests. Token resolution order: CLI flag > `SHATTERPOINT_TOKEN` env > `config.yaml:auth.token`.
- JWT `exp` claim decoded with expiry warning.
- Token redacted as `first4…last4` in banner, logs, and saved JSON reports.
- Origin-scoped redirect strip prevents leaking the bearer to third-party hosts.

#### SPA bundle mining (`--spa`)
- Fetches same-origin JS bundles for React / Vue / Angular / Next.js / Nuxt.
- Probes source maps (parses `sources[]` and `sourcesContent[]`).
- Extracts client-side routes and seeds them as Phase 2 crawl URLs.
- Extracts API endpoints from compiled JS.
- Decodes framework state dumps (`__NEXT_DATA__`, `__NUXT__`, `__INITIAL_STATE__`).
- Detects curated baked-in secrets: AWS keys, Google API keys, Stripe live keys, Slack tokens, GitHub tokens, Firebase config, generic `API_KEY=`/`SECRET=`/`TOKEN=` assignments. All values redacted with the same `first4…last4` format.
- Depth-1 webpack chunk-map enumeration.
- **SPA framework detection** runs every scan; if a framework is detected but `--spa` isn't set, the tool prints a hint suggesting `--spa`.

#### Output + UX
- **Auth / Security-Header taxonomy split** — `results["security_headers"]` is its own section. CSP, HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Permissions-Policy, Referrer-Policy, COOP/COEP/CORP no longer pollute `auth_mechanisms`.
- **Structured JSON report** with 18 documented sections.
- **Rich CLI output** with phase headers, finding bullets, summary tables, tree views.
- **Banner in `--help`** output (custom argparse formatter subclass).

#### Release engineering
- **Dynamic versioning** via `hatch-vcs` — version derived from git tags at build time. No version string in source code, no commit-back-to-main loop.
- **GitHub Actions CI** (`ci.yml`): ruff lint + pytest across Python 3.11/3.12/3.13 + CHANGELOG-enforcement on PRs.
- **GitHub Actions release pipeline** (`release.yml`): on every merge to `main`, computes `vMAJOR.MINOR.PATCH` from repo Variables, builds multi-arch (`linux/amd64`, `linux/arm64`) Docker image, pushes to `0xj4f/shatterpoint` Docker Hub with three tags (immutable + minor-floating + `latest`), creates GitHub Release with auto-generated notes.
- **Dockerfile**: single-stage, installs pre-built wheel, OCI labels, `/app/output` volume.
- **CHANGELOG enforcement**: every PR into `main` must touch `CHANGELOG.md`.

### Removed
- `Spider.probe_url` — dead code; SPA module now fetches bundles directly via the recon client.
- `direnum` config block — referenced feroxbuster integration that was never wired up.

### Internal
- Test suite: 76 fixture-based unit tests covering auth, baseline, dedup, fingerprint word-boundary, SPA framework detection, route extraction (React Router v6, Vue Router, Angular), source-map parsing, webpack chunk extraction, secret patterns, and HTTP security-header detection.
- Project renamed from `0xj4f-webcrawler` to `shatterpoint`.

[Unreleased]: https://github.com/0xj4f/shatterpoint/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/0xj4f/shatterpoint/releases/tag/v1.0.0
