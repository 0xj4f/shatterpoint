# Changelog

All notable changes to **shatterpoint** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version numbers are produced at release time from the GitHub Actions
`MAJOR_VERSION` and `MINOR_VERSION` variables; the patch component
auto-increments. See [README — Release process](README.md) for details.

## [1.2.0] - 2026-06-23

### Added
- **Detection + signal-only CVE pointer for Gerapy** (VSN depth, batch 7): CVE-2021-43857. (Batch 7 otherwise re-verified existing detections — Apache, Django, Flask, GitLab, Grafana, Rails, Tomcat — all correct; Apache OFBiz forces HTTPS and is left as a known gap.)
- **Detection + signal-only CVE pointers for 3 more products** (VSN depth, batch 6): Apache Solr (`Solr Admin`; CVE-2019-17558 Velocity SSTI), Metabase (`metabase.DEVICE` cookie; CVE-2023-38646 pre-auth RCE), Apache ActiveMQ (CVE-2023-46604 — OpenWire/61616, flagged as non-HTTP vector).
- **Detection for 3 more products** (VSN depth, batch 5): Kibana (`kbn-version` header; CVE-2018-17246 pointer), LimeSurvey, MyBB (named via body markers; their LFI labs are generic PHAR/polyglot technique demos with no product CVE, so no fabricated pointer).
- **Detection + signal-only CVE pointers for 6 more products** (VSN depth, batch 4): Sonatype Nexus (`Server: Nexus`; CVE-2024-4956), Apache Druid (CVE-2021-36749), Node-RED (CVE-2021-3223), Pimcore (`X-Powered-By: pimcore`; CVE-2021-23340), October CMS (`october_session` cookie; CVE-2020-5295), Grav CMS (CVE-2020-29556).
- **`paths_200` signature channel** — exploit-file-presence checks that only flag a path when it's actually **reachable (200)**, not merely present-but-blocked (403). PHPUnit's `eval-stdin.php` (CVE-2017-9841) is now flagged on a vulnerable host but **not** on Drupal (which 403s `/vendor`), so it never becomes a false CVE lead.
- **Detection + signal-only CVE pointers for 6 more products** (VSN depth, batch 3): GLPI (CVE-2022-35914), PHPUnit (CVE-2017-9841 via `paths_200`), Apache Superset (CVE-2023-27524), Gitea (`i_like_gitea` cookie; CVE-2020-14144), MinIO (`Server: MinIO`; CVE-2023-28432), Apache Flink (CVE-2020-17519). Signal-only manual pointers; passivity guard stays green.
- **Detection + signal-only CVE pointers for 10 more products** (VSN depth pass): OpenNetAdmin, Cacti, Webmin, Craft CMS, Bludit, ThinkPHP, Apache CouchDB, Atlassian Confluence, Nagios XI, Strapi. Each is fingerprinted by an FP-safe marker — a definitive header (`Server: MiniServ` / `Server: CouchDB`, `X-Confluence-Request-Time`, `X-Powered-By: Strapi`/`Bludit`/`Craft CMS`), a unique cookie (`ona_context_name`, `Cacti`), or a specific title/body — and `--framework-recon` surfaces each product's famous CVE as a **"verify manually" pointer**: Cacti CVE-2022-46169, Webmin CVE-2019-15107, Confluence CVE-2022-26134, CouchDB CVE-2017-12635/12636, Strapi CVE-2019-18818/19609, Craft CMS CVE-2024-56145, ThinkPHP CVE-2018-20062, Bludit CVE-2019-16113, Nagios XI CVE-2019-15949, OpenNetAdmin CVE-2019-25065. **Signal-only** — no auto-probes (every exploit needs a crafted POST/PUT/payload), so the passivity guard stays green.

### Fixed
- **More path-collision / body-substring false positives** (found in the batch-6 Java sweep): grafana's `/api/health` + `/api/datasources` path probes collided with any app exposing an `/api/*` health endpoint (Metabase, ActiveMQ → a Grafana FP) — grafana is now header/cookie/body only; and confluence's bare `"Confluence"` body marker matched a doc link in the Struts2 showcase — confluence now relies on its definitive `X-Confluence-Request-Time` header only.
- **Webmin was never detected** — its signature used a bogus `:10000` *path* (concatenated into a malformed URL) and missed the definitive `Server: MiniServ` header. Now header-based.
- **Technology false-positives from weak body substrings (precision pass).** Hardened the fingerprint signatures that fired on any page merely *mentioning* a technology in inline scripts, JSON, or UI text. `react`/`vue`/`angular` now require real DOM markers (`data-reactroot`, `__vue__`, `ng-version`, `_nghost`…) or a versioned CDN `<script src>`; `jquery` is detected only via a real versioned `<script src>` (now matching the `jquery.min.js?ver=` form WordPress/Drupal use); `jenkins` drops the bare `"Jenkins"` word for the `X-Jenkins` header + `Jenkins-Crumb` markup; `gitlab` drops bare `"gitlab"` for the definitive `X-Gitlab-Feature-Category` header + `_gitlab_session` cookie; `springboot` requires `org.springframework.boot` (not bare `org.springframework`, which Jenkins' bundled spring-security tripped). Most visibly, GitLab no longer reports **Jenkins at HIGH confidence** or **Spring Boot**, and is itself detected via its header instead of a substring.
- **Content-type gate on fingerprinting.** The body/script/meta signature channels now run only on `text/html` responses, so a framework substring inside a JSON API response or a crawled `.js` bundle no longer produces a detection (headers/cookies still apply to any response type).
- **Path-probe false-positives.** Dropped collision-prone path signals that tagged the wrong product: Apache's `/.htaccess` + `/server-status` (nginx 403s dotfiles too → an Apache FP on the nginx-fronted phpMyAdmin lab and on PHP dev servers serving `.htaccess` as 200), GitLab's `/users/sign_in` + `/api/v4/` (Grafana 401s `/api/v4/` → a GitLab FP on the Grafana lab), and Tomcat's generic `/docs/` + `/examples/` (Cacti ships a `/docs/` dir → a Tomcat FP). Apache is now Server-header-only; GitLab relies on its definitive `X-Gitlab-Feature-Category` header + `_gitlab_session` cookie; Tomcat keeps the unique `/manager/html` paths + `Apache-Coyote` header + `Apache Tomcat` body.
- **Honest confidence scoring.** Path-probe-only detections now carry an explicit `low` confidence instead of a confusing `[null]` (e.g. `/actuator/health` → Spring Boot). A detection backed *only* by a body/script substring can no longer reach **HIGH** on page-count alone — it caps at `medium`; reaching HIGH requires a corroborating channel (header/cookie/meta/form-field/stack-trace) or a 2nd distinct method. Definitive single-header detections (nginx, GitLab, …) are unaffected.
- **Catch-all / slow-host robustness (precision).** The catch-all filter no longer hinges on a single baseline fetch: `fetch_baseline` retries transient failures (3×), and an independent heuristic suppresses path-probe detections when ≥4 unrelated technologies match by path alone (the hallmark of a permissive/catch-all server). Previously, if the baseline fetch failed on a slow/warming target, the filter silently disabled and a catch-all host produced a false-positive cascade — including a spurious framework-recon CVE pointer on the wrong product (observed live: Laravel CVE-2021-3129 surfaced on a WordPress box because every path returned the homepage). Real products are unaffected (they surface via body/header/meta/cookie).
- Verified by a live full-range A/B across the **20-lab** VSN range: every confirmed false positive removed (gitlab `jenkins`/`react`, drupal `react`, jenkins `springboot`, grafana `gitlab`, phpMyAdmin + Laravel `apache`) and no `[null]` confidences remain; all true positives retained (CMS, frameworks, web servers, Tomcat, jQuery via `<script src>`). Also exercised against the expanded **69-lab** VSN range (batch-by-batch). Test suite now **194**.

## [1.1.0] - 2026-06-17

The `1.1` line centers on **framework-aware CVE signal-recon** — mapping detected exposures to known CVEs (signal-only, never exploit) across Laravel, Django, Flask, Spring Boot, and Next.js — plus arbitrary-header authentication, a stack-trace / secret miner, a large fingerprint-precision pass verified against a 20-lab range, and an internal DRY refactor of the crawl orchestrator.

### Added
- **Arbitrary auth headers via `-H "Name: value"`** (repeatable) — covers every authentication type: HTTP Basic, Bearer, Digest, NTLM/Negotiate, API keys (`X-API-Key`), `Cookie`-based sessions, and custom headers. Resolution precedence CLI `-H` > `config.auth.headers`; an explicit `-H "Authorization: ..."` overrides the `--token` bearer convenience. Applied across all clients (recon, fingerprint, framework-recon, SPA, spider).
  - **Origin-scoped like the bearer token**: custom auth headers are stripped on cross-origin redirects so an `X-API-Key`/`Cookie` can't leak to a third party. httpx auto-strips `Authorization` cross-origin but not custom headers, so the recon client gets an origin-strip request event hook (verified empirically) and the spider strips per-hop via `should_send_auth`.
  - **Redacted everywhere**: header values shown in the banner as `Name: first4…last4` (auth scheme word preserved, e.g. `Bearer eyJh…6Dc` / `Basic dXNl…ZA==`); raw values live only under `config['auth']` and never enter the saved JSON report (verified: scanned with secret `-H` values, 0 occurrences in the report).
  - Malformed `-H` (no colon / empty name) is warned about and skipped.
- **Framework CVE signal-recon** (`--framework-recon`) — new Phase 1.7 module that runs framework-specific GET probes when a supported framework is detected and maps the exposures to their CVEs with a "verify manually" disposition. **Signal-only — never exploit**: every probe is a content-gated GET with no payload, enforced by a CI passivity-guard test.
  - Profiles for **Laravel, Django, Flask, Spring Boot, Next.js**. Laravel intel pack probes `/_ignition/health-check`, `/_ignition/execute-solution`, `/telescope`, `/horizon`, `/log-viewer`, `/storage/logs/laravel.log`, `/.env` (+ `.bak` / `.example` / `.production` / `.local`), `/composer.json`, `/composer.lock`, `/artisan`, `/server.php`, `/api/user`, `/sanctum/csrf-cookie`, `/livewire/livewire.js`. Severity-tagged, 404-baseline filtered.
  - Source-verified CVE catalog (2018–2025): Laravel Ignition **CVE-2021-3129** + APP_KEY **CVE-2018-15133**; Spring Cloud Gateway **CVE-2022-22947** + actuator heapdump/env/jolokia; Flask Werkzeug debugger **CVE-2024-34069**; Django admin / debug-toolbar + DEBUG→pickle chain; Next.js **CVE-2025-29927** (version note).
  - `Probe` carries `cve`, `confirm_any` (body-content precision gate so a generic `/console` or `/admin/` 200 can't false-positive), and escalation fields (a reachable `.env` escalates to CVE-2018-15133 when `APP_KEY` is present).
  - `_MANUAL_POINTERS`: CVEs that need a payload to confirm (Spring4Shell **CVE-2022-22965**, Log4Shell **CVE-2021-44228**, Jinja2 SSTI, Next.js middleware bypass, Laravel env-manipulation) are surfaced as manual-test guidance, **never auto-probed**. New `springboot` fingerprint signature + multi-framework debug-page attribution in the stack-trace miner (Django technical-500, Werkzeug debugger, Spring Whitelabel).
- **Laravel-ecosystem product CVEs** (Proving Grounds-relevant). Detected as their own products — **not** lumped under Laravel — so the CVEs only fire when the specific product is present, never on a plain Laravel site:
  - **Voyager** (DevDojo Laravel admin package): fingerprint via `voyager-assets` / `thecontrolgroup/voyager` body markers; framework-recon probes `/admin/compass` → **CVE-2024-55415** (path traversal) + **CVE-2024-55416** (XSS) and `/admin/media` → **CVE-2024-55417** (upload→RCE), with a manual pointer for the one-click RCE chain.
  - **Innoshop** (Laravel e-commerce, ≤ 0.4.1): fingerprint via brand markers; **CVE-2025-52921** (CVSS 9.9 authenticated File Manager RCE) surfaced as a manual pointer.
  - Precision guard: the Voyager fingerprint uses body markers only (no `/admin/*` paths) — the fingerprinter follows redirects, so a `/admin/compass` path would falsely match any framework (e.g. Django) that 302s `/admin/*` to a 200 login. Verified live against the Django lab: zero Voyager/Innoshop false-positives.
- **Jenkins + GitLab fingerprint-only CVE pointers.** Added `jenkins` and `gitlab` framework-recon profiles with **no GET probes** (their flagship CVEs are non-GET vectors) that surface manual-test guidance off the existing fingerprints: Jenkins **CVE-2024-23897** (CLI `@file` arbitrary read → RCE) and GitLab **CVE-2021-22205** (unauthenticated ExifTool image-upload RCE). Signal-only; the passivity guard and per-framework manual-pointer test stay green. Verified end-to-end against the vulnerable-software-neighborhood labs `05-jenkins-cli-fileread` and `06-gitlab-exiftool`.
- **Stack-trace miner** (`utils/stacktrace.py`) — runs on every crawled response. Extracts: debug-mode flag (when exceptions render to the client), framework + version (Laravel via Illuminate / Symfony / vendor-path markers), filesystem install path, Ignition exposure flag, PHP version. PII / secret pass: leaked emails (within stack-trace context), RFC 1918 internal IPs, internal hostnames (`*.internal` / `*.local` / `*.svc.cluster.local`), AWS access keys (redacted) / ARNs / EC2 instance IDs, database connection URIs with credentials redacted to `scheme://user:***@host:port/db`.
- **Fingerprint conflict resolution** (`resolve_conflicts`). Signatures can declare `incompatible_with:`; when mutually exclusive techs both fire, strongest evidence wins (most distinct methods, then most matches, then highest confidence). Ties keep both.
- **Form-field signature channel** (`form_fields:` in `fingerprints.yaml`). Frameworks with characteristic hidden form-field names (e.g. Laravel `_token`) contribute fingerprint evidence; the match requires `type="hidden"`.
- **`framework_recon` + `debug_exposure` report sections** in the JSON report and Rich CLI summary — a severity-tagged table for framework-recon probes (with a CVE column + manual-pointers tree) and a tree view for debug exposures.
- **`docs/ARCHITECTURE.md`** — Mermaid diagrams of the nine-phase scan pipeline, the module call-graph, and the auth origin-scoping flow, plus a phase-responsibility table, a results-dict schema, and the precision-guard legend. Linked from the README and `docs/features.md`.

### Changed
- **`MAJOR_VERSION` / `MINOR_VERSION` hardcoded in `release.yml`** (was GitHub repo Variables) so the version line is monitored in the codebase and reviewed via PR. Also fixes the cause of the first release run not tagging.
- **Rails signature tightened**: removed blanket `<meta name="csrf-token">` match (collided with Laravel and every other CSRF-using framework). Now requires Rails-specific evidence: `x-runtime` header, `_session_id` / `_rails_session` cookie, `rails-ujs` / `data-turbo` / `Started GET` body markers. Declares `incompatible_with: [laravel, django, symfony]`.
- **Grafana signature tightened**: removed `/login` (every framework has /login). Now requires Grafana-specific evidence: `x-grafana-org-id` header, `grafana_session` cookie, `grafana-app` / `grafanaBootData` body markers, `/api/datasources` or `/public/build/runtime` paths.
- **Laravel signature strengthened**: added `Illuminate\\` namespace marker, `/vendor/laravel/framework/` body string, `Symfony\\Component\\HttpKernel` marker, the `_token` hidden form field, and the `/_ignition/health-check` path. Declares `incompatible_with: [rails, django, symfony]`.

### Fixed
- **Precision pass — false positives found by scanning the 20-lab VSN range.** Live-verified each fix against the actual lab that produced the FP:
  - **GitLab Laravel cascade (worst case).** GitLab's Rails forms carry a `_method` field that matched the Laravel `form_fields` signature, triggering the *entire* Laravel framework-recon profile → ~22 bogus probes (`/.env`, `/_ignition/*`, `/telescope`…) reported as criticals. Removed `_method` from the Laravel signature (it's shared by Rails/Symfony; `_token` stays). GitLab now reports cleanly as Nginx/Rails/Bootstrap/GitLab.
  - **Django false-positive on Voyager / GitLab / phpMyAdmin / Jenkins.** The Django fingerprint probed generic `/admin/` + `/static/admin/` paths; since the fingerprinter follows redirects, any app that 302s `/admin/` to a 200 login was tagged Django. Dropped those paths + the generic `x-frame-options: DENY` header; Django now detects via `csrftoken`/`django_language` cookies + `csrfmiddlewaretoken` body + the stack-trace miner (real Django still detected high-confidence).
  - **Jenkins false-positive on any `/login` page.** Dropped the generic `/login` path from the Jenkins signature; the definitive `X-Jenkins` header + body marker remain.
  - **Spring Boot false-positive on Jenkins** (stack-trace miner). Jenkins bundles spring-security, so bare `org.springframework.` attributed Spring Boot. Now requires `org.springframework.boot`, a Spring MVC DispatcherServlet frame, or the Whitelabel error page.
  - **Joomla false-positive on Drupal / phpMyAdmin.** Joomla probed generic dirs (`/components/`, `/modules/`, `/templates/`, `/administrator/`) that collide with Drupal. Tightened to Joomla-unique paths (`/language/en-GB/en-GB.xml`, `joomla.xml` manifest) + header/generator/body markers (real Joomla still detected).
  - **Drupal false-positive on Django (and other framework) targets.** Drupal's signature listed the non-Drupal-specific paths `/user/login` and `/admin/content`; Django's admin redirects `/admin/content` → 302, producing a phantom Drupal detection. Tightened to Drupal-unique paths (`/core/misc/drupal.js`, `/core/CHANGELOG.txt`, `/sites/default/`, `/core/install.php`).
  - **Catch-all "→ login" redirect baseline.** Root-cause structural fix: a target that 302s every unknown path to a login (GitLab → `/users/sign_in`) made framework-recon probes "fire" on the redirect (non-200 bypassed the content gate). The baseline now also records the catch-all redirect location (`Baseline.is_catchall_redirect`); framework-recon and common-path probing drop any 3xx that matches it. Defense-in-depth beyond the per-signature fixes.
- **Laravel false-positive on every PHP site.** The Laravel signature included `x-powered-by: PHP` as a header match — that's emitted by WordPress, Drupal, Joomla, phpMyAdmin, and basically anything PHP. The header check is removed; Laravel detection now requires Laravel-specific evidence (cookies, body, form fields, paths). Regression test added so this can't regress quietly.
- **Bootstrap false-positive on Laravel error pages**: bare `bootstrap` substring matched Laravel's `/bootstrap/app.php` filename in stack traces. Bootstrap signature now requires CSS-framework-specific evidence (`bootstrap.min.css`, `navbar-toggler`, `container-fluid`, `data-bs-toggle`).
- **Pipeline ordering bug**: framework_recon ran BEFORE the landing-page body detection that's the only way to identify Laravel on production targets with Ignition disabled. New Phase 1.6 fetches the landing HTML and runs body/cookie/form-field detection (and re-runs dedup + conflict resolution) BEFORE Phase 1.7; SPA analysis reuses that already-fetched landing HTML in Phase 1.8. This also fixes a **silent `--framework-recon` no-op** on production Laravel targets.
- **Laravel body pattern never matched real Laravel output**: YAML double-escaping (`"Illuminate\\\\"`) parsed to a Python string requiring two literal backslashes, but real Laravel error pages render `Illuminate\Routing` with single backslashes. Patterns corrected to `"Illuminate\\Routing"` / `"Illuminate\\Foundation"` / `"Symfony\\Component\\HttpKernel"`.
- **`form_fields:` signature channel matched visible inputs.** A non-hidden `<input name="_token">` was firing Laravel detection. Now requires `type="hidden"` to count as CSRF-token evidence.
- **Multiple `Set-Cookie` headers were collapsed.** `dict(httpx.Headers)` merges duplicate headers into a single comma-joined string, so a Laravel app sending `XSRF-TOKEN` + `laravel_session` as separate Set-Cookie headers produced only one session-cookie finding. CrawlResult now carries `set_cookies: list[str]` via `httpx.Headers.get_list("set-cookie")`; both `detect_auth_mechanisms` and `Fingerprinter._extract_cookies` iterate per-cookie. Both cookies now surface.
- **Silent config errors.** `load_config()` used to return `{}` whenever the file was missing or malformed — operators passing `-c custom.yaml` could be running with defaults and never know. Now: explicit `-c` with a missing file exits 2 with a clear error; any `yaml.YAMLError` exits 2 with the parser's line/column message; missing-by-default stays silent (running without a config is a valid mode).
- **`parse_robots` mangled sitemap URLs.** `line.split(":", 1)[1]` on `Sitemap: https://example.com/sitemap.xml` dropped the scheme, producing `//example.com/sitemap.xml`. Fixed by stripping the `Sitemap:` prefix instead of splitting on `:`.
- **Lab/Laravel Composer build broke on advisory-affected packages.** Composer 2.7+ refuses to install packages with active security advisories — the opposite of what an intentionally-vulnerable lab wants. The Laravel lab now sets `composer config policy.advisories.block false` for the builder stage.
- **Lab/Rails build broke on the `psych` gem.** Missing `libyaml-dev` system dep. Added.
- Three pre-existing **E501 lint errors** (long lines in `crawler.py`, `extractor.py`, `recon.py`) that were blocking the initial CI run.

### Removed
- **Dead code**: `Extractor.find_interesting_paths` (never called) and its companion `INTERESTING_PATHS` regex.

### Internal
- **`labs/` directory with Docker-based test targets** — real frameworks in known states, orchestrated via a single `docker compose` + `Makefile` so the deep-recon paths can be exercised end-to-end without an OSCP VPN:
  - `labs/laravel/` — intentionally vulnerable Laravel 10 (PHP 8.4): `APP_DEBUG=true`, `/_ignition/*` reachable, `/.env` leaked to web root, `/trigger-error` renders a full Ignition stack trace.
  - `labs/rails/` — plain Rails 7 install for the false-positive regression check (the Rails signature tightening must still detect real Rails).
  - `labs/wordpress/` — official `wordpress:6` image + MariaDB 10.11 sidecar; exercises CMS path probing + the 404-baseline filter on a real catch-all-style server.
  - `labs/django/`, `labs/flask/`, `labs/springboot/` — targets for the new framework-recon profiles.
  - All six on adjacent ports 8081–8086 (avoiding the common 80xx range); `labs/Makefile` wraps `make up / down / scan-*`. Verified end-to-end including a WordPress/Rails cross-check proving zero framework bleed.
- **DRY / orchestrator refactor of `crawler.py`** — pure structural cleanup, **no behaviour change**:
  - The catch-all 404/redirect baseline is now fetched **once** per scan and threaded into recon / fingerprint / framework-recon (was three redundant fetches → two network round-trips saved); each module keeps a `baseline=None` fallback for standalone use.
  - The dedup → conflict-resolution pair (run after Phases 1.5, 1.6, 4) is consolidated behind one `finalize_technologies()` helper so the call sites can't drift out of order.
  - The recon-client auth origin-strip hook moved from `crawler.py` to `utils/auth.py` as public `make_auth_strip_hook`, co-located with `should_send_auth`.
  - The ~400-line `run_crawler` monolith is extracted into a `CrawlOrchestrator` class with one method per phase (`_phase1_recon` … `_phase5_surface`); `run_crawler()` stays as a thin wrapper.
  - **Verified zero behaviour change**: 180 unit tests + ruff clean, plus a live pre/post A/B scan of four VSN labs (laravel-ignition, django-debug, spring-cloud-gateway, gitlab) — `technologies` / `common_paths` / `framework_recon` / `debug_exposure` byte-identical on the deterministic targets (gitlab's only variance was crawl-coverage nondeterminism on its 500-page cap, reproduced across two same-code runs).
- **Test suite grew to 180** fixture-based unit tests — covering the stack-trace miner, conflict resolution, form-field signatures, FrameworkRecon orchestration + passivity guard, the precision-pass FP regressions, `finalize_technologies` equivalence, and the shared-baseline pass-through.

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

[Unreleased]: https://github.com/0xj4f/shatterpoint/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/0xj4f/shatterpoint/releases/tag/v1.1.0
[1.0.0]: https://github.com/0xj4f/shatterpoint/releases/tag/v1.0.0
