# Changelog

All notable changes to **shatterpoint** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Version numbers are produced at release time from the GitHub Actions
`MAJOR_VERSION` and `MINOR_VERSION` variables; the patch component
auto-increments. See [README — Release process](README.md) for details.

## [Unreleased]

_No changes yet._

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
