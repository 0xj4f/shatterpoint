# shatterpoint

OSCP-focused web reconnaissance crawler — maps attack surfaces, fingerprints technologies, and catalogs every form, endpoint, and parameter on a target domain.

```bash
╰─$ shatterpoint --help

╔═══════════════════════════════════════════════════════╗
║       shatterpoint v1.3                               ║
║       Attack Surface Mapper & Fingerprinter           ║
╚═══════════════════════════════════════════════════════╝

usage: shatterpoint [-h] [-u URL] [-c CONFIG] [-d DEPTH] [-p PAGES]
                    [-t THREADS] [-o OUTPUT] [-v] [--no-fingerprint]
                    [--no-recon] [--spa] [--framework-recon] [--browser]
                    [--timeout TIMEOUT] [--token TOKEN] [-H "Name: value"]
                    [--proxy URL] [--version]

shatterpoint — OSCP Recon Attack Surface Mapper

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target URL (overrides config)
  -c, --config CONFIG   Config file path
  -d, --depth DEPTH     Max crawl depth
  -p, --pages PAGES     Max pages to crawl
  -t, --threads THREADS Concurrency level
  -o, --output OUTPUT   Output directory
  -v, --verbose         Verbose output
  --no-fingerprint      Skip fingerprinting
  --no-recon            Skip recon modules
  --spa                 Mine SPA bundles (React/Vue/Angular/Next.js/Nuxt)
  --framework-recon     Framework CVE signal-recon (Laravel/Django/Flask/...)
  --browser             Also render pages in headless Chromium (passive)
  --timeout TIMEOUT     Request timeout in seconds
  --token TOKEN         Bearer token for authenticated crawling
  -H, --header "Name: value"
                        Arbitrary auth header (repeatable; covers all auth types)
  --proxy URL           Route ALL traffic through a proxy (TOR/Burp/mitmproxy)
  --version             show program's version number and exit

Examples:
  shatterpoint -u http://10.10.10.1
  shatterpoint -u http://target.htb --token $JWT --framework-recon
  shatterpoint -u http://target.htb -H "X-API-Key: $KEY" -H "X-Tenant: acme"
  shatterpoint -u http://localhost:3001 --token $JWT --spa
  shatterpoint -u http://localhost:3001 --spa --browser
  shatterpoint -u http://target.htb --proxy socks5h://127.0.0.1:9050
  shatterpoint -c custom_config.yaml

```

## What It Does

Single-pass recon against **one target domain**. Signal-only — it maps and detects, it never exploits.

- 🕷️ **Crawls** every in-scope page (async, 15 concurrent requests)
- 📝 **Extracts** forms, file uploads, API endpoints, URL parameters, emails, HTML comments
- 🔍 **Fingerprints** 25+ technologies with version detection and confidence scoring
- 🗺️ **Probes** 70+ common paths (admin panels, backups, .git, .env, etc.) with a 404-baseline filter to kill catch-all false positives
- 🤖 **Parses** robots.txt, sitemap.xml, security.txt
- 🔐 **Authenticated crawling** — bearer token (`--token`) or any header (`-H`), origin-scoped and redacted
- 🧬 **Framework CVE signal-recon** (`--framework-recon`) — Laravel, Django, Flask, Spring Boot, Next.js, Voyager, Innoshop; maps exposures to CVEs with a "verify manually" disposition (never claims "vulnerable")
- 🪲 **Stack-trace mining** — flags debug-mode error pages, leaked filesystem paths, framework versions, secrets/DB-URIs
- 📦 **SPA bundle mining** (`--spa`) — follows every Vite/ES-module chunk, source maps, client-side routes (incl. route-constant objects), RPC methods (WebSocket RPC clients such as Hydra), baked secrets for React/Vue/Angular/Next/Nuxt
- 🌐 **Browser mode** (`--browser`, optional extra) — renders pages in headless Chromium: rendered forms, client-side redirects, live XHR/fetch/WebSocket calls, third-party hosts. Passive: never clicks, blocks non-GET
- 🧷 **Splits** real auth mechanisms from security headers in the report
- 📊 **Reports** structured JSON + rich CLI output

---

## Installation

### pipx (recommended)

```bash
# Latest from GitHub
pipx install git+https://github.com/0xj4f/shatterpoint.git

# Or from a local clone — editable, so code changes apply immediately
pipx install -e . --python "$(which python3)"
```

> pipx builds with **its own default Python** unless you pass `--python`, and `--force`
> **ignores** `--python`. shatterpoint needs Python ≥ 3.11, so if pipx's default is older
> (check with `pipx environment --value PIPX_DEFAULT_PYTHON`), rebuild with
> `pipx reinstall shatterpoint --python "$(which python3)"` rather than `--force`.

### Browser mode (optional)

`--browser` needs Playwright and a headless Chromium build (~195 MB on disk). Add them to an
existing install:

```bash
# pipx — adds Playwright to shatterpoint's environment;
# --include-apps also puts the `playwright` command on your PATH
pipx inject --include-apps shatterpoint playwright
playwright install --only-shell chromium

# pip / virtualenv
pip install 'shatterpoint[browser]'
playwright install --only-shell chromium
```

Quick check: `playwright --version` works, and a scan with `--browser` prints a
`PHASE 1.9: Browser Crawl` section. Docker image size: the `browser` target is about 770 MB
larger than the lean one (Chromium plus its system libraries).

### pip

```bash
pip install git+https://github.com/0xj4f/shatterpoint.git
```

### Docker

```bash
docker run --rm -v "$PWD/output:/app/output" 0xj4f/shatterpoint -u http://10.10.10.1
```

The published image is the lean one. For `--browser`, build the `browser` target from a clone
(the image installs the wheel from `dist/`):

```bash
pip install build && python -m build --wheel
docker build --target browser -t shatterpoint:browser .
docker run --rm -v "$PWD/output:/app/output" shatterpoint:browser -u https://app.target.test --spa --browser
```

### From source (dev)

```bash
git clone https://github.com/0xj4f/shatterpoint.git
cd shatterpoint
pip install -e ".[dev,browser]"
playwright install --only-shell chromium   # for the --browser end-to-end test
```

### Running the tests

```bash
ruff check src/ tests/
pytest tests/test_smoke.py -v            # whole suite, a few seconds
pytest tests/test_smoke.py -k browser    # browser mode only (includes a real headless-Chromium run)
pytest tests/test_smoke.py -k spa        # SPA mining only
```

Without Playwright the end-to-end browser test is **skipped** (shown as `s`) and everything else
still runs. CI installs Chromium, so it always runs there.

---

## Quick Start

```bash
# Basic scan
shatterpoint -u http://10.10.10.1

# OSCP box with limits
shatterpoint -u http://target.htb -d 5 -p 200

# Save to specific directory
shatterpoint -u http://10.10.10.1 -o ./loot/box1

# Fast scan — skip path probing
shatterpoint -u http://10.10.10.1 --no-recon

# Authenticated crawl + framework CVE recon (see Authentication below)
shatterpoint -u http://target.htb --token "$JWT" --framework-recon
shatterpoint -u http://target.htb -H "X-API-Key: $KEY" -H "Cookie: session=$SID"

# Use a config file
shatterpoint -c config.yaml
```

---

## CLI Reference

```
options:
  -u, --url URL          Target URL
  -c, --config CONFIG    Config file path (default: config.yaml if present)
  -d, --depth DEPTH      Max crawl depth (default: 10)
  -p, --pages PAGES      Max pages to crawl (default: 500)
  -t, --threads THREADS  Concurrency level (default: 15)
  -o, --output OUTPUT    Output directory (default: ./output)
  -v, --verbose          Verbose output
  --no-fingerprint       Skip technology fingerprinting
  --no-recon             Skip recon modules (robots, sitemap, path probing)
  --spa                  Mine SPA bundles (React/Vue/Angular/Next.js/Nuxt):
                         chunks, source maps, routes, RPC methods, secrets
  --framework-recon      Framework-specific CVE signal-recon (signal-only)
  --browser              Also render pages in headless Chromium (Playwright):
                         rendered DOM, client-side redirects, XHR/fetch/WS
                         calls. Needs the [browser] extra (see Browser mode)
  --timeout TIMEOUT      Request timeout in seconds (default: 10)
  --token TOKEN          Bearer token; also reads $SHATTERPOINT_TOKEN / config
  -H, --header "Name: value"
                         Arbitrary auth header (repeatable). Covers all auth
                         types — Basic, API key, Cookie, NTLM/Negotiate, custom
  --proxy URL            Route ALL traffic through a proxy (TOR / Burp /
                         mitmproxy). http://, https://, socks5://, socks5h://
  --version              Show version
```

> `--spa`, `--framework-recon` and `--browser` are opt-in. Without them, shatterpoint is a pure
> crawler + fingerprinter. SPA framework *detection* and a "rerun with --framework-recon"
> hint still run on every scan; only the deeper mining/probing is gated behind the flags.

---

## Authentication

Crawl behind a login by supplying credentials on the CLI. shatterpoint sends them on
**same-origin requests only** and **strips them on cross-origin redirects**, so a token or
cookie never leaks to a third-party host. All credential values are **redacted** in the
banner and never written to the saved JSON report.

### Bearer token — `--token`

```bash
shatterpoint -u http://target.htb --token "$JWT"
```

Resolution order: `--token` flag > `$SHATTERPOINT_TOKEN` env var > `config.yaml` `auth.token`.
Sent as `Authorization: Bearer <token>`. If the token is a JWT, shatterpoint decodes the
`exp` claim and warns when it's expired or expiring soon.

### Any header — `-H` / `--header` (covers all auth types)

`-H` is **repeatable** and takes a raw `"Name: value"` header, so it covers **every**
authentication scheme:

```bash
# HTTP Basic
shatterpoint -u http://target.htb -H "Authorization: Basic dXNlcjpwYXNz"

# API key (and any number of extra headers)
shatterpoint -u http://target.htb -H "X-API-Key: $KEY" -H "X-Tenant: acme"

# Cookie-based session
shatterpoint -u http://target.htb -H "Cookie: session=$SID; role=admin"

# NTLM / Negotiate, or any custom scheme
shatterpoint -u http://target.htb -H "Authorization: NTLM $TOKEN"
```

| Auth type | Example |
|---|---|
| Bearer / OAuth / JWT | `--token $JWT` *or* `-H "Authorization: Bearer $JWT"` |
| HTTP Basic | `-H "Authorization: Basic <base64(user:pass)>"` |
| HTTP Digest / NTLM / Negotiate | `-H "Authorization: <scheme> <creds>"` |
| API key | `-H "X-API-Key: ..."` / `-H "Apikey: ..."` |
| Cookie session | `-H "Cookie: session=..."` |
| Multi-header (tenant, CSRF, …) | repeat `-H` as needed |

**Notes**
- Precedence: `-H` (CLI) > `config.yaml` `auth.headers`. An explicit `-H "Authorization: ..."`
  **overrides** the `--token` bearer convenience.
- `-H` headers are origin-scoped exactly like the bearer token (stripped on cross-origin
  redirects) — an `X-API-Key` or `Cookie` is treated as sensitive as a token.
- Malformed `-H` input (missing colon / empty name) is warned about and skipped.

### Config-file equivalent

```yaml
auth:
  token: null                 # bearer; or set --token / $SHATTERPOINT_TOKEN
  headers:                    # arbitrary headers — same as repeated -H
    X-API-Key: "your-api-key"
    Cookie: "session=abc123"
```

---

## Proxy

Route **all** outbound traffic through a single proxy with `--proxy <url>` — to scan from a
different IP (**TOR**), inspect every request (**Burp**), or record/rewrite them
(**mitmproxy**). It covers everything: recon, fingerprinting, framework-recon, SPA bundle
mining, the crawl, and the internal baseline probe.

```bash
# Burp / mitmproxy — a bare host:port defaults to http://
shatterpoint -u http://target.htb --proxy http://127.0.0.1:8080

# TOR — use socks5h so DNS is resolved *through* TOR (no DNS leak)
shatterpoint -u http://target.htb --proxy socks5h://127.0.0.1:9050
```

- Accepts `http://`, `https://`, `socks5://`, `socks5h://`. SOCKS/TOR support ships with the
  package (the `httpx[socks]` extra) — nothing else to install.
- Precedence: `--proxy` flag > `config.yaml` `proxy.url`.
- **Fail-closed:** a malformed proxy value aborts the scan, and a requested proxy is *never*
  silently bypassed — so a typo can't deanonymise a TOR scan by falling back to direct.
- TLS verification is already off (OSCP targets use self-signed certs), so Burp/mitmproxy
  interception works without importing their CA.

```yaml
# config.yaml equivalent
proxy:
  url: null            # e.g. "socks5h://127.0.0.1:9050"; --proxy overrides this
```

---

## Browser mode

Some SPAs only reveal themselves at runtime: routes that redirect anonymous users to
`/login`, API calls whose URLs are built in JavaScript, forms that only exist once React
renders. `--browser` adds **Phase 1.9**, which opens each seed (the target, sitemap URLs and
`--spa` routes) in headless Chromium and records what the app actually does.

```bash
# Install once (pip, Docker and more under Installation → Browser mode)
pipx inject --include-apps shatterpoint playwright
playwright install --only-shell chromium     # headless-only build: ~195 MB on disk vs ~360 MB full Chromium

shatterpoint -u https://app.target.test --spa --browser
```

What it adds to the report (`browser` key + existing tables):

- **Browser Pages** — every rendered path and where the app *landed* (`/admin → /login`
  means auth-guarded; `/admin → /` means a gated route). Rendered pages replace their
  empty-shell HTTP versions, so **forms, comments and inline endpoints** of the rendered
  DOM flow into the normal Forms / API Endpoints tables.
- **Backend calls** — XHR / fetch / EventSource / WebSocket URLs on the target's own site
  (sibling subdomains such as an API gateway included), listed in API Endpoints as
  `browser:<type>`. In-scope GET calls are also handed to the HTTP crawler.
- **Browser network** — the other hosts the page contacted (CDNs, analytics, error
  reporting), and any **blocked** requests.

Notes:

- **Passive:** it never clicks or types. Any non-GET request the app fires on its own
  (analytics beacons, autosaves) is recorded and **blocked**, never sent. WebSocket frames
  are not inspected or filtered — without clicks the app only does what it does on load.
- Like a real user's browser, it talks to whatever hosts the app loads (CDNs, analytics,
  API gateways). `--proxy` routes the browser too (`socks5h://` is passed to Chromium as
  `socks5://`, which already resolves DNS through the proxy). Chromium does not support
  SOCKS proxy authentication.
- Auth from `--token` / `-H` is added only to requests for the target origin.
- Up to `browser.max_pages` (30) pages, one at a time, `browser.wait_ms` (2000) settle time
  each — expect roughly 3 s per page.

```yaml
# config.yaml equivalent
browser:
  enabled: false     # same as --browser
  max_pages: 30
  wait_ms: 2000
```

---

## Configuration

Drop a `config.yaml` in your working directory to customize defaults:

```yaml
target:
  url: "http://10.10.10.1"

crawler:
  max_depth: 10
  max_pages: 500
  concurrency: 15
  timeout: 10
  max_redirects: 3
  delay: 0.1

extract:
  forms: true
  api_endpoints: true
  file_uploads: true
  comments: true
  emails: true
  js_endpoints: true

fingerprint:
  enabled: true
  check_headers: true
  check_cookies: true
  check_paths: true
  check_meta: true

recon:
  robots_txt: true
  sitemap_xml: true
  security_txt: true
  common_paths: true
  auth_detection: true

framework_recon:
  enabled: false              # same as --framework-recon
  auto_when_detected: false   # run automatically when a supported framework is found
  timeout: 8

spa:
  enabled: false              # same as --spa
  auto_when_detected: false
  source_maps: true
  extract_secrets: true
  max_bundles: 60
  max_bundle_size_bytes: 5242880

browser:
  enabled: false              # same as --browser
  max_pages: 30
  wait_ms: 2000

auth:
  token: null                 # bearer; or --token / $SHATTERPOINT_TOKEN
  headers: {}                 # arbitrary auth headers, same as repeated -H
    # X-API-Key: "your-api-key"
    # Cookie: "session=abc123"

output:
  directory: "./output"
```

CLI flags override config file values.

---

## Output

Reports are saved as JSON to `./output/recon_{domain}_{timestamp}.json`.

See [docs/schema.md](docs/schema.md) for the full report schema, [docs/features.md](docs/features.md) for detailed feature documentation, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the scan pipeline and module design.

---

## Project Structure

```
shatterpoint/
├── pyproject.toml
├── config.yaml
├── src/shatterpoint/
│   ├── __init__.py
│   ├── crawler.py              # Main orchestrator & CLI entry point
│   ├── modules/
│   │   ├── spider.py           # Async crawler engine
│   │   ├── parser.py           # HTML extraction (forms, links, comments)
│   │   ├── extractor.py        # API/JS endpoint & attack surface analysis
│   │   ├── fingerprint.py      # Technology detection engine
│   │   ├── recon.py            # robots.txt, sitemap, common paths, auth
│   │   ├── framework_recon.py  # Framework CVE signal-recon (--framework-recon)
│   │   ├── spa.py              # SPA bundle mining (--spa)
│   │   └── browser.py          # Headless Chromium crawl (--browser, optional extra)
│   ├── utils/
│   │   ├── validator.py        # URL validation & scope enforcement
│   │   └── formatter.py        # Rich CLI output & JSON reporting
│   └── signatures/
│       └── fingerprints.yaml   # 25+ technology signatures
├── tests/
│   └── test_smoke.py
└── docs/
    ├── ARCHITECTURE.md         # Scan pipeline, module graph, precision guards
    ├── features.md
    └── schema.md
```

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| **Native Python** (not Scrapy) | Surgical precision for OSCP recon, not general scraping |
| **15 concurrent requests** | Fast enough under time pressure, won't DoS the lab |
| **Single domain scope** | One target per run — compose with a wrapper later |
| **Manual redirect tracking** | Logs full redirect chains (useful for auth bypass recon) |
| **Self-signed cert support** | `verify=False` — OSCP targets always have bad certs |
| **No attacks** | Map only — exploitation is your job |

---

## Adding Custom Fingerprints

Edit `src/shatterpoint/signatures/fingerprints.yaml`:

```yaml
my_custom_app:
  name: "My Custom App"
  category: "Custom"
  headers:
    - header: "x-custom-header"
      pattern: "(?i)myapp/?([\\d.]+)?"
  paths:
    - "/custom/login"
    - "/custom/api/"
  body:
    - "MyCustomApp"
  cookies:
    - "myapp_session"
```

---

## Release process

Versioning is **derived from git tags** at build time via [`hatch-vcs`](https://github.com/ofek/hatch-vcs). There is no version string committed in source code — the wheel and the published Docker image both report whatever the latest matching tag says.

On every merge to `main`, the `release.yml` workflow:

1. Reads `MAJOR_VERSION` and `MINOR_VERSION` from the `env:` block hardcoded in `release.yml`.
2. Finds the highest existing `v${MAJOR}.${MINOR}.*` tag and computes the next `PATCH`.
3. Runs lint + tests as a sanity gate.
4. Creates an annotated git tag `vMAJOR.MINOR.PATCH` (locally only at this point).
5. Builds the wheel — `hatch-vcs` reads the local tag and stamps the wheel.
6. Builds a multi-arch (`linux/amd64`, `linux/arm64`) Docker image.
7. Pushes the image to Docker Hub with three tags: `MAJOR.MINOR.PATCH`, `MAJOR.MINOR`, `latest`.
8. Only then pushes the git tag (so a failed Docker push doesn't leave a dangling tag).
9. Creates a GitHub Release with auto-generated notes.

To ship a new minor or major line, **bump `MAJOR_VERSION` / `MINOR_VERSION` in the `env:` block of `release.yml`** and merge. The version lives in the codebase and is reviewed via PR — no GitHub UI clicks, nothing hidden in repo settings.

### Required GitHub setup (one-time)

| Where | What | Value |
|---|---|---|
| Settings → Environments → new **Development** | (environment) | (creates the scope) |
| Settings → Environments → Development → Secrets | `DOCKER_USER` | your Docker Hub username |
| Settings → Environments → Development → Secrets | `DOCKER_PASSWORD` | a Docker Hub **access token** (not your password) |
| Settings → Actions → General → Workflow permissions | "Read and write permissions" | (or rely on per-job `permissions: contents: write` in `release.yml` — which is already set) |

Version (`MAJOR_VERSION` / `MINOR_VERSION`) is **no longer a GitHub Variable** — it's hardcoded in `release.yml`. Only the Docker Hub secrets need configuring.

Optional but recommended on the Development environment: require a reviewer to approve before the Docker push runs. Stops accidental publishes if a problematic PR sneaks into `main`.

### Pull-request rules

The `ci.yml` workflow runs on **every push to any branch** (and on PRs into `main`), so a
breaking change shows up before a PR exists. It blocks merges unless:

- `ruff check src/ tests/` is clean.
- `pytest tests/ -v` passes on Python 3.11, 3.12, 3.13 and 3.14. Playwright and headless Chromium
  are installed in CI, so the `--browser` end-to-end test runs too.
- `CHANGELOG.md` was modified in the PR (add a bullet under `[Unreleased]`).

For PRs with no user-facing change (typos, internal refactors), add a line under `### Internal` rather than skipping the file.

---

## License

MIT

---

**Author**: [0xj4f](https://github.com/0xj4f)
