# shatterpoint

OSCP-focused web reconnaissance crawler — maps attack surfaces, fingerprints technologies, and catalogs every form, endpoint, and parameter on a target domain.

```bash
╰─$ shatterpoint --help

╔═══════════════════════════════════════════════════════╗
║       shatterpoint v1.0                               ║
║       Attack Surface Mapper & Fingerprinter           ║
╚═══════════════════════════════════════════════════════╝

usage: shatterpoint [-h] [-u URL] [-c CONFIG] [-d DEPTH] [-p PAGES] [-t THREADS] [-o OUTPUT] [-v] [--no-fingerprint] [--no-recon] [--timeout TIMEOUT]
                    [--version]

shatterpoint — OSCP Recon Attack Surface Mapper

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target URL (overrides config)
  -c, --config CONFIG   Config file path
  -d, --depth DEPTH     Max crawl depth
  -p, --pages PAGES     Max pages to crawl
  -t, --threads THREADS
                        Concurrency level
  -o, --output OUTPUT   Output directory
  -v, --verbose         Verbose output
  --no-fingerprint      Skip fingerprinting
  --no-recon            Skip recon modules
  --timeout TIMEOUT     Request timeout in seconds
  --version             show program's version number and exit

Examples:
  shatterpoint -u http://10.10.10.1
  shatterpoint -u http://target.htb -d 5 -p 200
  shatterpoint -u https://10.10.10.1:8443 -o ./loot -v
  shatterpoint -c custom_config.yaml

```

## What It Does

Single-pass recon against **one target domain**. No attacks — just mapping.

- 🕷️ **Crawls** every in-scope page (async, 15 concurrent requests)
- 📝 **Extracts** forms, file uploads, API endpoints, URL parameters, emails, HTML comments
- 🔍 **Fingerprints** 25+ technologies with version detection and confidence scoring
- 🗺️ **Probes** 70+ common paths (admin panels, backups, .git, .env, etc.)
- 🤖 **Parses** robots.txt, sitemap.xml, security.txt
- 🔐 **Detects** auth mechanisms (Basic, NTLM, Bearer, login forms, session cookies)
- 📊 **Reports** structured JSON + rich CLI output

---

## Installation

### pipx (recommended)

```bash
pipx install git+https://github.com/0xj4f/shatterpoint.git
pipx install -e . --force --python "$(which python3)"

```

### pip

```bash
pip install git+https://github.com/0xj4f/shatterpoint.git
```

### From source (dev)

```bash
git clone https://github.com/0xj4f/shatterpoint.git
cd shatterpoint
pip install -e ".[dev]"
```

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

# Use a config file
shatterpoint -c config.yaml
```

---

## CLI Reference

```
usage: shatterpoint [-h] [-u URL] [-c CONFIG] [-d DEPTH] [-p PAGES]
                    [-t THREADS] [-o OUTPUT] [-v]
                    [--no-fingerprint] [--no-recon] [--timeout TIMEOUT]
                    [--version]

options:
  -u, --url URL          Target URL
  -c, --config CONFIG    Config file path (default: config.yaml)
  -d, --depth DEPTH      Max crawl depth (default: 10)
  -p, --pages PAGES      Max pages to crawl (default: 500)
  -t, --threads THREADS  Concurrency level (default: 15)
  -o, --output OUTPUT    Output directory (default: ./output)
  -v, --verbose          Verbose output
  --no-fingerprint       Skip technology fingerprinting
  --no-recon             Skip recon modules (robots, sitemap, path probing)
  --timeout TIMEOUT      Request timeout in seconds (default: 10)
  --version              Show version
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

output:
  directory: "./output"
```

CLI flags override config file values.

---

## Output

Reports are saved as JSON to `./output/recon_{domain}_{timestamp}.json`.

See [docs/schema.md](docs/schema.md) for the full report schema and [docs/features.md](docs/features.md) for detailed feature documentation.

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
│   │   └── recon.py            # robots.txt, sitemap, common paths, auth
│   ├── utils/
│   │   ├── validator.py        # URL validation & scope enforcement
│   │   └── formatter.py        # Rich CLI output & JSON reporting
│   └── signatures/
│       └── fingerprints.yaml   # 25+ technology signatures
├── tests/
│   └── test_smoke.py
└── docs/
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

1. Reads `MAJOR_VERSION` and `MINOR_VERSION` from repo Variables.
2. Finds the highest existing `v${MAJOR}.${MINOR}.*` tag and computes the next `PATCH`.
3. Runs lint + tests as a sanity gate.
4. Creates an annotated git tag `vMAJOR.MINOR.PATCH` (locally only at this point).
5. Builds the wheel — `hatch-vcs` reads the local tag and stamps the wheel.
6. Builds a multi-arch (`linux/amd64`, `linux/arm64`) Docker image.
7. Pushes the image to Docker Hub with three tags: `MAJOR.MINOR.PATCH`, `MAJOR.MINOR`, `latest`.
8. Only then pushes the git tag (so a failed Docker push doesn't leave a dangling tag).
9. Creates a GitHub Release with auto-generated notes.

To ship a new minor or major line, **bump the variable in the GitHub UI**. No code change required.

### Required GitHub setup (one-time)

| Where | What | Value |
|---|---|---|
| Settings → Secrets and variables → Actions → **Variables** | `MAJOR_VERSION` | `1` |
| Settings → Secrets and variables → Actions → **Variables** | `MINOR_VERSION` | `0` |
| Settings → Environments → new **Development** | (environment) | (creates the scope) |
| Settings → Environments → Development → Secrets | `DOCKER_USER` | your Docker Hub username |
| Settings → Environments → Development → Secrets | `DOCKER_PASSWORD` | a Docker Hub **access token** (not your password) |
| Settings → Actions → General → Workflow permissions | "Read and write permissions" | (or rely on per-job `permissions: contents: write` in `release.yml` — which is already set) |

Optional but recommended on the Development environment: require a reviewer to approve before the Docker push runs. Stops accidental publishes if a problematic PR sneaks into `main`.

### Pull-request rules

The `ci.yml` workflow blocks merges unless:

- `ruff check src/ tests/` is clean.
- `pytest tests/ -v` passes on Python 3.11, 3.12, 3.13.
- `CHANGELOG.md` was modified in the PR (add a bullet under `[Unreleased]`).

For PRs with no user-facing change (typos, internal refactors), add a line under `### Internal` rather than skipping the file.

---

## License

MIT

---

**Author**: [0xj4f](https://github.com/0xj4f)
