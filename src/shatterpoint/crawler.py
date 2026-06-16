"""
shatterpoint — Main Orchestrator
Ties together all modules into a single-pass reconnaissance workflow.

Usage:
    shatterpoint -u http://target.com
    shatterpoint -u http://target.com -o ./results -v
"""

import argparse
import asyncio
import sys
import time
import warnings
from pathlib import Path

import httpx
import yaml

from shatterpoint import __version__
from shatterpoint.modules.extractor import Extractor
from shatterpoint.modules.fingerprint import (
    Fingerprinter,
    dedup_technologies,
    resolve_conflicts,
)
from shatterpoint.modules.framework_recon import FrameworkRecon
from shatterpoint.modules.parser import HTMLParser
from shatterpoint.modules.recon import ReconModule
from shatterpoint.modules.spa import SPAAnalyzer
from shatterpoint.modules.spider import Spider
from shatterpoint.utils.auth import (
    ENV_VAR,
    redact_token,
    resolve_token,
    warn_on_expiry,
)
from shatterpoint.utils.formatter import (
    BANNER_TEXT,
    console,
    print_banner,
    print_finding,
    print_section,
    print_status,
    print_summary,
    save_report,
)
from shatterpoint.utils.stacktrace import merge_findings, mine_response
from shatterpoint.utils.validator import URLValidator

# Suppress SSL warnings (OSCP targets use self-signed certs)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


class _BannerArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that prepends the shatterpoint banner to --help output."""

    def format_help(self) -> str:
        return f"{BANNER_TEXT}\n\n" + super().format_help()


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file, "r") as f:
            return yaml.safe_load(f) or {}
    return {}


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = _BannerArgumentParser(
        prog="shatterpoint",
        description="shatterpoint — OSCP Recon Attack Surface Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic unauthenticated recon on an OSCP lab box
  shatterpoint -u http://10.10.10.1

  # Limit depth/pages for a fast first pass
  shatterpoint -u http://target.htb -d 5 -p 200

  # Authenticated crawl with a bearer token
  shatterpoint -u http://target.htb --token $JWT

  # SPA target (React/Vue/Angular/Next.js/Nuxt) — mines bundles & routes
  shatterpoint -u http://localhost:3001 --token $JWT --spa

  # SPA-only pass, skip noisy path probing on catch-all routers
  shatterpoint -u http://localhost:3001 --token $JWT --spa --no-recon

  # Save to a specific loot directory, verbose
  shatterpoint -u https://10.10.10.1:8443 -o ./loot -v

  # Config file instead of CLI flags
  shatterpoint -c custom_config.yaml

Environment:
  SHATTERPOINT_TOKEN    Bearer token fallback when --token is not passed.
        """,
    )
    parser.add_argument("-u", "--url", help="Target URL (overrides config)")
    parser.add_argument("-c", "--config", default="config.yaml", help="Config file path")
    parser.add_argument("-d", "--depth", type=int, help="Max crawl depth")
    parser.add_argument("-p", "--pages", type=int, help="Max pages to crawl")
    parser.add_argument("-t", "--threads", type=int, help="Concurrency level")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--no-fingerprint", action="store_true", help="Skip fingerprinting")
    parser.add_argument("--no-recon", action="store_true", help="Skip recon modules")
    parser.add_argument(
        "--spa",
        action="store_true",
        help=(
            "Enable SPA bundle mining (React/Vue/Angular/Next.js/Nuxt). "
            "Fetches same-origin JS bundles, probes source maps, extracts "
            "client-side routes, API endpoints, chunks, and baked secrets. "
            "SPA framework detection runs every scan regardless of this flag."
        ),
    )
    parser.add_argument(
        "--framework-recon",
        action="store_true",
        help=(
            "Enable framework-aware deep recon. When a supported framework "
            "is detected (v1: Laravel), probes framework-specific paths for "
            "common exposures (debug handlers, env file leaks, debug panels). "
            "Stack-trace mining of crawl responses runs every scan regardless."
        ),
    )
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds")
    parser.add_argument(
        "--token",
        help=(
            "Bearer token for authenticated crawling (sent as Authorization: Bearer <token>). "
            f"Also reads ${ENV_VAR} env var or config 'auth.token'. "
            "CLI > env > config."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()


async def run_crawler(config: dict) -> dict:
    """Main crawler orchestration logic."""
    target_url = config["target"]["url"]
    start_time = time.time()

    # Initialize components
    validator = URLValidator(target_url)
    spider = Spider(config, validator)
    html_parser = HTMLParser()
    extractor = Extractor()
    fingerprinter = Fingerprinter(config)
    recon = ReconModule(config, validator.base_url)

    # Results container
    results = {
        "target": {
            "url": target_url,
            "domain": validator.target_domain,
            "base_url": validator.base_url,
        },
        "scan_start": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "technologies": [],
        "forms": [],
        "api_endpoints": [],
        "file_uploads": [],
        "interesting_files": [],
        "comments": [],
        "emails": [],
        "parameters": [],
        "auth_mechanisms": [],
        "security_headers": [],
        "robots_txt": {},
        "sitemap": {},
        "security_txt": {},
        "common_paths": [],
        "all_urls": [],
        "attack_surface": {},
        "spa": {},
        "framework_recon": {},
        "debug_exposure": {},
    }

    spa_analyzer = SPAAnalyzer(config, validator, extractor, html_parser)
    framework_recon = FrameworkRecon(config, validator)

    # ─── Phase 1: Pre-Crawl Recon ───────────────────────────────
    print_section("PHASE 1: Pre-Crawl Reconnaissance")

    recon_cfg = config.get("recon", {})
    recon_headers = {"User-Agent": config.get("crawler", {}).get("user_agent", "")}
    auth_token = (config.get("auth") or {}).get("token")
    if auth_token:
        recon_headers["Authorization"] = f"Bearer {auth_token}"
    async with httpx.AsyncClient(
        verify=False,
        headers=recon_headers,
        limits=httpx.Limits(max_connections=10),
    ) as recon_client:
        recon_results = await recon.run_all(recon_client)
        results.update(recon_results)

        # Add sitemap URLs to seed list
        seed_urls = [target_url]
        sitemap_urls = results.get("sitemap", {}).get("urls", [])
        if sitemap_urls:
            for surl in sitemap_urls[:50]:
                if validator.is_in_scope(surl):
                    seed_urls.append(surl)
            print_status(f"Added {len(seed_urls) - 1} sitemap URLs as seeds")

        # Add robots.txt paths as seeds
        robots_disallowed = results.get("robots_txt", {}).get("disallowed", [])
        for path in robots_disallowed:
            full_url = f"{validator.base_url}{path}"
            if validator.is_in_scope(full_url):
                seed_urls.append(full_url)

        # ─── Phase 1.5: Fingerprint via path probing ─────────────
        if not config.get("_no_fingerprint"):
            print_section("PHASE 1.5: Technology Path Probing")
            path_detections = await fingerprinter.probe_known_paths(recon_client, validator.base_url)
            if path_detections:
                results["technologies"].extend(path_detections)
            # Dedup after Phase 1.5 so the Phase 4 merge logic sees a
            # clean per-id list (avoids 6× WordPress rows in the report).
            results["technologies"] = dedup_technologies(results["technologies"])
            # Resolve mutually-exclusive collisions (e.g. Laravel vs Rails
            # both firing on shared <meta name="csrf-token">). Strongest
            # evidence wins; ties keep both.
            results["technologies"] = resolve_conflicts(
                results["technologies"], fingerprinter.signatures
            )

        # ─── Phase 1.6: Landing-page body detection ──────────────
        # Fetch the landing HTML and run body/cookie/form-field
        # fingerprint checks. This MUST happen BEFORE framework deep
        # recon, otherwise targets that only reveal Laravel via cookies
        # (production deploys with Ignition disabled) never trigger the
        # deep-recon phase even when --framework-recon is set.
        print_section("PHASE 1.6: Landing-Page Body Detection")
        landing_html = ""
        landing_resp = None
        landing_forms: list[dict] = []
        try:
            landing_resp = await recon_client.get(
                target_url,
                follow_redirects=True,
                timeout=httpx.Timeout(10),
            )
            landing_html = landing_resp.text or ""
        except Exception as e:
            print_finding("Landing", f"Could not fetch landing HTML: {e}")

        if landing_html and not config.get("_no_fingerprint"):
            # Pass forms parsed from the landing HTML so the form_fields:
            # signature channel can fire (Laravel _token, etc.).
            landing_forms = html_parser.extract_forms(landing_html, target_url)
            body_detections = fingerprinter.fingerprint_from_response(
                target_url,
                dict(landing_resp.headers) if landing_resp is not None else {},
                landing_html,
                forms=landing_forms,
            )
            existing_ids = {t["id"] for t in results["technologies"]}
            for det in body_detections:
                if det["id"] not in existing_ids:
                    results["technologies"].append(det)
                    existing_ids.add(det["id"])
            # Re-run dedup + conflict resolution after body merges so
            # the framework_recon decision sees a clean tech list.
            results["technologies"] = dedup_technologies(results["technologies"])
            results["technologies"] = resolve_conflicts(
                results["technologies"], fingerprinter.signatures,
            )

        # ─── Phase 1.7: Framework deep recon ─────────────────────
        # Triggered when a supported framework appears in the detected
        # techs (v1: Laravel) AND framework_recon is enabled or
        # auto_when_detected is set. Mirrors the SPA gating pattern.
        print_section("PHASE 1.7: Framework Deep Recon")
        results["framework_recon"] = await framework_recon.analyze(
            recon_client, validator.base_url, results["technologies"],
        )
        if (
            results["framework_recon"].get("detected_frameworks")
            and not results["framework_recon"].get("ran")
        ):
            detected = results["framework_recon"]["detected_frameworks"]
            print_finding(
                "Framework Recon",
                f"{', '.join(d.title() for d in detected)} detected — "
                "rerun with --framework-recon to probe framework-specific paths",
            )

        # ─── Phase 1.8: SPA Analysis ─────────────────────────────
        # Landing HTML was fetched in Phase 1.6; we reuse it here so
        # SPA mining doesn't need a second round-trip.
        print_section("PHASE 1.8: SPA Analysis")
        results["spa"] = await spa_analyzer.analyze(
            recon_client, landing_html, validator.base_url, results["technologies"]
        )

        # If SPA detected but mining didn't run, nudge the user.
        if (
            results["spa"].get("detected")
            and not results["spa"].get("mining_ran")
        ):
            print_finding(
                "SPA",
                f"{results['spa']['framework']} detected — "
                "rerun with --spa to mine bundles, routes, and secrets",
            )

        # Add SPA-discovered routes to the crawl seed list
        for route in results["spa"].get("routes", []):
            route_url = f"{validator.base_url}{route['path']}"
            if validator.is_in_scope(route_url):
                seed_urls.append(route_url)
        if results["spa"].get("routes"):
            print_status(
                f"Added {len(results['spa']['routes'])} SPA route(s) as crawl seeds"
            )

    # ─── Phase 2: Crawl ─────────────────────────────────────────
    print_section("PHASE 2: Crawling & Discovery")

    seed_urls = list(set(seed_urls))
    crawl_results = await spider.crawl(seed_urls)

    # ─── Phase 3: Extract & Analyze ─────────────────────────────
    print_section("PHASE 3: Extraction & Analysis")

    all_urls = list(crawl_results.keys())
    results["all_urls"] = sorted(all_urls)
    all_emails = set()
    all_forms = []
    all_api_endpoints = []
    all_comments = []
    all_auth = []
    all_security_headers = []
    all_js_endpoints = []
    # Stack-trace mining runs on every crawled page regardless of any
    # framework flag — it's the universal "did the server leak debug
    # info in an error response?" check.
    stacktrace_findings: list[tuple[str, dict]] = []

    extract_cfg = config.get("extract", {})

    for url, crawl_result in crawl_results.items():
        if crawl_result.error or not crawl_result.body:
            continue

        body = crawl_result.body
        headers = crawl_result.headers

        # Stack-trace miner — empty dict for clean pages, populated
        # dict for pages with debug/framework/ignition signals.
        st = mine_response(body)
        if st:
            stacktrace_findings.append((url, st))

        # Extract forms
        if extract_cfg.get("forms", True):
            forms = html_parser.extract_forms(body, url)
            all_forms.extend(forms)

        # Extract comments
        if extract_cfg.get("comments", True):
            comments = html_parser.extract_comments(body, url)
            all_comments.extend(comments)

        # Extract emails
        if extract_cfg.get("emails", True):
            emails = html_parser.extract_emails(body)
            all_emails.update(emails)

        # Extract API endpoints from URL/response
        if extract_cfg.get("api_endpoints", True):
            apis = extractor.extract_api_endpoints(url, headers, body)
            all_api_endpoints.extend(apis)

        # Extract JS endpoints
        if extract_cfg.get("js_endpoints", True):
            scripts = html_parser.extract_scripts(body)
            for inline_js in scripts.get("inline", []):
                js_eps = extractor.extract_js_endpoints(inline_js, url)
                all_js_endpoints.extend(js_eps)

        # Detect auth mechanisms + security headers (separate taxonomies)
        if recon_cfg.get("auth_detection", True):
            if extract_cfg.get("forms"):
                page_forms = [f for f in all_forms if f["found_on"] == url]
            else:
                page_forms = html_parser.extract_forms(body, url)
            auth = recon.detect_auth_mechanisms(url, headers, body, page_forms)
            all_auth.extend(auth)
            all_security_headers.extend(recon.detect_security_headers(url, headers))

        # Track interesting files
        if validator.is_interesting_file(url):
            results["interesting_files"].append({
                "url": url,
                "status_code": crawl_result.status_code,
                "content_type": crawl_result.content_type,
            })

    # Deduplicate API endpoints (includes SPA-mined endpoints)
    spa_endpoints = results.get("spa", {}).get("api_endpoints_from_bundles", [])
    seen_apis = set()
    unique_apis = []
    for api in all_api_endpoints + all_js_endpoints + spa_endpoints:
        key = api.get("url", "")
        if key not in seen_apis:
            seen_apis.add(key)
            unique_apis.append(api)

    results["forms"] = all_forms
    results["api_endpoints"] = unique_apis
    results["comments"] = all_comments
    results["emails"] = sorted(all_emails)
    results["parameters"] = extractor.extract_url_parameters(all_urls)

    # Merge stack-trace findings into the debug_exposure block. If the
    # stack-trace miner identified a framework that the fingerprinter
    # didn't, synthesise a tech entry so the operator sees it in the
    # summary tech table too.
    if stacktrace_findings:
        results["debug_exposure"] = merge_findings(stacktrace_findings)
        st_framework = results["debug_exposure"].get("framework")
        if st_framework:
            tech_id = st_framework.lower()
            existing_ids = {t.get("id") for t in results["technologies"]}
            if tech_id not in existing_ids:
                results["technologies"].append({
                    "id": tech_id,
                    "name": st_framework,
                    "category": "Framework",
                    "version": results["debug_exposure"].get("framework_version"),
                    "matched_on": [{
                        "method": "stacktrace",
                        "detail": "Detected via leaked stack trace in error response",
                    }],
                    "confidence": "high",
                })
            else:
                # Add stack-trace evidence to the existing entry
                for tech in results["technologies"]:
                    if tech.get("id") == tech_id:
                        tech.setdefault("matched_on", []).append({
                            "method": "stacktrace",
                            "detail": "Detected via leaked stack trace in error response",
                        })
                        if not tech.get("version") and results["debug_exposure"].get("framework_version"):
                            tech["version"] = results["debug_exposure"]["framework_version"]
                        break

    # Deduplicate auth mechanisms
    seen_auth = set()
    unique_auth = []
    for a in all_auth:
        key = f"{a['type']}:{a.get('url', '')}:{a.get('detail', '')[:50]}"
        if key not in seen_auth:
            seen_auth.add(key)
            unique_auth.append(a)
    results["auth_mechanisms"] = unique_auth

    # Deduplicate security headers — same header on same URL with same value
    # is a single finding regardless of how many times we saw it. Collapse
    # across URLs at presentation time but keep one entry per (header, value)
    # to give the operator one snapshot rather than a per-URL flood.
    seen_sh: set[tuple[str, str]] = set()
    unique_security_headers = []
    for sh in all_security_headers:
        key = (sh.get("header", ""), sh.get("value", ""))
        if key in seen_sh:
            continue
        seen_sh.add(key)
        unique_security_headers.append(sh)
    results["security_headers"] = unique_security_headers

    # File uploads
    results["file_uploads"] = [f for f in all_forms if f.get("has_file_upload")]

    # ─── Phase 4: Fingerprinting ────────────────────────────────
    if not config.get("_no_fingerprint"):
        print_section("PHASE 4: Technology Fingerprinting")
        # Group forms by URL so the form_fields: signature channel can
        # fire on the aggregated pass (Laravel _token detection, etc).
        forms_by_url: dict[str, list[dict]] = {}
        for f in all_forms:
            forms_by_url.setdefault(f.get("found_on", ""), []).append(f)
        crawl_detections = fingerprinter.fingerprint_aggregate(
            crawl_results, forms_by_url=forms_by_url,
        )

        # Append all crawl detections and run one unified dedup pass —
        # avoids the bug where Phase 4's inline merge silently dropped
        # extra evidence when entries had been duplicated by Phase 1.5.
        results["technologies"].extend(crawl_detections)
        results["technologies"] = dedup_technologies(results["technologies"])
        # Final conflict-resolution pass after all evidence is in.
        results["technologies"] = resolve_conflicts(
            results["technologies"], fingerprinter.signatures
        )

        for tech in results["technologies"]:
            print_finding(
                "Tech",
                f"{tech['name']} ({tech.get('category', '')}) "
                f"v{tech.get('version', '?')} [{tech.get('confidence', '?')}]",
            )

    # ─── Phase 5: Attack Surface Summary ────────────────────────
    print_section("PHASE 5: Attack Surface Analysis")

    results["attack_surface"] = extractor.analyze_attack_surface(
        all_forms, all_urls, unique_apis
    )

    # Timing
    elapsed = round(time.time() - start_time, 2)
    results["scan_duration"] = elapsed
    results["pages_crawled"] = spider.pages_crawled

    return results


def main():
    """Entry point."""
    args = parse_args()
    config = load_config(args.config)

    # Apply CLI overrides
    if args.url:
        config.setdefault("target", {})["url"] = args.url
    if args.depth:
        config.setdefault("crawler", {})["max_depth"] = args.depth
    if args.pages:
        config.setdefault("crawler", {})["max_pages"] = args.pages
    if args.threads:
        config.setdefault("crawler", {})["concurrency"] = args.threads
    if args.timeout:
        config.setdefault("crawler", {})["timeout"] = args.timeout
    if args.verbose:
        config.setdefault("output", {})["verbose"] = True
    if args.no_fingerprint:
        config["_no_fingerprint"] = True
    if args.spa:
        config.setdefault("spa", {})["enabled"] = True
    if args.framework_recon:
        config.setdefault("framework_recon", {})["enabled"] = True
    if args.no_recon:
        config.setdefault("recon", {}).update({
            "robots_txt": False,
            "sitemap_xml": False,
            "security_txt": False,
            "common_paths": False,
        })

    # Resolve bearer token (CLI > env > config) and stash into config.
    # The raw token only ever lives in config['auth']['token'] — it is
    # never placed into the results dict that gets serialized to disk.
    token = resolve_token(args.token, config)
    token_display = redact_token(token) if token else ""
    config.setdefault("auth", {})["token"] = token
    config["auth"]["token_display"] = token_display

    print_banner(token_display=token_display)

    # Validate target
    target_url = config.get("target", {}).get("url", "")
    if not target_url or target_url == "http://example.com":
        console.print("[bold red]ERROR:[/bold red] No target URL specified!")
        console.print("  Use: shatterpoint -u http://target.com")
        sys.exit(1)

    # Ensure scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
        config["target"]["url"] = target_url

    print_status(f"Target: {target_url}")
    print_status(f"Config: {args.config}")
    if token:
        warning = warn_on_expiry(token)
        if warning:
            print_finding("Auth", f"[bold red]WARNING:[/bold red] {warning}")
    console.print()

    # Run
    try:
        results = asyncio.run(run_crawler(config))
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user[/bold red]")
        sys.exit(1)

    # Output
    print_section("RESULTS")
    print_summary(results)

    # Save report
    output_dir = args.output or config.get("output", {}).get("directory", "./output")
    report_path = save_report(results, output_dir)
    console.print(f"[bold green]Report saved:[/bold green] {report_path}")
    console.print()


if __name__ == "__main__":
    main()
