"""
0xj4f-webcrawler — Main Orchestrator
Ties together all modules into a single-pass reconnaissance workflow.

Usage:
    0xj4f-webcrawler -u http://target.com
    0xj4f-webcrawler -u http://target.com -o ./results -v
"""

import argparse
import asyncio
import sys
import time
import warnings
from pathlib import Path

import httpx
import yaml

from oxj4f_webcrawler import __version__
from oxj4f_webcrawler.modules.spider import Spider
from oxj4f_webcrawler.modules.parser import HTMLParser
from oxj4f_webcrawler.modules.extractor import Extractor
from oxj4f_webcrawler.modules.fingerprint import Fingerprinter
from oxj4f_webcrawler.modules.recon import ReconModule
from oxj4f_webcrawler.utils.validator import URLValidator
from oxj4f_webcrawler.utils.formatter import (
    print_banner,
    print_status,
    print_section,
    print_finding,
    print_summary,
    save_report,
    console,
)

# Suppress SSL warnings (OSCP targets use self-signed certs)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file."""
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file, "r") as f:
            return yaml.safe_load(f) or {}
    return {}


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="0xj4f-webcrawler — OSCP Recon Attack Surface Mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  0xj4f-webcrawler -u http://10.10.10.1
  0xj4f-webcrawler -u http://target.htb -d 5 -p 200
  0xj4f-webcrawler -u https://10.10.10.1:8443 -o ./loot -v
  0xj4f-webcrawler -c custom_config.yaml
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
    parser.add_argument("--timeout", type=int, help="Request timeout in seconds")
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
        "robots_txt": {},
        "sitemap": {},
        "security_txt": {},
        "common_paths": [],
        "all_urls": [],
        "attack_surface": {},
    }

    # ─── Phase 1: Pre-Crawl Recon ───────────────────────────────
    print_section("PHASE 1: Pre-Crawl Reconnaissance")

    recon_cfg = config.get("recon", {})
    async with httpx.AsyncClient(
        verify=False,
        headers={"User-Agent": config.get("crawler", {}).get("user_agent", "")},
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
    all_js_endpoints = []

    extract_cfg = config.get("extract", {})

    for url, crawl_result in crawl_results.items():
        if crawl_result.error or not crawl_result.body:
            continue

        body = crawl_result.body
        headers = crawl_result.headers

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

        # Detect auth mechanisms
        if recon_cfg.get("auth_detection", True):
            page_forms = html_parser.extract_forms(body, url) if not extract_cfg.get("forms") else [f for f in all_forms if f["found_on"] == url]
            auth = recon.detect_auth_mechanisms(url, headers, body, page_forms)
            all_auth.extend(auth)

        # Track interesting files
        if validator.is_interesting_file(url):
            results["interesting_files"].append({
                "url": url,
                "status_code": crawl_result.status_code,
                "content_type": crawl_result.content_type,
            })

    # Deduplicate API endpoints
    seen_apis = set()
    unique_apis = []
    for api in all_api_endpoints + all_js_endpoints:
        key = api.get("url", "")
        if key not in seen_apis:
            seen_apis.add(key)
            unique_apis.append(api)

    results["forms"] = all_forms
    results["api_endpoints"] = unique_apis
    results["comments"] = all_comments
    results["emails"] = sorted(all_emails)
    results["parameters"] = extractor.extract_url_parameters(all_urls)

    # Deduplicate auth mechanisms
    seen_auth = set()
    unique_auth = []
    for a in all_auth:
        key = f"{a['type']}:{a.get('url', '')}:{a.get('detail', '')[:50]}"
        if key not in seen_auth:
            seen_auth.add(key)
            unique_auth.append(a)
    results["auth_mechanisms"] = unique_auth

    # File uploads
    results["file_uploads"] = [f for f in all_forms if f.get("has_file_upload")]

    # ─── Phase 4: Fingerprinting ────────────────────────────────
    if not config.get("_no_fingerprint"):
        print_section("PHASE 4: Technology Fingerprinting")
        crawl_detections = fingerprinter.fingerprint_aggregate(crawl_results)

        existing_ids = {t["id"] for t in results["technologies"]}
        for det in crawl_detections:
            if det["id"] not in existing_ids:
                results["technologies"].append(det)
            else:
                for existing in results["technologies"]:
                    if existing["id"] == det["id"]:
                        existing["matched_on"].extend(det.get("matched_on", []))
                        if det.get("version") and not existing.get("version"):
                            existing["version"] = det["version"]
                        existing["confidence"] = det.get("confidence", existing.get("confidence"))
                        break

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
    print_banner()

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
    if args.no_recon:
        config.setdefault("recon", {}).update({
            "robots_txt": False,
            "sitemap_xml": False,
            "security_txt": False,
            "common_paths": False,
        })

    # Validate target
    target_url = config.get("target", {}).get("url", "")
    if not target_url or target_url == "http://example.com":
        console.print("[bold red]ERROR:[/bold red] No target URL specified!")
        console.print("  Use: 0xj4f-webcrawler -u http://target.com")
        sys.exit(1)

    # Ensure scheme
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
        config["target"]["url"] = target_url

    print_status(f"Target: {target_url}")
    print_status(f"Config: {args.config}")
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
