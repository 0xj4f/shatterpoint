"""
Output Formatting & Reporting
Generates structured JSON reports and rich CLI output.
"""

import json
import os
from datetime import datetime, timezone

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

console = Console()


def print_banner():
    """Print the tool banner."""
    banner = """
[bold red]╔═══════════════════════════════════════════════════════╗
║       0xj4f-webcrawler v1.0                           ║
║       Attack Surface Mapper & Fingerprinter           ║
╚═══════════════════════════════════════════════════════╝[/bold red]
"""
    console.print(banner)


def print_status(msg: str, style: str = "bold cyan"):
    """Print a status message."""
    console.print(f"  [bold white]>[/bold white] [{style}]{msg}[/{style}]")


def print_finding(category: str, detail: str):
    """Print a finding inline."""
    console.print(f"    [yellow]•[/yellow] [bold]{category}:[/bold] {detail}")


def print_section(title: str):
    """Print a section header."""
    console.print(f"\n[bold green]{'─' * 60}[/bold green]")
    console.print(f"[bold green]  {title}[/bold green]")
    console.print(f"[bold green]{'─' * 60}[/bold green]")


def print_summary(results: dict):
    """Print a rich summary of all findings to the console."""
    target = results.get("target", {})

    # Header
    console.print()
    console.print(Panel(
        f"[bold white]Target:[/bold white] {target.get('url', 'N/A')}\n"
        f"[bold white]Domain:[/bold white] {target.get('domain', 'N/A')}\n"
        f"[bold white]Scan Time:[/bold white] {results.get('scan_duration', 'N/A')}s\n"
        f"[bold white]Pages Crawled:[/bold white] {results.get('pages_crawled', 0)}",
        title="[bold red]SCAN RESULTS[/bold red]",
        border_style="red",
    ))

    # Technologies
    techs = results.get("technologies", [])
    if techs:
        table = Table(title="Technologies Detected", box=box.ROUNDED, border_style="cyan")
        table.add_column("Technology", style="bold white")
        table.add_column("Category", style="yellow")
        table.add_column("Version", style="green")
        table.add_column("Confidence", style="magenta")
        for tech in techs:
            table.add_row(
                tech.get("name", ""),
                tech.get("category", ""),
                tech.get("version", "N/A"),
                tech.get("confidence", ""),
            )
        console.print(table)

    # Forms
    forms = results.get("forms", [])
    if forms:
        table = Table(title=f"Forms Found ({len(forms)})", box=box.ROUNDED, border_style="yellow")
        table.add_column("Page", style="white", max_width=40)
        table.add_column("Action", style="cyan", max_width=30)
        table.add_column("Method", style="green")
        table.add_column("Inputs", style="yellow")
        table.add_column("File Upload", style="red")
        for form in forms[:30]:  # Limit display
            inputs = ", ".join(
                f"{i['name']}({i['type']})" for i in form.get("inputs", []) if i.get("name")
            )
            has_upload = "⚠ YES" if form.get("has_file_upload") else "no"
            table.add_row(
                form.get("found_on", "")[:40],
                form.get("action", "")[:30],
                form.get("method", "").upper(),
                inputs[:50] or "N/A",
                has_upload,
            )
        console.print(table)

    # API Endpoints
    apis = results.get("api_endpoints", [])
    if apis:
        table = Table(title=f"API Endpoints ({len(apis)})", box=box.ROUNDED, border_style="green")
        table.add_column("Endpoint", style="bold white")
        table.add_column("Source", style="yellow")
        for api in apis[:50]:
            table.add_row(api.get("url", ""), api.get("source", ""))
        console.print(table)

    # Interesting Files
    interesting = results.get("interesting_files", [])
    if interesting:
        table = Table(title=f"Interesting Files ({len(interesting)})", box=box.ROUNDED, border_style="red")
        table.add_column("URL", style="bold white")
        table.add_column("Status", style="green")
        for f in interesting[:30]:
            table.add_row(f.get("url", ""), str(f.get("status_code", "")))
        console.print(table)

    # Auth Mechanisms
    auth = results.get("auth_mechanisms", [])
    if auth:
        tree = Tree("[bold red]Authentication Mechanisms[/bold red]")
        for a in auth:
            tree.add(f"[yellow]{a.get('type', '')}[/yellow] - {a.get('detail', '')} [dim]({a.get('url', '')})[/dim]")
        console.print(tree)

    # Robots/Sitemap
    robots = results.get("robots_txt", {})
    if robots.get("found"):
        tree = Tree("[bold cyan]robots.txt[/bold cyan]")
        for d in robots.get("disallowed", [])[:20]:
            tree.add(f"[red]Disallowed:[/red] {d}")
        for a in robots.get("allowed", [])[:10]:
            tree.add(f"[green]Allowed:[/green] {a}")
        console.print(tree)

    sitemap = results.get("sitemap", {})
    if sitemap.get("found"):
        console.print(f"\n[bold cyan]Sitemap:[/bold cyan] {sitemap.get('url_count', 0)} URLs found")

    # Emails
    emails = results.get("emails", [])
    if emails:
        console.print(f"\n[bold cyan]Emails Found:[/bold cyan] {', '.join(emails[:20])}")

    # Comments
    comments = results.get("comments", [])
    if comments:
        table = Table(title=f"Interesting Comments ({len(comments)})", box=box.ROUNDED, border_style="dim")
        table.add_column("Page", style="white", max_width=40)
        table.add_column("Comment", style="yellow", max_width=60)
        for c in comments[:20]:
            table.add_row(c.get("url", "")[:40], c.get("comment", "")[:60])
        console.print(table)

    # URL tree
    all_urls = results.get("all_urls", [])
    if all_urls:
        console.print(f"\n[bold cyan]Total URLs Discovered:[/bold cyan] {len(all_urls)}")

    # Parameters
    params = results.get("parameters", [])
    if params:
        table = Table(title=f"URL Parameters ({len(params)})", box=box.ROUNDED, border_style="magenta")
        table.add_column("URL", style="white", max_width=50)
        table.add_column("Parameters", style="yellow")
        for p in params[:30]:
            table.add_row(p.get("url", "")[:50], ", ".join(p.get("params", [])))
        console.print(table)

    console.print()


def save_report(results: dict, output_dir: str) -> str:
    """Save the full results as a JSON report."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    domain = results.get("target", {}).get("domain", "unknown")
    filename = f"recon_{domain}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(results, f, indent=2, default=str)

    return filepath
