# -*- coding: utf-8 -*-
"""
findmewho.cli
CLI entry point for findme-who.
"""

import sys
import os
import csv
import argparse
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from .engine import enrich_domain, enrich_batch, clean_domain_input

console = Console()

def main():
    parser = argparse.ArgumentParser(description="findme-who: High-Speed B2B Passive Lead Enrichment Engine")
    parser.add_argument("input", help="Target domain, URL, or CSV file of domains")
    parser.add_argument("-o", "--output", default="enriched_leads.csv", help="Output CSV path (default: enriched_leads.csv)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Concurrent domain workers (default: 5)")
    parser.add_argument("-p", "--pages", type=int, default=25, help="Max pages to crawl per domain (default: 25)")
    parser.add_argument("--timeout", type=int, default=45, help="Timeout per domain in seconds (default: 45)")
    parser.add_argument("--deep", action="store_true", help="Run the slow account-hunting pass (dozens of external probes per email/name)")
    args = parser.parse_args()

    domains = []
    if os.path.exists(args.input):
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                for col in row:
                    if "." in col and not col.startswith("#"):
                        d = clean_domain_input(col)
                        if d and d not in ["website", "domain", "url"]:
                            domains.append(d)
                            break
    else:
        d = clean_domain_input(args.input)
        if d:
            domains.append(d)

    domains = list(dict.fromkeys(domains))
    if not domains:
        console.print("[red]No valid domains found to enrich.[/red]")
        sys.exit(1)

    mode = "DEEP (slow)" if args.deep else "fast"
    console.print(f"[cyan]findme-who enriching [bold]{len(domains)}[/bold] domains ({mode} | Workers: {args.threads} | Max Pages: {args.pages})...[/cyan]")

    start_time = datetime.now()
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Running passive event graph...", total=len(domains))
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_dom = {executor.submit(enrich_domain, d, args.pages, args.timeout, args.deep): d for d in domains}
            for fut in as_completed(future_to_dom):
                res = fut.result()
                if res:
                    results.append(res)
                progress.advance(task)

    elapsed = (datetime.now() - start_time).total_seconds()
    console.print(f"[green][OK] Finished {len(results)} domains in {elapsed:.1f}s ({len(results)/max(0.1, elapsed):.1f} dom/s)[/green]")

    if results:
        headers = list(results[0].keys())
        with open(args.output, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        console.print(f"[green][OK] Exported CSV to: [bold]{args.output}[/bold][/green]")

        table = Table(title="Lead Intelligence Preview")
        table.add_column("Domain", style="cyan bold")
        table.add_column("Primary Email", style="green")
        table.add_column("Phone", style="yellow")
        table.add_column("Phone Type", style="magenta")
        table.add_column("CMS", style="blue")
        table.add_column("Mail Provider", style="white")

        for r in results[:5]:
            table.add_row(
                r.get("domain", ""),
                r.get("primary_email", "N/A") or "N/A",
                r.get("phone", "N/A") or "N/A",
                r.get("phone_type", "None"),
                r.get("cms", "Unknown"),
                r.get("mail_provider", "Unknown")
            )
        console.print(table)

if __name__ == "__main__":
    main()
