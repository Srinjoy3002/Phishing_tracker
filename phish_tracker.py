#!/usr/bin/env python3
"""
PhishTracker: Advanced Cross-Platform Phishing Site Detector
Operable on Kali Linux & Windows Terminal
Author: Cybersecurity Engineering Lab
"""

import sys
import os

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import argparse
from rich.console import Console
from rich.table import Table
from rich.status import Status
from rich.prompt import Prompt

# Ensure local directory is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import print_banner
from core.engine import scan_target
from core.reporter import render_terminal_report, export_json, export_markdown

console = Console(legacy_windows=False)



def scan_single(url: str, args) -> dict:
    """Scan a single target with live spinner status updates."""
    with console.status(f"[bold cyan]Scanning target: [white]{url}[/white]...", spinner="dots") as status:
        def update_progress(msg: str):
            status.update(f"[bold cyan]{msg}")

        result = scan_target(
            target_url=url,
            fast_mode=args.fast,
            skip_content=args.no_content,
            progress_callback=update_progress
        )

    # Render results
    render_terminal_report(result)

    # Export if requested
    if args.json:
        export_json(result, args.json)
    if args.markdown:
        export_markdown(result, args.markdown)

    return result


def scan_batch(filepath: str, args):
    """Scan a list of URLs from a text file and display a summary matrix."""
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error: Target list file '{filepath}' not found.[/bold red]")
        sys.exit(1)

    with open(filepath, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    console.print(f"[bold cyan]Loaded {len(urls)} target(s) from [yellow]{filepath}[/yellow]...[/bold cyan]\n")

    summary_table = Table(title="[bold white]Batch Scan Threat Matrix[/bold white]", border_style="cyan")
    summary_table.add_column("Target Host", style="bold white", width=35)
    summary_table.add_column("Score", justify="center", width=10)
    summary_table.add_column("Threat Level", width=22)
    summary_table.add_column("Key Findings", style="dim white")

    results = []
    for idx, u in enumerate(urls, 1):
        with console.status(f"[cyan]Analyzing ({idx}/{len(urls)}): [white]{u}[/white]...", spinner="dots"):
            res = scan_target(
                target_url=u,
                fast_mode=args.fast,
                skip_content=args.no_content,
                progress_callback=None
            )
            results.append(res)

        score = res["risk_score"]
        if score >= 70:
            score_styled = f"[bold red]{score}[/bold red]"
        elif score >= 50:
            score_styled = f"[yellow]{score}[/yellow]"
        elif score >= 25:
            score_styled = f"[cyan]{score}[/cyan]"
        else:
            score_styled = f"[green]{score}[/green]"

        top_findings = ", ".join([f["title"] for f in res["findings"][:2]])
        if len(res["findings"]) > 2:
            top_findings += f" (+{len(res['findings']) - 2} more)"
        if not top_findings:
            top_findings = "Clean / No flags"

        summary_table.add_row(
            res["hostname"],
            score_styled,
            f"{res['emoji']} [{res['color_tag']}]{res['classification']}[/{res['color_tag']}]",
            top_findings
        )

    console.print(summary_table)
    console.print()

    # Batch export
    if args.json:
        export_json({"batch_results": results}, args.json)
    if args.markdown:
        # Export all in markdown
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(f"# PhishTracker Batch Scan Matrix ({len(urls)} targets)\n\n")
            f.write("| Host | Score | Threat Level | Findings Count |\n| :--- | :--- | :--- | :--- |\n")
            for r in results:
                f.write(f"| `{r['hostname']}` | **{r['risk_score']}** | {r['classification']} | {len(r['findings'])} |\n")
        console.print(f"[bold green]✔ Batch Markdown report saved to:[/bold green] [cyan]{args.markdown}[/cyan]")


def interactive_mode(args):
    """Interactive CLI REPL for Windows Terminal and Kali Linux."""
    print_banner()
    console.print("[bold green]Interactive Mode Active.[/bold green] Type target URL to inspect (or 'exit' to quit).\n")

    while True:
        try:
            target = Prompt.ask("[bold cyan]phish-tracker[/bold cyan] >")
            target = target.strip()
            if not target:
                continue
            if target.lower() in ["exit", "quit", "q"]:
                console.print("[yellow]Exiting PhishTracker. Stay safe![/yellow]")
                break

            scan_single(target, args)
            console.print("-" * 60)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Session interrupted. Exiting.[/yellow]")
            break


def main():
    parser = argparse.ArgumentParser(
        description="PhishTracker: Advanced Phishing Site Detector (Kali Linux & Windows Terminal)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phish_tracker.py -u "https://paypal-security-update.xyz/login"
  python phish_tracker.py -f samples/test_urls.txt
  python phish_tracker.py -u "http://192.168.1.50/bank" --fast
  python phish_tracker.py -u "https://suspicious-site.top" --json report.json --markdown report.md
  python phish_tracker.py   (Enters interactive prompt)
        """
    )
    parser.add_argument("-u", "--url", type=str, help="Target URL or domain to inspect")
    parser.add_argument("-f", "--file", type=str, help="Path to text file containing list of target URLs")
    parser.add_argument("--fast", action="store_true", help="Fast mode (lexical URL heuristics only, skip network queries)")
    parser.add_argument("--no-content", action="store_true", help="Skip passive HTML/DOM fetching (perform DNS, WHOIS, and SSL only)")
    parser.add_argument("--json", type=str, help="Export analysis result to JSON file")
    parser.add_argument("-m", "--markdown", type=str, help="Export analysis result to Markdown incident report")

    args = parser.parse_args()

    # If no URL or file provided, default to interactive mode
    if not args.url and not args.file:
        interactive_mode(args)
    elif args.url:
        print_banner()
        scan_single(args.url, args)
    elif args.file:
        print_banner()
        scan_batch(args.file, args)


if __name__ == "__main__":
    main()
