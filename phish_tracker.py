#!/usr/bin/env python3
"""
PhishTracker: Advanced Cross-Platform Phishing Site Detector
Operable on Kali Linux & Windows Terminal
Features: PyPhisher/Zphisher Kit Detection, Cloudflare Tunnel Telemetry, Tor & Proxy OPSEC Anonymity
Author: Srinjoy3002
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
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

# Ensure local directory is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.banner import print_banner
from core.engine import scan_target
from core.reporter import render_terminal_report, export_json, export_markdown

console = Console(legacy_windows=False)


def scan_single(url: str, args) -> dict:
    """Scan a single target with live spinner status updates and OPSEC routing."""
    with console.status(f"[bold cyan]Scanning target: [white]{url}[/white]...", spinner="dots") as status:
        def update_progress(msg: str):
            status.update(f"[bold cyan]{msg}")

        result = scan_target(
            target_url=url,
            fast_mode=args.fast,
            skip_content=args.no_content or args.passive,
            proxy=args.proxy,
            use_tor=args.tor,
            progress_callback=update_progress
        )

    # Render terminal report
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
                skip_content=args.no_content or args.passive,
                proxy=args.proxy,
                use_tor=args.tor,
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
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(f"# PhishTracker Batch Scan Matrix ({len(urls)} targets)\n\n")
            f.write("| Host | Score | Threat Level | Findings Count |\n| :--- | :--- | :--- | :--- |\n")
            for r in results:
                f.write(f"| `{r['hostname']}` | **{r['risk_score']}** | {r['classification']} | {len(r['findings'])} |\n")
        console.print(f"[bold green]✔ Batch Markdown report saved to:[/bold green] [cyan]{args.markdown}[/cyan]")


def interactive_mode(args):
    """Interactive CLI REPL with OPSEC privacy guard."""
    print_banner()

    opsec_notice = (
        "[bold white]OPSEC ADVISORY:[/bold white]\n"
        " • Active content analysis sends HTTP requests to target servers.\n"
        " • Phishing kits (e.g. PyPhisher, Zphisher) use IP-loggers (ip-api.com) to record victim IPs.\n"
        " • [bold green]Recommended:[/bold green] Use [bold cyan]--tor[/bold cyan] or [bold cyan]--proxy[/bold cyan] to anonymize, or [bold cyan]--passive[/bold cyan] for zero-touch inspection."
    )
    console.print(Panel(opsec_notice, border_style="yellow", title="[bold yellow]OPERATIONAL SECURITY[/bold yellow]"))
    console.print()

    # If neither tor nor proxy is set, ask if user wants stealth mode
    if not args.tor and not args.proxy and not args.passive:
        use_stealth = Confirm.ask("[yellow]Enable Stealth Mode (skips active DOM requests to keep your IP hidden from PyPhisher)?[/yellow]", default=False)
        if use_stealth:
            args.passive = True

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
        description="PhishTracker: Multi-Vector Phishing Detector with OPSEC & PyPhisher Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan PyPhisher Cloudflare Quick Tunnel:
  python phish_tracker.py -u "https://occupation-exposure-piece-spam.trycloudflare.com"

  # Scan with Deceptive URL Masking Bait (@ trick):
  python phish_tracker.py -u "https://get-unlimited-followers-for-instagram@occupation-exposure-piece-spam.trycloudflare.com"

  # Anonymize through Tor to prevent PyPhisher from logging your IP:
  python phish_tracker.py -u "https://suspicious-link.com" --tor

  # Route through custom SOCKS5 / HTTP proxy:
  python phish_tracker.py -u "https://suspicious-link.com" --proxy "socks5h://127.0.0.1:9050"

  # Zero-Touch Stealth Recon (Zero packets sent to target web server, 100% invisible to PyPhisher):
  python phish_tracker.py -u "https://suspicious-link.com" --passive

  # Batch Triage:
  python phish_tracker.py -f samples/test_urls.txt
        """
    )
    parser.add_argument("-u", "--url", type=str, help="Target URL or domain to inspect")
    parser.add_argument("-f", "--file", type=str, help="Path to text file containing list of target URLs")
    parser.add_argument("--tor", action="store_true", help="Route traffic through local Tor SOCKS5 proxy (port 9050 / 9150) to anonymize IP")
    parser.add_argument("--proxy", type=str, help="Custom proxy URL (e.g. socks5h://127.0.0.1:1080 or http://127.0.0.1:8080)")
    parser.add_argument("--passive", action="store_true", help="Zero-touch passive mode: Skip HTTP requests to target server to prevent IP logging")
    parser.add_argument("--fast", action="store_true", help="Fast mode: Lexical heuristics only (skip network/DNS queries)")
    parser.add_argument("--no-content", action="store_true", help="Skip HTML/DOM fetching (DNS, WHOIS, and SSL only)")
    parser.add_argument("--json", type=str, help="Export analysis result to JSON file")
    parser.add_argument("-m", "--markdown", type=str, help="Export analysis result to Markdown incident report")

    args = parser.parse_args()

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
