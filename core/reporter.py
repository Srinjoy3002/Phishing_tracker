import sys
import json
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(legacy_windows=False)



def render_terminal_report(result: dict):
    """
    Render a comprehensive terminal dashboard for single URL scan results.
    """
    score = result["risk_score"]
    color_tag = result["color_tag"]
    emoji = result["emoji"]
    classification = result["classification"]
    telemetry = result["telemetry"]
    findings = result["findings"]
    recs = result["recommendations"]

    # 1. Header Overview
    console.print()
    overview_table = Table(show_header=False, box=None, padding=(0, 2))
    overview_table.add_row("[bold cyan]Target URL:[/bold cyan]", f"[bold white]{result['url']}[/bold white]")
    overview_table.add_row("[bold cyan]Resolved Host:[/bold cyan]", f"[yellow]{result['hostname']}[/yellow]")
    overview_table.add_row("[bold cyan]Scheme / Protocol:[/bold cyan]", f"{result['scheme'].upper()}")
    console.print(overview_table)
    console.print()

    # 2. Visual Risk Score Gauge
    bar_width = 30
    filled_blocks = int((score / 100) * bar_width)
    empty_blocks = bar_width - filled_blocks
    
    if score >= 70:
        bar_color = "red"
    elif score >= 50:
        bar_color = "yellow"
    elif score >= 25:
        bar_color = "cyan"
    else:
        bar_color = "green"

    gauge_bar = f"[{bar_color}]{'█' * filled_blocks}[/{bar_color}][dim]{'░' * empty_blocks}[/dim]"
    
    meter_panel = Panel(
        f"  [bold]Threat Level:[/bold] {emoji} [{color_tag}]{classification}[/{color_tag}]\n"
        f"  [bold]Risk Score:[/bold]   {gauge_bar} [bold {bar_color}]{score} / 100[/bold {bar_color}]\n"
        f"  [bold]Indicators:[/bold]   [bold white]{len(findings)} flagged[/bold white]",
        title="[bold white]ANALYSIS ASSESSMENT[/bold white]",
        border_style=bar_color
    )
    console.print(meter_panel)
    console.print()

    # 3. Telemetry Highlights Table
    telem_table = Table(title="[bold cyan]Infrastructure & Domain Telemetry[/bold cyan]", border_style="dim")
    telem_table.add_column("Vector", style="bold white", width=22)
    telem_table.add_column("Observed Value", style="cyan")
    telem_table.add_column("Assessment", style="dim white")

    # Domain Age
    age_days = telemetry["whois"].get("age_days")
    if age_days is not None:
        age_str = f"{age_days} days (Created: {telemetry['whois'].get('creation_date', 'N/A')})"
        age_eval = "[bold red]High Risk (Fresh)[/bold red]" if age_days < 30 else ("[yellow]Young[/yellow]" if age_days < 90 else "[green]Established[/green]")
    else:
        age_str = "Unavailable / Private"
        age_eval = "[dim]Unverified[/dim]"
    telem_table.add_row("Domain Age", age_str, age_eval)

    # DNS Resolution
    a_records = telemetry["dns"].get("a_records", [])
    ip_str = ", ".join(a_records[:3]) if a_records else "Unresolved"
    telem_table.add_row("Resolved IP(s)", ip_str, "[green]Active[/green]" if a_records else "[red]Dead / Sinkholed[/red]")

    # MX Records
    mx_records = telemetry["dns"].get("mx_records", [])
    mx_str = f"{len(mx_records)} MX Record(s)" if mx_records else "None detected"
    mx_eval = "[green]Configured[/green]" if mx_records else "[yellow]No Mail Server[/yellow]"
    telem_table.add_row("Mail Exchange (MX)", mx_str, mx_eval)

    # SSL Issuer
    has_ssl = telemetry["ssl"].get("has_ssl", False)
    if has_ssl:
        ssl_str = f"{telemetry['ssl'].get('issuer', 'N/A')} ({telemetry['ssl'].get('days_remaining', 'N/A')} days left)"
        ssl_eval = "[red]Self-Signed[/red]" if telemetry["ssl"].get("is_self_signed") else "[green]Valid Certificate[/green]"
    else:
        ssl_str = "No SSL / Failed Handshake"
        ssl_eval = "[red]Unencrypted[/red]"
    telem_table.add_row("SSL/TLS Identity", ssl_str, ssl_eval)

    # Shannon Entropy
    entropy = telemetry["lexical"].get("entropy", 0.0)
    ent_eval = "[red]Suspicious (Random/DGA)[/red]" if entropy >= 3.8 else "[green]Normal[/green]"
    telem_table.add_row("Domain Entropy", f"{entropy} bits", ent_eval)

    # Page Title
    page_title = telemetry["content"].get("title", "N/A")
    telem_table.add_row("HTML Page Title", page_title[:45] if page_title else "None", "[dim]DOM Inspection[/dim]")

    console.print(telem_table)
    console.print()

    # 4. Triggered Indicators / Findings Table
    if findings:
        findings_table = Table(title="[bold red]Triggered Threat Indicators[/bold red]", border_style="red")
        findings_table.add_column("Severity", width=12)
        findings_table.add_column("Category", width=16, style="cyan")
        findings_table.add_column("Indicator Title", style="bold white", width=32)
        findings_table.add_column("MITRE ATT&CK", width=14, style="magenta")
        findings_table.add_column("Evidence & Details", style="dim white")

        for f in findings:
            sev = f.get("severity", "LOW")
            if sev == "CRITICAL":
                sev_styled = "[bold red]CRITICAL[/bold red]"
            elif sev == "HIGH":
                sev_styled = "[red]HIGH[/red]"
            elif sev == "MEDIUM":
                sev_styled = "[yellow]MEDIUM[/yellow]"
            else:
                sev_styled = "[blue]LOW[/blue]"

            mitre = f.get("mitre", "N/A")
            findings_table.add_row(
                sev_styled,
                f.get("category", "General"),
                f.get("title", "Unknown"),
                mitre,
                f.get("description", "")
            )

        console.print(findings_table)
        console.print()
    else:
        console.print(Panel("[bold green]✔ No malicious indicators or anomalous heuristics detected.[/bold green]", border_style="green"))
        console.print()

    # 5. Remediation Recommendations
    if recs:
        rec_text = "\n".join([f" • {r}" for r in recs])
        console.print(Panel(rec_text, title="[bold yellow]SOC Analyst & Incident Response Recommendations[/bold yellow]", border_style="yellow"))
        console.print()


def export_json(result: dict, filepath: str):
    """Export scan results as machine-readable JSON."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    console.print(f"[bold green]✔ JSON report saved to:[/bold green] [cyan]{filepath}[/cyan]")


def export_markdown(result: dict, filepath: str):
    """Export scan results as a Markdown Incident Report."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"# PhishTracker Triage Report: {result['hostname']}",
        f"**Generated:** {now_str}  ",
        f"**Target URL:** `{result['url']}`  ",
        f"**Risk Score:** `{result['risk_score']} / 100` ({result['classification']})  ",
        "\n---\n",
        "## Executive Summary",
        f"- **Threat Classification:** {result['classification']}",
        f"- **Calculated Risk Score:** {result['risk_score']} / 100",
        f"- **Indicators Flagged:** {len(result['findings'])}",
        "\n---\n",
        "## Technical Telemetry",
        "| Vector | Observed Telemetry |",
        "| :--- | :--- |",
        f"| Domain | `{result['hostname']}` |",
        f"| Scheme | `{result['scheme']}` |",
        f"| Resolved IPs | `{', '.join(result['telemetry']['dns'].get('a_records', [])) or 'None'}` |",
        f"| Domain Age | `{result['telemetry']['whois'].get('age_days', 'Unknown')} days` |",
        f"| Registrar | `{result['telemetry']['whois'].get('registrar', 'Unknown')}` |",
        f"| SSL Issuer | `{result['telemetry']['ssl'].get('issuer', 'None')}` |",
        f"| Domain Entropy | `{result['telemetry']['lexical'].get('entropy', 0.0)}` |",
        f"| HTML Title | `{result['telemetry']['content'].get('title', 'None')}` |",
        "\n---\n",
        "## Flagged Indicators & Evidence",
        "| Severity | Category | Indicator | MITRE ATT&CK | Description |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ]

    for f in result["findings"]:
        lines.append(
            f"| **{f.get('severity', 'LOW')}** | {f.get('category', '')} | {f.get('title', '')} | `{f.get('mitre', 'N/A')}` | {f.get('description', '')} |"
        )

    lines.extend([
        "\n---\n",
        "## Recommended Actions",
    ])
    for r in result["recommendations"]:
        lines.append(f"- {r}")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    console.print(f"[bold green]✔ Markdown report saved to:[/bold green] [cyan]{filepath}[/cyan]")
