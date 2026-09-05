import sys
import platform
from rich.console import Console
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


BANNER_ART = r"""
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
  ██████╔╝███████║██║███████╗███████║   ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║   ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
  ██║     ██║  ██║██║███████║██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
"""


def print_banner():
    """Render the cybersecurity terminal banner."""
    os_name = platform.system()
    os_release = platform.release()
    arch = platform.machine()
    
    env_str = f"Target Environment: {os_name} {os_release} ({arch}) | Python {platform.python_version()}"
    subtitle = "Next-Gen Heuristic Phishing Site Detector | Kali Linux & Windows Terminal Edition"
    
    banner_text = Text()
    banner_text.append(BANNER_ART, style="bold cyan")
    banner_text.append(f"\n   {subtitle}\n", style="bold yellow")
    banner_text.append(f"   {env_str}\n", style="dim white")

    panel = Panel(
        banner_text,
        border_style="bright_blue",
        title="[bold green]v1.0.0 [SEC-TOOL][/bold green]",
        subtitle="[dim]Defensive Cyber Operations & URL Triage[/dim]"
    )
    console.print(panel)
