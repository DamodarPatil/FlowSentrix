"""
NetGuard CLI Banner
ASCII art and startup information display.
"""
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = r"""
 ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
"""

VERSION = "1.0.0"


def print_banner(db_packets=0, sessions=0, interface=None):
    """Print the startup banner with system info."""
    # Print ASCII art in cyan
    banner_text = Text(BANNER)
    banner_text.stylize("bold cyan")
    console.print(banner_text, highlight=False)
    
    # Tagline
    console.print("        [bold white]Network Traffic Analyzer • Protocol Inspector • Threat Monitor[/]")
    console.print()
    
    # System info line
    info_parts = [
        f"[bold green]Version[/]: {VERSION}",
        f"[bold green]Protocols[/]: 12+",
    ]
    if interface:
        info_parts.append(f"[bold green]Interface[/]: {interface}")
    console.print("   " + "  │  ".join(info_parts))
    
    # DB stats line
    db_parts = [
        f"[bold yellow]Database[/]: {db_packets:,} packets",
        f"[bold yellow]Sessions[/]: {sessions}",
    ]
    console.print("   " + "  │  ".join(db_parts))
    console.print()
    
    # Tip
    console.print("   [dim]Type [bold white]help[/bold white] to see available commands[/dim]")
    console.print()
