from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich import box
from hivebee import __version__

console = Console()

ASCII_ART = """██╗  ██╗██╗██╗   ██╗███████╗██████╗ ███████╗███████╗
██║  ██║██║██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝
███████║██║██║   ██║█████╗  ██████╔╝█████╗  █████╗  
██╔══██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══╝  ██╔══╝  
██║  ██║██║ ╚████╔╝ ███████╗██████╔╝███████╗███████╗
╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═════╝ ╚══════╝╚══════╝"""

def draw_banner():
    console.print(Text(ASCII_ART, style="bold yellow"))
    console.print(Text("Deception-Based Intrusion Detection", style="dim white"), justify="center")
    console.print(Text(f"v{__version__}", style="cyan"), justify="center")
    console.print()

def draw_header(title: str):
    console.print(f"\n[cyan]// {title.upper()}[/cyan]\n")

def draw_menu() -> str:
    draw_banner()
    menu = Panel(
        "\n".join([
            "  [bold white]1.[/bold white] Dashboard  — live alert feed",
            "  [bold white]2.[/bold white] Install   — scan + deploy honeyfiles",
            "  [bold white]3.[/bold white] Monitor   — start live monitoring",
            "  [bold white]4.[/bold white] Status    — system overview",
            "  [bold white]5.[/bold white] Files     — inspect honeyfiles",
            "  [bold white]6.[/bold white] Timeline  — threat history",
            "  [bold white]7.[/bold white] Users     — who triggered what",
            "  [bold white]8.[/bold white] Report    — export summary",
            "  [bold white]9.[/bold white] Config    — edit settings",
            "",
            "  [bold white]q.[/bold white] Quit",
        ]),
        title="[bold yellow]HIVEBEE IDS[/bold yellow]",
        border_style="yellow",
        box=box.ROUNDED,
    )
    console.print(menu)
    return console.input("\n[cyan]>[/cyan] ").strip().lower()
