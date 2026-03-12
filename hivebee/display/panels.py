import json
import subprocess
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich import box
from hivebee import load_config, BASE_DIR, __version__
from hivebee.monitor import is_auditd_running, get_rule_count

console = Console()

def status_panel(alerts: list, baseline: list) -> Panel:
    auditd = "[green]RUNNING[/green]" if is_auditd_running() else "[red]STOPPED[/red]"
    armed = len(baseline)
    total = len(alerts)
    critical = sum(1 for a in alerts if a.get("risk_level") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("risk_level") == "HIGH")
    last = alerts[-1]["timestamp"] if alerts else "—"

    recent = alerts[-3:] if len(alerts) >= 3 else alerts
    recent_lines = "\n".join(
        f"  [dim]{a['timestamp']}[/dim] [cyan]{a['user']}[/cyan] → {a['file']}"
        for a in reversed(recent)
    ) or "  No alerts yet"

    content = (
        f"[bold cyan]System Time :[/bold cyan]  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[bold cyan]auditd      :[/bold cyan]  {auditd}\n"
        f"[bold cyan]Version     :[/bold cyan]  v{__version__}\n\n"
        f"[bold cyan]Files Armed :[/bold cyan]  [green]{armed}[/green]\n"
        f"[bold cyan]Total Alerts:[/bold cyan]  {total}\n"
        f"[bold cyan]Critical    :[/bold cyan]  [bright_white]{critical}[/bright_white]\n"
        f"[bold cyan]High        :[/bold cyan]  [cyan]{high}[/cyan]\n"
        f"[bold cyan]Last Alert  :[/bold cyan]  {last}\n\n"
        f"[bold cyan]Recent:[/bold cyan]\n{recent_lines}"
    )
    return Panel(content, title="[bold yellow]SYSTEM STATUS[/bold yellow]", border_style="yellow", box=box.ROUNDED)

def install_output(steps: list):
    TAG_COLORS = {
        "SCAN":     "cyan",
        "DETECT":   "steel_blue1",
        "AI":       "bright_white",
        "GENERATE": "sky_blue1",
        "DEPLOY":   "cyan",
        "AUDIT":    "steel_blue1",
        "DONE":     "green",
        "ERROR":    "red",
        "SKIP":     "dim white",
    }
    for tag, message in steps:
        color = TAG_COLORS.get(tag, "white")
        console.print(f"  [[{color}]{tag}[/{color}]] {message}")

def file_detail(path: str, alerts: list):
    hits = [a for a in alerts if a.get("file") == path]
    if not hits:
        console.print(f"[dim]No events recorded for {path}[/dim]")
        return

    console.print(f"\n[bold cyan]File:[/bold cyan] {path}")
    console.print(f"[bold cyan]Total hits:[/bold cyan] {len(hits)}\n")

    table = Table(box=box.SIMPLE, header_style="bold cyan", show_header=True)
    table.add_column("Timestamp", style="dim white", width=20)
    table.add_column("User",      style="cyan",      width=10)
    table.add_column("Process",   style="cyan",      width=12)
    table.add_column("Score",     width=12)
    table.add_column("Risk",      width=10)

    from hivebee.display.tables import _score_bar, _risk_badge
    for a in sorted(hits, key=lambda x: x.get("timestamp", "")):
        table.add_row(
            a.get("timestamp", ""),
            a.get("user", ""),
            a.get("process", ""),
            _score_bar(a.get("score", 0)),
            _risk_badge(a.get("risk_level", "LOW")),
        )
    console.print(table)

def config_editor():
    config = load_config()
    config_path = BASE_DIR / "config" / "default_config.yaml"

    while True:
        console.print("\n[bold yellow]CONFIG EDITOR[/bold yellow]\n")
        scoring = config.get("scoring", {})
        alerts_cfg = config.get("alerts", {})
        ai_cfg = config.get("ai", {})
        monitor_cfg = config.get("monitor", {})
        whitelist = config.get("whitelisted_processes", [])

        console.print(f"  [bold cyan]1.[/bold cyan]  Root access points     : {scoring.get('root_access_points', 4)}")
        console.print(f"  [bold cyan]2.[/bold cyan]  Unknown process points  : {scoring.get('unknown_process_points', 3)}")
        console.print(f"  [bold cyan]3.[/bold cyan]  Credential file points  : {scoring.get('credential_file_points', 2)}")
        console.print(f"  [bold cyan]4.[/bold cyan]  After hours points      : {scoring.get('after_hours_points', 2)}")
        console.print(f"  [bold cyan]5.[/bold cyan]  Critical threshold      : {scoring.get('critical_threshold', 7)}")
        console.print(f"  [bold cyan]6.[/bold cyan]  Notify on level         : {alerts_cfg.get('notify_on', 'HIGH')}")
        console.print(f"  [bold cyan]7.[/bold cyan]  Desktop notifications   : {alerts_cfg.get('desktop', True)}")
        console.print(f"  [bold cyan]8.[/bold cyan]  AI enabled              : {ai_cfg.get('enabled', True)}")
        console.print(f"  [bold cyan]9.[/bold cyan]  Poll interval (seconds) : {monitor_cfg.get('poll_interval', 5)}")
        console.print(f"  [bold cyan]10.[/bold cyan] Whitelisted processes   : {', '.join(whitelist)}")
        console.print(f"\n  [bold cyan]s.[/bold cyan] Save   [bold cyan]q.[/bold cyan] Back\n")

        choice = Prompt.ask("[cyan]>[/cyan]").strip().lower()

        if choice == "q":
            break
        elif choice == "s":
            import yaml
            config_path.write_text(yaml.dump(config, default_flow_style=False))
            console.print("[green]Config saved.[/green]")
            break
        elif choice == "1":
            v = Prompt.ask("Root access points").strip()
            if v: config["scoring"]["root_access_points"] = int(v)
        elif choice == "2":
            v = Prompt.ask("Unknown process points").strip()
            if v: config["scoring"]["unknown_process_points"] = int(v)
        elif choice == "3":
            v = Prompt.ask("Credential file points").strip()
            if v: config["scoring"]["credential_file_points"] = int(v)
        elif choice == "4":
            v = Prompt.ask("After hours points").strip()
            if v: config["scoring"]["after_hours_points"] = int(v)
        elif choice == "5":
            v = Prompt.ask("Critical threshold").strip()
            if v: config["scoring"]["critical_threshold"] = int(v)
        elif choice == "6":
            v = Prompt.ask("Notify on [LOW/MEDIUM/HIGH/CRITICAL]").strip().upper()
            if v: config["alerts"]["notify_on"] = v
        elif choice == "7":
            v = Prompt.ask("Desktop notifications [true/false]").strip().lower()
            if v: config["alerts"]["desktop"] = v == "true"
        elif choice == "8":
            v = Prompt.ask("AI enabled [true/false]").strip().lower()
            if v: config["ai"]["enabled"] = v == "true"
        elif choice == "9":
            v = Prompt.ask("Poll interval (seconds)").strip()
            if v: config["monitor"]["poll_interval"] = int(v)
        elif choice == "10":
            v = Prompt.ask("Whitelisted processes (comma separated)").strip()
            if v: config["whitelisted_processes"] = [x.strip() for x in v.split(",")]


if __name__ == "__main__":
    from hivebee.logger import read_alerts
    import json

    alerts = read_alerts()
    baseline_path = BASE_DIR / "logs" / "baseline.json"
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else []
    console.print(status_panel(alerts, baseline))
