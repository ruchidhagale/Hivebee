import json
import time
import sys
from rich.console import Console
from rich.live import Live
from hivebee import load_config, BASE_DIR
from hivebee.display.banner import draw_banner, draw_header, draw_menu
from pathlib import Path

console = Console()

def _load_baseline():
    path = BASE_DIR / "logs" / "baseline.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []

def cmd_dashboard():
    from hivebee.logger import read_alerts
    from hivebee.display.tables import alerts_table
    draw_header("dashboard")
    console.print("[dim]Live alert feed — refreshes every 5s. Press Ctrl+C to exit.[/dim]\n")
    try:
        while True:
            alerts = read_alerts()
            config = load_config()
            critical = sum(1 for a in alerts if a.get("risk_level") == "CRITICAL")
            high     = sum(1 for a in alerts if a.get("risk_level") == "HIGH")
            armed    = len(_load_baseline())
            console.clear()
            draw_header("dashboard")
            console.print(
                f"  [bright_white]Total: {len(alerts)}[/bright_white]  "
                f"[bright_white]Critical: {critical}[/bright_white]  "
                f"[cyan]High: {high}[/cyan]  "
                f"[green]Armed: {armed}[/green]\n"
            )
            console.print(alerts_table(alerts))
            time.sleep(5)
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard exited.[/dim]")

def cmd_install():
    from hivebee.scanner import scan
    from hivebee.ai import generate_honeyfiles
    from hivebee.generator import deploy_all
    from hivebee.monitor import apply_rules
    from hivebee.display.banner import draw_header
    from hivebee.display.panels import install_output

    draw_header("install")
    steps = []

    console.print("[dim]Scanning system...[/dim]")
    profile = scan()
    steps.append(("SCAN", f"Detected {profile.get('os', 'Linux')} — {profile.get('system_type', 'workstation')}"))
    detected = profile.get("software", [])
    steps.append(("DETECT", f"Software found: {', '.join(detected) if detected else 'none'}"))
    install_output(steps)

    console.print("\n[dim]Generating honeyfiles...[/dim]")
    files = generate_honeyfiles(profile)
    steps2 = [("AI", f"{len(files)} honeyfiles generated for {profile.get('system_type')}")]
    install_output(steps2)

    console.print("\n[dim]Deploying...[/dim]")
    deployed = deploy_all(files)
    steps3 = [("DEPLOY", f"{len(deployed)} files written to disk")]
    install_output(steps3)

    console.print("\n[dim]Arming auditd rules...[/dim]")
    count = apply_rules(deployed)
    steps4 = [
        ("AUDIT", f"{count} auditd watch rules registered"),
        ("DONE",  f"Run [bold]sudo hivebee monitor[/bold] to start watching"),
    ]
    install_output(steps4)

def cmd_monitor():
    from hivebee.parser import parse_events
    from hivebee.scorer import score_event
    from hivebee.logger import log_alert, log_debug, read_alerts
    from hivebee.alerter import alert
    from hivebee.monitor import clear_rules
    from hivebee.display.tables import _score_bar, _risk_badge

    draw_header("monitor")
    console.print("[dim]Monitoring honeyfiles — press Ctrl+C to stop.[/dim]\n")

    seen_pids = set()
    # Seed with already-logged pids to avoid re-alerting on startup
    for a in read_alerts():
        seen_pids.add(a.get("pid", ""))

    try:
        while True:
            events = parse_events()
            for event in events:
                pid = event.get("pid", "")
                if pid in seen_pids:
                    continue
                seen_pids.add(pid)

                scored = score_event(event)
                log_alert(scored)
                alert(scored)
                log_debug(f"Alert fired: {scored['file']} by {scored['user']} score={scored['score']}")

                console.print(
                    f"  [dim]{scored['timestamp']}[/dim]  "
                    f"[cyan]{scored['user']}[/cyan]  "
                    f"{scored['process']}  "
                    f"{scored['file']}  ",
                    end=""
                )
                console.print(_risk_badge(scored["risk_level"]))

            time.sleep(load_config().get("monitor", {}).get("poll_interval", 5))

    except KeyboardInterrupt:
        console.print("\n[dim]Stopping monitor — clearing auditd rules...[/dim]")
        clear_rules()
        console.print("[green]Monitor stopped cleanly.[/green]")

def cmd_status():
    from hivebee.logger import read_alerts
    from hivebee.display.panels import status_panel
    draw_header("status")
    alerts = read_alerts()
    baseline = _load_baseline()
    console.print(status_panel(alerts, baseline))

def cmd_files():
    from hivebee.logger import read_alerts
    from hivebee.display.tables import honeyfiles_table
    from hivebee.display.panels import file_detail
    from rich.prompt import Prompt

    draw_header("files")
    alerts = read_alerts()
    baseline = _load_baseline()

    if not baseline:
        console.print("[dim]No honeyfiles deployed yet — run install first.[/dim]")
        return

    console.print(honeyfiles_table(baseline, alerts))
    console.print("\n[dim]Enter a number to inspect a file, or q to go back.[/dim]")

    for i, entry in enumerate(baseline, 1):
        console.print(f"  [cyan]{i}.[/cyan] {entry['path']}")

    choice = Prompt.ask("\n[cyan]>[/cyan]").strip().lower()
    if choice == "q":
        return
    try:
        idx = int(choice) - 1
        file_detail(baseline[idx]["path"], alerts)
    except (ValueError, IndexError):
        pass

def cmd_timeline():
    from hivebee.logger import read_alerts
    from hivebee.display.tables import timeline_table
    draw_header("timeline")
    alerts = read_alerts()
    if not alerts:
        console.print("[dim]No alerts yet.[/dim]")
        return
    console.print(timeline_table(alerts))

def cmd_users():
    from hivebee.logger import read_alerts
    from hivebee.display.tables import users_table
    draw_header("users")
    alerts = read_alerts()
    if not alerts:
        console.print("[dim]No alerts yet.[/dim]")
        return
    console.print(users_table(alerts))

def cmd_report():
    from hivebee.reporter import generate_report
    draw_header("report")
    path = generate_report()
    console.print(f"[green]Report saved →[/green] {path}")

def cmd_config():
    from hivebee.display.panels import config_editor
    draw_header("config")
    config_editor()

def cmd_uninstall():
    import json
    from hivebee.monitor import clear_rules

    draw_header("uninstall")

    baseline_path = BASE_DIR / "logs" / "baseline.json"
    if not baseline_path.exists():
        console.print("[dim]No honeyfiles found — nothing to uninstall.[/dim]")
        return

    baseline = json.loads(baseline_path.read_text())
    if not baseline:
        console.print("[dim]Baseline is empty — nothing to uninstall.[/dim]")
        return

    console.print(f"[yellow]This will delete {len(baseline)} honeyfiles and clear all auditd rules.[/yellow]")
    confirm = console.input("\n[cyan]Are you sure? (yes/no)>[/cyan] ").strip().lower()
    if confirm != "yes":
        console.print("[dim]Aborted.[/dim]")
        return

    # Clear auditd rules first
    clear_rules()

    # Delete honeyfiles
    removed = 0
    for entry in baseline:
        path = Path(entry.get("path", ""))
        try:
            if path.exists():
                path.unlink()
                console.print(f"  [red]REMOVED[/red] {path}")
                removed += 1
            else:
                console.print(f"  [dim]SKIP[/dim] {path} — already gone")
        except Exception as e:
            console.print(f"  [red]ERROR[/red] {path} — {e}")

    # Clear baseline
    baseline_path.write_text("[]")

    console.print(f"\n[green]Uninstall complete — {removed} files removed.[/green]")

COMMANDS = {
    "1": cmd_dashboard,
    "2": cmd_install,
    "3": cmd_monitor,
    "4": cmd_status,
    "5": cmd_files,
    "6": cmd_timeline,
    "7": cmd_users,
    "8": cmd_report,
    "9": cmd_config,
    "dashboard": cmd_dashboard,
    "install":   cmd_install,
    "monitor":   cmd_monitor,
    "status":    cmd_status,
    "files":     cmd_files,
    "timeline":  cmd_timeline,
    "users":     cmd_users,
    "report":    cmd_report,
    "config":    cmd_config,
    "uninstall": cmd_uninstall,
}

def main():
    # Allow direct CLI args: sudo hivebee monitor
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd in COMMANDS:
            COMMANDS[cmd]()
        elif cmd in ("--version", "-v"):
            from hivebee import __version__
            console.print(f"hivebee v{__version__}")
        else:
            console.print(f"[red]Unknown command:[/red] {cmd}")
            console.print("Usage: hivebee [dashboard|install|monitor|status|files|timeline|users|report|config]")
        return

    # Interactive menu loop
    while True:
        choice = draw_menu()
        if choice in ("q", "quit", "exit"):
            console.print("\n[dim]Don't touch the hive.[/dim]\n")
            break
        elif choice in COMMANDS:
            try:
                COMMANDS[choice]()
            except Exception as e:
                console.print(f"\n[red]Error:[/red] {e}")
            console.input("\n[dim]Press Enter to return to menu...[/dim]")
        else:
            console.print("[dim]Invalid choice.[/dim]")

if __name__ == "__main__":
    main()
