from datetime import datetime
from rich.table import Table
from rich.text import Text
from rich import box

RISK_COLORS = {
    "CRITICAL": "bright_white",
    "HIGH":     "cyan",
    "MEDIUM":   "steel_blue1",
    "LOW":      "sky_blue1",
}

def _score_bar(score: int) -> Text:
    filled = round(score)
    empty = 10 - filled
    if score >= 7:
        color = "bright_white"
    elif score >= 5:
        color = "cyan"
    elif score >= 3:
        color = "steel_blue1"
    else:
        color = "sky_blue1"
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * empty, style="dim white")
    bar.append(f" {score}/10", style=color)
    return bar

def _risk_badge(level: str) -> Text:
    color = RISK_COLORS.get(level, "white")
    return Text(f" {level} ", style=f"bold {color}")

def alerts_table(alerts: list) -> Table:
    table = Table(box=box.ROUNDED, border_style="yellow", show_header=True, header_style="bold cyan")
    table.add_column("Timestamp",  style="dim white", width=20)
    table.add_column("File",       style="white",     max_width=35)
    table.add_column("User",       style="cyan",      width=10)
    table.add_column("Process",    style="cyan",      width=12)
    table.add_column("Score",      width=18)
    table.add_column("Risk",       width=10)

    for a in sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True):
        table.add_row(
            a.get("timestamp", ""),
            a.get("file", ""),
            a.get("user", ""),
            a.get("process", ""),
            _score_bar(a.get("score", 0)),
            _risk_badge(a.get("risk_level", "LOW")),
        )
    return table

def honeyfiles_table(baseline: list, alerts: list) -> Table:
    table = Table(box=box.ROUNDED, border_style="yellow", show_header=True, header_style="bold cyan")
    table.add_column("Name",          style="white",     width=28)
    table.add_column("Path",          style="dim white", max_width=40)
    table.add_column("Status",        width=12)
    table.add_column("Hits",          width=6)
    table.add_column("Last Accessed", width=20)

    for entry in baseline:
        path = entry.get("path", "")
        hits = [a for a in alerts if a.get("file") == path]
        hit_count = len(hits)
        last = hits[-1]["timestamp"] if hits else "—"
        status = Text(" TRIGGERED ", style="bold red") if hit_count else Text(" ARMED ", style="bold green")
        table.add_row(
            entry.get("name", ""),
            path,
            status,
            str(hit_count),
            last,
        )
    return table

def timeline_table(alerts: list) -> Table:
    table = Table(box=box.ROUNDED, border_style="yellow", show_header=True, header_style="bold cyan")
    table.add_column("Time",    style="dim white", width=20)
    table.add_column("User",    style="cyan",      width=10)
    table.add_column("Process", style="cyan",      width=12)
    table.add_column("File",    style="white",     max_width=35)
    table.add_column("Risk",    width=10)

    sorted_alerts = sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)
    last_date = None

    for a in sorted_alerts:
        ts = a.get("timestamp", "")
        date = ts[:10] if ts else ""
        if date != last_date:
            table.add_row(f"[bold yellow]── {date} ──[/bold yellow]", "", "", "", "")
            last_date = date
        table.add_row(
            ts[11:] if len(ts) > 10 else ts,
            a.get("user", ""),
            a.get("process", ""),
            a.get("file", ""),
            _risk_badge(a.get("risk_level", "LOW")),
        )
    return table

def users_table(alerts: list) -> Table:
    table = Table(box=box.ROUNDED, border_style="yellow", show_header=True, header_style="bold cyan")
    table.add_column("User",       width=14)
    table.add_column("Events",     width=8)
    table.add_column("Files Hit",  width=10)
    table.add_column("Max Score",  width=12)
    table.add_column("Pattern",    style="dim white")

    user_map = {}
    for a in alerts:
        u = a.get("user", "unknown")
        if u not in user_map:
            user_map[u] = {"events": 0, "files": set(), "max_score": 0}
        user_map[u]["events"] += 1
        user_map[u]["files"].add(a.get("file", ""))
        user_map[u]["max_score"] = max(user_map[u]["max_score"], a.get("score", 0))

    for user, data in sorted(user_map.items(), key=lambda x: -x[1]["max_score"]):
        file_count = len(data["files"])
        pattern = "systematic" if file_count > 1 else "single file"
        user_text = Text(user, style="bold red") if user == "root" else Text(user)
        table.add_row(
            user_text,
            str(data["events"]),
            str(file_count),
            _score_bar(data["max_score"]),
            pattern,
        )
    return table


if __name__ == "__main__":
    from rich.console import Console
    from hivebee.logger import read_alerts
    from hivebee import BASE_DIR
    import json

    console = Console()
    alerts = read_alerts()

    baseline_path = BASE_DIR / "logs" / "baseline.json"
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else []

    console.print("\n[bold yellow]ALERTS TABLE[/bold yellow]")
    console.print(alerts_table(alerts))

    console.print("\n[bold yellow]HONEYFILES TABLE[/bold yellow]")
    console.print(honeyfiles_table(baseline, alerts))

    console.print("\n[bold yellow]TIMELINE[/bold yellow]")
    console.print(timeline_table(alerts))

    console.print("\n[bold yellow]USERS[/bold yellow]")
    console.print(users_table(alerts))
