import json
from collections import Counter
from datetime import datetime
from hivebee import BASE_DIR, __version__
from hivebee.logger import read_alerts

def generate_report() -> str:
    alerts = read_alerts()
    baseline_path = BASE_DIR / "logs" / "baseline.json"
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else []

    now = datetime.now()
    filename = f"report_{now.strftime('%Y-%m-%d')}.txt"
    output_path = BASE_DIR / "logs" / filename

    total = len(alerts)
    critical = sum(1 for a in alerts if a.get("risk_level") == "CRITICAL")
    high = sum(1 for a in alerts if a.get("risk_level") == "HIGH")
    medium = sum(1 for a in alerts if a.get("risk_level") == "MEDIUM")
    low = sum(1 for a in alerts if a.get("risk_level") == "LOW")

    # Top offender (user with most events)
    users = Counter(a.get("user", "unknown") for a in alerts)
    top_offender = users.most_common(1)[0] if users else ("none", 0)

    # Honeyfile hit map
    file_hits = Counter(a.get("file", "") for a in alerts)

    lines = []
    lines.append("=" * 60)
    lines.append(f"  HIVEBEE IDS v{__version__} — THREAT REPORT")
    lines.append(f"  Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)
    lines.append("")

    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total Events  : {total}")
    lines.append(f"  Critical      : {critical}")
    lines.append(f"  High          : {high}")
    lines.append(f"  Medium        : {medium}")
    lines.append(f"  Low           : {low}")
    lines.append(f"  Top Offender  : {top_offender[0]} ({top_offender[1]} events)")
    lines.append(f"  Files Armed   : {len(baseline)}")
    lines.append("")

    lines.append("HONEYFILE HIT MAP")
    lines.append("-" * 40)
    if file_hits:
        for path, count in file_hits.most_common():
            lines.append(f"  {count:>3}x  {path}")
    else:
        lines.append("  No files triggered.")
    lines.append("")

    lines.append("FULL EVENT LOG")
    lines.append("-" * 40)
    for a in sorted(alerts, key=lambda x: x.get("timestamp", "")):
        lines.append(f"  [{a.get('risk_level', 'LOW'):>8}] {a.get('timestamp', '')}  "
                     f"user={a.get('user', '')}  process={a.get('process', '')}  "
                     f"score={a.get('score', 0)}/10")
        lines.append(f"            file={a.get('file', '')}")
        reasons = a.get("reasons", [])
        if reasons:
            lines.append(f"            reasons: {', '.join(reasons)}")
        lines.append("")

    lines.append("=" * 60)
    lines.append("  END OF REPORT")
    lines.append("=" * 60)

    report_text = "\n".join(lines)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text)
    return str(output_path)


if __name__ == "__main__":
    path = generate_report()
    print(f"[REPORTER] Report saved to {path}")
