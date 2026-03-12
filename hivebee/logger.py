import json
from datetime import datetime
from pathlib import Path
from hivebee import load_config, BASE_DIR

def _get_paths():
    config = load_config()
    logging_cfg = config.get("logging", {})
    alerts_log = BASE_DIR / logging_cfg.get("alerts_log", "logs/alerts.json")
    debug_log = BASE_DIR / logging_cfg.get("debug_log", "logs/debug.log")
    return alerts_log, debug_log

def log_alert(event: dict):
    alerts_path, _ = _get_paths()
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    with open(alerts_path, "a") as f:
        f.write(json.dumps(event) + "\n")

def log_debug(message: str):
    _, debug_path = _get_paths()
    debug_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(debug_path, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def read_alerts() -> list:
    alerts_path, _ = _get_paths()
    if not alerts_path.exists():
        return []
    events = []
    for line in alerts_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            continue
    return events

def clear_alerts():
    alerts_path, _ = _get_paths()
    if alerts_path.exists():
        alerts_path.write_text("")


if __name__ == "__main__":
    # Test write and read back
    test_event = {
        "file": "/home/kali/db_credentials.txt",
        "user": "root",
        "process": "cat",
        "timestamp": "2026-03-11 18:06:55",
        "pid": "12345",
        "score": 9,
        "risk_level": "CRITICAL",
        "reasons": ["root access (+4)", "unlisted process cat (+3)", "credential filename (+2)"],
    }

    log_alert(test_event)
    log_debug("Test debug message from logger.py")

    alerts = read_alerts()
    print(f"[LOGGER] {len(alerts)} alert(s) in log:")
    for a in alerts:
        print(f"  {a['timestamp']} | {a['risk_level']} | {a['file']}")
