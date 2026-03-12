import subprocess
from pathlib import Path

def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""

def apply_rules(baseline: list) -> int:
    """Register auditd watch rules for every honeyfile in baseline."""
    count = 0
    for entry in baseline:
        path = entry.get("path")
        if not path or not Path(path).exists():
            continue
        result = _run(f"auditctl -w {path} -p rwa -k hivebee")
        count += 1
        print(f"  [AUDIT] watching → {path}")
    return count

def clear_rules():
    """Remove all hivebee auditd rules cleanly."""
    # Get all hivebee rules
    rules = _run("auditctl -l")
    for line in rules.splitlines():
        if "hivebee" in line:
            # Convert -a to -d to delete the rule
            delete_cmd = line.replace("-a always,exit", "-d always,exit") \
                             .replace("-a exit,always", "-d exit,always")
            _run(f"auditctl {delete_cmd}")
    print("[MONITOR] auditd rules cleared")

def is_auditd_running() -> bool:
    status = _run("systemctl is-active auditd")
    return status == "active"

def get_rule_count() -> int:
    rules = _run("auditctl -l")
    return sum(1 for line in rules.splitlines() if "hivebee" in line)


if __name__ == "__main__":
    import json
    from hivebee import BASE_DIR

    BASELINE_PATH = BASE_DIR / "logs" / "baseline.json"

    if not BASELINE_PATH.exists():
        print("[ERROR] No baseline.json found — run generator first")
        exit(1)

    baseline = json.loads(BASELINE_PATH.read_text())

    print(f"[MONITOR] auditd running: {is_auditd_running()}")
    count = apply_rules(baseline)
    print(f"[MONITOR] {count} rules applied")
    print(f"\nVerify with: sudo auditctl -l | grep hivebee")
