import json
import subprocess
from datetime import datetime
from hivebee import load_config, BASE_DIR

BASELINE_PATH = BASE_DIR / "logs" / "baseline.json"

def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""

def _load_baseline() -> list:
    if not BASELINE_PATH.exists():
        return []
    try:
        return json.loads(BASELINE_PATH.read_text())
    except Exception:
        return []

def _parse_ausearch_block(block: str) -> dict | None:
    """Parse a single ausearch event block into a flat dict."""
    event = {}
    for line in block.splitlines():
        line = line.strip()
        if "type=SYSCALL" in line:
            for token in line.split():
                if "=" in token:
                    k, _, v = token.partition("=")
                    event[k] = v.strip('"')
        elif "type=PATH" in line:
            for token in line.split():
                if "=" in token:
                    k, _, v = token.partition("=")
                    if k == "name":
                        event["path_name"] = v.strip('"')
    return event if event else None

def parse_events(since: str = None) -> list:
    """
    Run ausearch and return list of canonical event dicts.
    Only returns events matching files in baseline.json.
    since: optional datetime string like '2026-03-11 18:00:00'
    """
    baseline = _load_baseline()
    if not baseline:
        return []

    watched_paths = {entry["path"] for entry in baseline}

    # Build ausearch command
    cmd = "ausearch -k hivebee --interpret"
    if since:
        cmd += f" --start {since}"

    raw = _run(cmd)
    if not raw:
        return []

    # Split into individual event blocks (separated by ----)
    blocks = raw.split("----")
    events = []
    seen_pids = set()

    for block in blocks:
        if not block.strip():
            continue

        parsed = _parse_ausearch_block(block)
        if not parsed:
            continue

        # Match against baseline paths
        matched_path = None
        for path in watched_paths:
            if path in block:
                matched_path = path
                break

        if not matched_path:
            continue

        pid = parsed.get("pid", "0")
        if pid in seen_pids:
            continue
        seen_pids.add(pid)

        # Extract fields
        user = parsed.get("uid", parsed.get("auid", "unknown"))
        process = parsed.get("exe", parsed.get("comm", "unknown"))
        if "/" in process:
            process = process.split("/")[-1]

        # Parse timestamp from block
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for line in block.splitlines():
            if "msg=audit(" in line:
                try:
                    ts_raw = line.split("msg=audit(")[1].split(":")[0]
                    timestamp = datetime.fromtimestamp(float(ts_raw)).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
                break

        events.append({
            "file": matched_path,
            "user": user,
            "process": process,
            "timestamp": timestamp,
            "pid": pid,
            "score": 0,        # filled by scorer
            "risk_level": "",  # filled by scorer
            "reasons": [],     # filled by scorer
        })

    return events


if __name__ == "__main__":
    events = parse_events()
    if not events:
        print("[PARSER] No events found — try touching a honeyfile first:")
        baseline = _load_baseline()
        if baseline:
            print(f"  cat {baseline[0]['path']}")
    else:
        print(f"[PARSER] {len(events)} events found:")
        for e in events:
            print(f"  {e['timestamp']} | {e['user']} | {e['process']} | {e['file']}")
