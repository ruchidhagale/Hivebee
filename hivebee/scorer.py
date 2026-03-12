from datetime import datetime
from hivebee import load_config

CREDENTIAL_KEYWORDS = [
    "password", "passwd", "credentials", "creds", "secret",
    "private", "id_rsa", "token", "api_key", "auth", "bank",
    "wallet", "db_dump", "backup", "shadow", "master"
]

def score_event(event: dict) -> dict:
    config = load_config()
    scoring = config.get("scoring", {})
    whitelist = config.get("whitelisted_processes", [])

    root_pts     = scoring.get("root_access_points", 4)
    process_pts  = scoring.get("unknown_process_points", 3)
    cred_pts     = scoring.get("credential_file_points", 2)
    hours_pts    = scoring.get("after_hours_points", 2)
    threshold    = scoring.get("critical_threshold", 7)

    score = 0
    reasons = []

    # Rule 1 — root access
    if event.get("user") in ("root", "0"):
        score += root_pts
        reasons.append(f"root access (+{root_pts})")

    # Rule 2 — unlisted process
    process = event.get("process", "")
    if process and process not in whitelist:
        score += process_pts
        reasons.append(f"unlisted process {process} (+{process_pts})")

    # Rule 3 — credential filename
    filename = event.get("file", "").lower()
    if any(kw in filename for kw in CREDENTIAL_KEYWORDS):
        score += cred_pts
        reasons.append(f"credential filename (+{cred_pts})")

    # Rule 4 — after hours (before 7am or after 10pm)
    try:
        hour = datetime.strptime(event["timestamp"], "%Y-%m-%d %H:%M:%S").hour
        if hour < 7 or hour >= 22:
            score += hours_pts
            reasons.append(f"after hours access (+{hours_pts})")
    except Exception:
        pass

    # Cap at 10
    score = min(score, 10)

    # Risk level
    if score >= threshold:
        risk_level = "CRITICAL"
    elif score >= 5:
        risk_level = "HIGH"
    elif score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {**event, "score": score, "risk_level": risk_level, "reasons": reasons}


if __name__ == "__main__":
    # Simulate a root + cat + credentials file event
    test_event = {
        "file": "/home/kali/db_credentials.txt",
        "user": "root",
        "process": "cat",
        "timestamp": "2026-03-11 18:06:55",
        "pid": "12345",
        "score": 0,
        "risk_level": "",
        "reasons": [],
    }
    result = score_event(test_event)
    print(f"Score:     {result['score']}/10")
    print(f"Risk:      {result['risk_level']}")
    print(f"Reasons:   {result['reasons']}")
