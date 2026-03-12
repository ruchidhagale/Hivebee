import smtplib
import subprocess
from email.mime.text import MIMEText
from hivebee import load_config

def _desktop_notify(event: dict):
    title = f"HiveBee — {event['risk_level']} Alert"
    body = f"{event['file']}\nUser: {event['user']} | Process: {event['process']} | Score: {event['score']}/10"
    try:
        subprocess.run(
            ["notify-send", "-u", "critical", title, body],
            check=False, capture_output=True
        )
    except FileNotFoundError:
        pass  # notify-send not available, skip silently

def _email_notify(event: dict, email_cfg: dict):
    try:
        subject = f"[HiveBee] {event['risk_level']} — {event['file']}"
        body = (
            f"HiveBee IDS Alert\n"
            f"{'='*40}\n"
            f"Risk Level : {event['risk_level']}\n"
            f"Score      : {event['score']}/10\n"
            f"File       : {event['file']}\n"
            f"User       : {event['user']}\n"
            f"Process    : {event['process']}\n"
            f"Timestamp  : {event['timestamp']}\n"
            f"Reasons    : {', '.join(event.get('reasons', []))}\n"
        )

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = email_cfg["from"]
        msg["To"] = email_cfg["to"]

        with smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"]) as server:
            server.starttls()
            server.login(email_cfg["from"], email_cfg["password"])
            server.send_message(msg)
    except Exception as e:
        from hivebee.logger import log_debug
        log_debug(f"[ALERTER] Email failed: {e}")

def alert(event: dict):
    config = load_config()
    alerts_cfg = config.get("alerts", {})

    # Check if event meets notify threshold
    levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    notify_on = alerts_cfg.get("notify_on", "HIGH")
    event_level = event.get("risk_level", "LOW")

    if levels.index(event_level) < levels.index(notify_on):
        return  # below threshold, skip

    # Desktop notification
    if alerts_cfg.get("desktop", True):
        _desktop_notify(event)

    # Email notification
    email_cfg = alerts_cfg.get("email", {})
    if email_cfg.get("enabled", False):
        _email_notify(event, email_cfg)


if __name__ == "__main__":
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
    alert(test_event)
    print("[ALERTER] Alert fired — check for desktop notification")
