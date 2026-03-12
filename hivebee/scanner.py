import os
import subprocess
from pathlib import Path

def _run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""

def scan() -> dict:
    profile = {}

    # OS info
    profile["os"] = _run("lsb_release -ds") or _run("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    profile["kernel"] = _run("uname -r")
    profile["hostname"] = _run("hostname")
    profile["arch"] = _run("uname -m")

    # Users
    users = _run("cat /etc/passwd | grep -E '/home|/root' | cut -d: -f1")
    profile["users"] = [u for u in users.splitlines() if u]

    # Running services
    services = _run("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
    profile["services"] = [s.replace(".service", "") for s in services.splitlines() if s]

    # Installed software (detect common stacks)
    checks = {
        "apache2":  "which apache2",
        "nginx":    "which nginx",
        "mysql":    "which mysql",
        "postgres": "which psql",
        "php":      "which php",
        "python3":  "which python3",
        "node":     "which node",
        "docker":   "which docker",
        "ssh":      "which sshd",
        "ftp":      "which vsftpd",
    }
    profile["software"] = [name for name, cmd in checks.items() if _run(cmd)]

    # Home directories
    home_dirs = list(Path("/home").iterdir()) if Path("/home").exists() else []
    profile["home_dirs"] = [str(d) for d in home_dirs if d.is_dir()]

    # Classify system type
    software = profile["software"]
    if "apache2" in software or "nginx" in software:
        profile["system_type"] = "webserver"
    elif "mysql" in software or "postgres" in software:
        profile["system_type"] = "database"
    elif "docker" in software:
        profile["system_type"] = "container_host"
    elif "ssh" in software:
        profile["system_type"] = "ssh_server"
    else:
        profile["system_type"] = "workstation"

    return profile

if __name__ == "__main__":
    import json
    print(json.dumps(scan(), indent=2))

