import json
import urllib.request as _req
from hivebee import load_config

FALLBACK_TEMPLATES = {
    "webserver": [
        {"name": "db_credentials.txt", "path": "/var/www/html/db_credentials.txt"},
        {"name": "wp-config.php.bak", "path": "/var/www/html/wp-config.php.bak"},
        {"name": ".env", "path": "/var/www/html/.env"},
        {"name": "admin_passwords.txt", "path": "/var/www/html/admin_passwords.txt"},
    ],
    "database": [
        {"name": "db_dump.sql", "path": "/root/db_dump.sql"},
        {"name": "mysql_credentials.txt", "path": "/root/mysql_credentials.txt"},
        {"name": "backup.sql", "path": "/tmp/backup.sql"},
    ],
    "ssh_server": [
        {"name": "authorized_keys.bak", "path": "/root/.ssh/authorized_keys.bak"},
        {"name": "id_rsa_backup", "path": "/root/.ssh/id_rsa_backup"},
        {"name": "ssh_passwords.txt", "path": "/etc/ssh/ssh_passwords.txt"},
    ],
    "workstation": [
        {"name": "passwords.txt", "path": "/home/kali/passwords.txt"},
        {"name": "credentials.csv", "path": "/home/kali/credentials.csv"},
        {"name": "private_keys.txt", "path": "/home/kali/private_keys.txt"},
        {"name": "bank_details.txt", "path": "/home/kali/Documents/bank_details.txt"},
    ],
    "container_host": [
        {"name": "docker-compose.override.yml", "path": "/root/docker-compose.override.yml"},
        {"name": ".docker_credentials", "path": "/root/.docker_credentials"},
        {"name": "registry_password.txt", "path": "/root/registry_password.txt"},
    ],
}

def generate_honeyfiles(profile: dict) -> list:
    config = load_config()
    ai_cfg = config.get("ai", {})
    system_type = profile.get("system_type", "workstation")

    if not ai_cfg.get("enabled", True):
        return FALLBACK_TEMPLATES.get(system_type, FALLBACK_TEMPLATES["workstation"])

    prompt = f"""You are a cybersecurity expert setting up honeypot files for a deception-based IDS.

System profile:
- OS: {profile.get('os')}
- System type: {system_type}
- Software detected: {', '.join(profile.get('software', []))}
- Users: {', '.join(profile.get('users', []))}

Generate 6 realistic honeyfiles that an attacker would find irresistible on this system.
Return ONLY a JSON array, no explanation, no markdown. Each item must have:
- "name": filename only
- "path": full absolute path where it should be placed

Example:
[{{"name": "db_credentials.txt", "path": "/var/www/html/db_credentials.txt"}}]"""

    try:
        payload = json.dumps({
            "model": "llama3.2",
            "prompt": prompt,
            "stream": False
        }).encode()

        request = _req.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with _req.urlopen(request, timeout=100) as resp:
            result = json.loads(resp.read())
            text = result["response"].strip()

            # Strip markdown fences
            if "```" in text:
                parts = text.split("```")
                for part in parts:
                    part = part.strip()
                    if part.startswith("json"):
                        part = part[4:].strip()
                    if part.startswith("["):
                        text = part
                        break

            # Find JSON array anywhere in the response
            start = text.find("[")
            end = text.rfind("]")
            if start == -1 or end == -1:
                raise ValueError("No JSON array found in response")
            text = text[start:end+1]

            parsed = json.loads(text)

            # Validate every item is a dict with name and path
            honeyfiles = []
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                name = item.get("name", "").strip()
                path = item.get("path", "").strip()
                if name and path and path.startswith("/"):
                    honeyfiles.append({"name": name, "path": path})

            if not honeyfiles:
                raise ValueError("No valid honeyfiles parsed from response")

            return honeyfiles

    except Exception as e:
        print(f"[AI] Ollama call failed ({e}) — using fallback templates")
        return FALLBACK_TEMPLATES.get(system_type, FALLBACK_TEMPLATES["workstation"])


if __name__ == "__main__":
    from hivebee.scanner import scan
    profile = scan()
    print(f"[AI] System type: {profile['system_type']}")
    files = generate_honeyfiles(profile)
    print(json.dumps(files, indent=2))
