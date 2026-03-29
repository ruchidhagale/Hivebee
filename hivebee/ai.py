import json
import urllib.request as _req
from hivebee import load_config

FALLBACK_TEMPLATES = {
    "webserver": [
        {"name": "db_credentials.txt", "path": "/var/www/html/db_credentials.txt"},
        {"name": "wp-config.php.bak",  "path": "/var/www/html/wp-config.php.bak"},
        {"name": ".env",               "path": "/var/www/html/.env"},
        {"name": "admin_passwords.txt","path": "/var/www/html/admin_passwords.txt"},
    ],
    "database": [
        {"name": "db_dump.sql",         "path": "/root/db_dump.sql"},
        {"name": "mysql_credentials.txt","path": "/root/mysql_credentials.txt"},
        {"name": "backup.sql",          "path": "/tmp/backup.sql"},
    ],
    "ssh_server": [
        {"name": "authorized_keys.bak", "path": "/root/.ssh/authorized_keys.bak"},
        {"name": "id_rsa_backup",       "path": "/root/.ssh/id_rsa_backup"},
    ],
    "workstation": [
        {"name": "passwords.txt",       "path": "/home/kali/passwords.txt"},
        {"name": "credentials.csv",     "path": "/home/kali/credentials.csv"},
        {"name": "bank_details.txt",    "path": "/home/kali/Documents/bank_details.txt"},
    ],
    "container_host": [
        {"name": "docker-compose.override.yml","path": "/root/docker-compose.override.yml"},
        {"name": ".docker_credentials",        "path": "/root/.docker_credentials"},
    ],
}

def generate_honeyfiles(profile: dict) -> list:
    config     = load_config()
    ai_cfg     = config.get("ai", {})
    system_type = profile.get("system_type", "workstation")
    count      = 4

    if not ai_cfg.get("enabled", True):
        return FALLBACK_TEMPLATES.get(system_type, FALLBACK_TEMPLATES["workstation"])

    prompt = f"""You are a sysadmin documenting config files on a {system_type} Linux server.
List {count} realistic config or credential files that would exist on this server.
Respond ONLY with a JSON array. No explanation, no markdown, no extra text.
Use exactly this format:
[
  {{"name": "db_config.ini", "path": "/etc/myapp/db_config.ini"}},
  {{"name": "smtp_pass.txt", "path": "/root/smtp_pass.txt"}}
]"""

    try:
        model = ai_cfg.get("model", "llama3.2")
        base_url = ai_cfg.get("base_url", "http://localhost:11434").rstrip("/")

        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False
        }).encode()

        request = _req.Request(
            f"{base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"}
        )

        with _req.urlopen(request, timeout=120) as resp:
            result = json.loads(resp.read())
            text   = result["response"].strip()

        # Strip markdown fences if present
        if "```" in text:
            for part in text.split("```"):
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("["):
                    text = part
                    break

        # Extract JSON array
        start = text.find("[")
        end   = text.rfind("]")
        if start == -1 or end == -1:
            raise ValueError("No JSON array found in response")
        text = text[start:end+1]

        parsed = json.loads(text)

        honeyfiles = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            name = item.get("name", "").strip()
            path = item.get("path", "").strip()
            if name and path and path.startswith("/"):
                honeyfiles.append({"name": name, "path": path})

        if not honeyfiles:
            raise ValueError("No valid honeyfiles parsed")

        print(f"  [AI] {len(honeyfiles)} honeyfiles generated for {system_type}")
        return honeyfiles

    except Exception as e:
        print(f"  [AI] Ollama failed ({e}) — using fallback templates")
        return FALLBACK_TEMPLATES.get(system_type, FALLBACK_TEMPLATES["workstation"])


if __name__ == "__main__":
    from hivebee.scanner import scan
    profile = scan()
    print(f"[AI] System type: {profile['system_type']}")
    files = generate_honeyfiles(profile)
    print(json.dumps(files, indent=2))
