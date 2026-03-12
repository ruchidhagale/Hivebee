import json
import os
import random
import time
from datetime import datetime, timedelta
from pathlib import Path
from hivebee import load_config, BASE_DIR

BASELINE_PATH = BASE_DIR / "logs" / "baseline.json"

CONTENT_TEMPLATES = {
    "credentials": """# Database Credentials
host=localhost
port=3306
database=production_db
username=admin
password=Sup3rS3cur3P@ss!
""",
    "env": """DB_HOST=localhost
DB_PORT=5432
DB_NAME=production
DB_USER=postgres
DB_PASS=postgres_prod_2024!
SECRET_KEY=a8f3k2m9x1z7q4w6e5r0t
API_KEY=sk-prod-Xk29mN3pL8qR5tY2wZ
""",
    "sql": """-- Production database backup
-- Generated: 2024-01-15 03:00:01
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(255),
    email VARCHAR(100)
);
INSERT INTO users VALUES (1, 'admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4tbQKgHhKm', 'admin@company.com');
INSERT INTO users VALUES (2, 'root', '$2b$12$XkD9mN3pL8qR5tY2wZaB1eKj7mP4nQ6vR9sT2uW5xY8zA3bC6dE9f', 'root@company.com');
""",
    "ssh_key": """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7n2OHh
backed_up_key_do_not_share_2024
Hk29mN3pL8qR5tY2wZaB1eKj7mP4nQ6vR9sT2uW5xY8zA3bC6dE9fGhIjKlMnOp
-----END RSA PRIVATE KEY-----
""",
    "passwords": """# Internal passwords - DO NOT SHARE
admin portal:     admin / P@ssw0rd2024!
database root:    root / db_r00t_secure
ssh backup:       sysadmin / Ssh@dmin99
vpn access:       vpnuser / VpnS3cur3#
email admin:      mailAdmin / M@il2024
""",
    "config": """[database]
host = 192.168.1.100
port = 5432
name = prod_db
user = db_admin
pass = Pr0dDbP@ss!

[api]
endpoint = https://internal-api.company.local
key = api-prod-Xk29mN3pL8qR5tY2wZ
secret = sec-8f3k2m9x1z7q4w6e5r0t
""",
}

def _pick_content(filename: str) -> str:
    name = filename.lower()
    if any(x in name for x in ["sql", "dump", "backup"]):
        return CONTENT_TEMPLATES["sql"]
    elif any(x in name for x in ["id_rsa", "private", "key"]):
        return CONTENT_TEMPLATES["ssh_key"]
    elif any(x in name for x in ["password", "passwd", "credentials", "creds"]):
        return CONTENT_TEMPLATES["passwords"]
    elif ".env" in name:
        return CONTENT_TEMPLATES["env"]
    elif any(x in name for x in ["config", "conf", "cfg"]):
        return CONTENT_TEMPLATES["config"]
    else:
        return CONTENT_TEMPLATES["credentials"]

def _backdate(path: Path):
    # Make file look old — random date 30-180 days ago
    days_ago = random.randint(30, 180)
    old_time = time.time() - (days_ago * 86400)
    os.utime(path, (old_time, old_time))

def deploy_all(files: list) -> list:
    config = load_config()
    deployed = []

    for f in files:
        path = Path(f["path"])
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            content = _pick_content(f["name"])
            path.write_text(content)
            path.chmod(0o644)
            _backdate(path)
            deployed.append({
                "name": f["name"],
                "path": str(path),
                "deployed_at": datetime.now().isoformat(),
            })
            print(f"  [DEPLOY] {path}")
        except PermissionError:
            print(f"  [SKIP] {path} — permission denied (run as root)")
        except Exception as e:
            print(f"  [ERROR] {path} — {e}")

    # Write baseline
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(json.dumps(deployed, indent=2))
    print(f"\n[DONE] {len(deployed)} honeyfiles deployed → {BASELINE_PATH}")
    return deployed


if __name__ == "__main__":
    from hivebee.scanner import scan
    from hivebee.ai import generate_honeyfiles
    profile = scan()
    files = generate_honeyfiles(profile)
    deploy_all(files)
