# HiveBee IDS 🐝

Deception-based intrusion detection for Linux. Deploys AI-generated honeyfiles and monitors them with auditd.

## Install
```bash
pip install hivebee-ids
```

## Usage
```bash
sudo hivebee          # interactive menu
sudo hivebee install  # scan + deploy honeyfiles
sudo hivebee monitor  # start live monitoring
sudo hivebee status   # system overview
sudo hivebee uninstall # remove all honeyfiles
```

## Requirements

- Linux only
- auditd must be installed (`sudo apt install auditd`)
- Ollama for AI honeyfile generation (optional)

## How it works

1. **Install** — scans your system, generates context-aware honeyfiles using AI, deploys them with realistic content
2. **Monitor** — watches for any access using auditd, scores events 0-10, fires desktop alerts
3. **Dashboard** — live terminal UI showing all activity in real time

## Stack

- Python 3.10+
- rich (terminal UI)
- auditd (kernel-level file monitoring)
- Ollama / Claude API (honeyfile generation)
