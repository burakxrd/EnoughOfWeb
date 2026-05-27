"""
EnoughOfWeb — Global Configuration
All settings with sensible defaults. Agent-friendly: no manual config needed.
"""

import os
import json
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).parent
DATA_DIR = ROOT_DIR / "data"
SAVES_DIR = ROOT_DIR / "saves"
PAYLOADS_DIR = ROOT_DIR / "payloads"
CONFIG_FILE = DATA_DIR / "config.json"

# Ensure dirs exist
DATA_DIR.mkdir(exist_ok=True)
SAVES_DIR.mkdir(exist_ok=True)

# ── Defaults ───────────────────────────────────────────────────────────────
DEFAULTS = {
    # HTTP
    "timeout": 10,
    "threads": 5,
    "max_retries": 3,
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",

    # Proxy (Burp Suite)
    "proxy_enabled": False,
    "proxy_host": "127.0.0.1",
    "proxy_port": 8080,
    "verify_ssl": False,

    # Kali SSH (optional)
    "kali_ssh_enabled": False,
    "kali_ssh_host": "",
    "kali_ssh_port": 22,
    "kali_ssh_user": "kali",
    "kali_ssh_key": "",
    "kali_ssh_password": "",

    # Flag extraction
    "flag_format": r"[A-Za-z0-9_]+\{[^\}]+\}",

    # Bottleneck detection
    "bottleneck_max_retries": 5,
    "bottleneck_max_similar_errors": 3,
    "bottleneck_timeout": 30,

    # Module priority (default order)
    "module_priority": [
        "sqli", "ssti", "cmdi", "lfi", "xss",
        "jwt", "ssrf", "idor", "auth_bypass"
    ],
}


def load_config() -> dict:
    """Load config from file, falling back to defaults."""
    config = DEFAULTS.copy()
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            config.update(saved)
        except (json.JSONDecodeError, IOError):
            pass
    return config


def save_config(config: dict):
    """Persist config to disk."""
    DATA_DIR.mkdir(exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def first_run_setup(non_interactive: bool = False):
    """Interactive first-run setup. Only asks essentials, rest is defaults."""
    if CONFIG_FILE.exists():
        return load_config()

    config = DEFAULTS.copy()
    
    if non_interactive:
        save_config(config)
        return config

    print("\n╔══════════════════════════════════════╗")
    print("║   EnoughOfWeb — First Run Setup      ║")
    print("╚══════════════════════════════════════╝\n")

    # Proxy
    proxy = input("[?] Use Burp Suite proxy? (y/N): ").strip().lower()
    if proxy == "y":
        config["proxy_enabled"] = True
        port = input(f"    Proxy port [{config['proxy_port']}]: ").strip()
        if port:
            config["proxy_port"] = int(port)

    # Kali SSH
    kali = input("[?] Connect to Kali Linux via SSH? (y/N): ").strip().lower()
    if kali == "y":
        config["kali_ssh_enabled"] = True
        config["kali_ssh_host"] = input("    Kali host/IP: ").strip()
        port = input(f"    SSH port [{config['kali_ssh_port']}]: ").strip()
        if port:
            config["kali_ssh_port"] = int(port)
        config["kali_ssh_user"] = input(f"    Username [{config['kali_ssh_user']}]: ").strip() or config["kali_ssh_user"]
        key = input("    SSH key path (empty for password): ").strip()
        if key:
            config["kali_ssh_key"] = key
        else:
            config["kali_ssh_password"] = input("    Password: ").strip()

    # Flag format
    flag = input(f"[?] Custom flag regex? (Enter for default): ").strip()
    if flag:
        config["flag_format"] = flag

    save_config(config)
    print("\n[OK] Config saved. You can change it anytime in data/config.json\n")
    return config
