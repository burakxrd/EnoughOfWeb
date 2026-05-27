"""
EnoughOfWeb — Loot Manager
Manages extracted credentials, hashes, and other sensitive data discovered during exploitation.
Organizes data by target domain/IP to prevent cross-contamination across different targets.
"""

import json
from pathlib import Path
from urllib.parse import urlparse

class LootManager:
    def __init__(self, data_dir: Path = None):
        if data_dir is None:
            # Default to ROOT_DIR/data
            self.data_dir = Path(__file__).parent.parent / "data"
        else:
            self.data_dir = data_dir
            
        self.loot_file = self.data_dir / "loot.json"
        self._cache = self._load()

    def _load(self) -> dict:
        """Load loot DB from disk."""
        if not self.loot_file.exists():
            return {}
        try:
            with open(self.loot_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self):
        """Save loot DB to disk."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with open(self.loot_file, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, indent=4)

    def _get_domain(self, target_url: str) -> str:
        """Extract domain or IP from URL."""
        if not target_url.startswith("http"):
            target_url = "http://" + target_url
        domain = urlparse(target_url).netloc
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain

    def add_credential(self, target_url: str, username: str, password: str, source_module: str = "unknown"):
        """
        Add a discovered credential to the LootDB for a specific target.
        """
        if not username or not password:
            return
            
        domain = self._get_domain(target_url)
        if domain not in self._cache:
            self._cache[domain] = {"credentials": [], "hashes": []}
            
        creds = self._cache[domain]["credentials"]
        
        # Check if already exists
        for c in creds:
            if c["username"] == username and c["password"] == password:
                return
                
        creds.append({
            "username": username,
            "password": password,
            "source": source_module
        })
        self._save()

    def get_credentials(self, target_url: str) -> list:
        """
        Get all credentials for a specific target domain.
        Returns list of dicts: [{'username': '..', 'password': '..', 'source': '..'}, ...]
        """
        domain = self._get_domain(target_url)
        if domain in self._cache:
            return self._cache[domain].get("credentials", [])
        return []
