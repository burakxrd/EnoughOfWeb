"""
EnoughOfWeb — Adaptive Learner (v2)
Context-aware experience database. Logs every attempt with full target context,
session tracking, and source detection (autonomous vs agent_override).
"""

import json
import uuid
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from collections import Counter


# ── Data Structures ────────────────────────────────────────────────────────

@dataclass
class TargetContext:
    """Snapshot of what we know about the target at scan time."""
    url: str = ""
    domain: str = ""
    tech: List[str] = field(default_factory=list)          # ["php", "apache"]
    has_login_form: bool = False
    has_upload_form: bool = False
    has_file_param: bool = False
    has_id_param: bool = False
    has_url_param: bool = False
    has_cmd_param: bool = False
    cookies: List[str] = field(default_factory=list)        # cookie names
    interesting_paths: List[str] = field(default_factory=list)
    param_names: List[str] = field(default_factory=list)

    @classmethod
    def from_recon(cls, target_url: str, recon_data: dict) -> "TargetContext":
        """Build context from recon output."""
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        domain = parsed.netloc

        # Extract tech
        tech = []
        tech_info = recon_data.get("technology", {})
        server = (tech_info.get("server", "") or "").lower()
        powered = (tech_info.get("x_powered_by", "") or "").lower()

        if "php" in powered or "php" in server:
            tech.append("php")
        if "asp" in powered or "asp" in server:
            tech.append("asp")
        if any(kw in server for kw in ("werkzeug", "flask")):
            tech.extend(["flask", "python"])
        if "express" in powered or "express" in server:
            tech.extend(["express", "node"])
        if "django" in server or "django" in powered:
            tech.extend(["django", "python"])
        if "tornado" in server:
            tech.extend(["tornado", "python"])
        if "apache" in server:
            tech.append("apache")
        if "nginx" in server:
            tech.append("nginx")

        for fw in tech_info.get("frameworks", []):
            fw_l = fw.lower()
            if "jinja" in fw_l:
                tech.append("jinja2")
            if "flask" in fw_l and "flask" not in tech:
                tech.append("flask")

        # Extract form signals
        has_login = False
        has_upload = False
        param_names = []
        password_fields = {"password", "pass", "passwd", "pwd"}

        for form in recon_data.get("forms", []):
            inputs = form.get("inputs", {})
            if isinstance(inputs, dict):
                input_keys = set(k.lower() for k in inputs.keys())
                param_names.extend(inputs.keys())
            elif isinstance(inputs, list):
                input_keys = set(inp.get("name", "").lower() for inp in inputs)
                param_names.extend(inp.get("name", "") for inp in inputs if inp.get("name"))
            else:
                input_keys = set()

            if input_keys & password_fields:
                has_login = True
            if "file" in input_keys or any(
                (inp.get("type", "") if isinstance(inp, dict) else "").lower() == "file"
                for inp in (inputs if isinstance(inputs, list) else [])
            ):
                has_upload = True

        # Extract URL param signals
        url_params = recon_data.get("url_params", [])
        if isinstance(url_params, list):
            param_names.extend(url_params)

        # Also from parameters list
        for p in recon_data.get("parameters", []):
            name = p.get("name", "") if isinstance(p, dict) else str(p)
            if name:
                param_names.append(name)

        param_lower = set(n.lower() for n in param_names)

        has_file_param = bool(param_lower & {"file", "path", "page", "include", "doc", "template", "lang"})
        has_id_param = bool(param_lower & {"id", "uid", "user_id", "item_id", "order_id"})
        has_url_param = bool(param_lower & {"url", "uri", "redirect", "next", "goto", "link", "src"})
        has_cmd_param = bool(param_lower & {"cmd", "command", "exec", "run", "ping", "ip"})

        # Cookies
        cookies = list(recon_data.get("cookies", {}).keys())

        # Interesting paths
        paths_data = recon_data.get("interesting_paths", {})
        if isinstance(paths_data, dict):
            interesting = [k for k, v in paths_data.items() if v]
        elif isinstance(paths_data, list):
            interesting = paths_data
        else:
            interesting = []

        return cls(
            url=target_url,
            domain=domain,
            tech=list(set(tech)),
            has_login_form=has_login,
            has_upload_form=has_upload,
            has_file_param=has_file_param,
            has_id_param=has_id_param,
            has_url_param=has_url_param,
            has_cmd_param=has_cmd_param,
            cookies=cookies,
            interesting_paths=interesting,
            param_names=list(set(param_names)),
        )


@dataclass
class ExploitAttempt:
    """Record of a single exploit attempt with full context."""
    # Identity
    id: str = ""
    timestamp: str = ""
    session_id: str = ""

    # Target context
    target_context: Dict[str, Any] = field(default_factory=dict)

    # Action
    module: str = ""                     # "sqli", "ssti", etc.
    technique: str = ""                  # "union-based", "jinja2_rce", etc.
    payload: str = ""
    parameter: str = ""
    method: str = ""                     # GET / POST

    # Result
    success: bool = False
    flag_found: bool = False
    flag: str = ""
    response_code: int = 0
    response_length: int = 0
    error: str = ""
    duration_ms: float = 0.0

    # Source tracking
    source: str = "autonomous"           # "autonomous" | "agent_override" | "agent_retry"
    sequence_position: int = 0           # Nth module in this session
    previous_module: str = ""
    previous_result: str = ""            # "success" | "fail" | "no_findings" | ""

    # Legacy compat
    challenge_url: str = ""
    vulnerability_type: str = ""
    detection_time_ms: float = 0.0
    error_message: str = ""
    notes: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = uuid.uuid4().hex[:12]
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

        # Legacy field mapping
        if self.vulnerability_type and not self.module:
            self.module = self.vulnerability_type
        if self.error_message and not self.error:
            self.error = self.error_message
        if self.detection_time_ms and not self.duration_ms:
            self.duration_ms = self.detection_time_ms
        if self.challenge_url and not self.target_context:
            self.target_context = {"url": self.challenge_url}


class AdaptiveLearner:
    """
    Context-aware experience database.
    Logs every exploit attempt with target context, session info, and source tracking.
    Persists to data/experience.json.
    """

    DB_VERSION = 2

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            data_dir = Path(__file__).parent.parent / "data"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.db_file = self.data_dir / "experience.json"
        self.legacy_file = self.data_dir / "learning_log.json"

        self._cache: Optional[List[dict]] = None
        self._dirty = False

    # ── File I/O ───────────────────────────────────────────────────────────

    def _load(self) -> List[dict]:
        """Load entries from disk, auto-migrating legacy format."""
        if self._cache is not None:
            return self._cache

        # Try v2 first
        if self.db_file.exists():
            try:
                with open(self.db_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and data.get("version") == self.DB_VERSION:
                    self._cache = data.get("entries", [])
                elif isinstance(data, list):
                    # Old format without version wrapper
                    self._cache = data
                else:
                    self._cache = []
            except (json.JSONDecodeError, IOError):
                self._cache = []
            return self._cache

        # Try legacy file and migrate
        if self.legacy_file.exists():
            try:
                with open(self.legacy_file, "r", encoding="utf-8") as f:
                    legacy = json.load(f)
                if isinstance(legacy, list):
                    self._cache = [self._migrate_v1_entry(e) for e in legacy]
                    self._dirty = True
                    self._save()
                else:
                    self._cache = []
            except (json.JSONDecodeError, IOError):
                self._cache = []
            return self._cache

        self._cache = []
        return self._cache

    def _migrate_v1_entry(self, entry: dict) -> dict:
        """Migrate a v1 learning_log entry to v2 format."""
        return {
            "id": uuid.uuid4().hex[:12],
            "timestamp": entry.get("timestamp", ""),
            "session_id": "",
            "target_context": {"url": entry.get("challenge_url", "")},
            "module": entry.get("vulnerability_type", ""),
            "technique": entry.get("technique", ""),
            "payload": entry.get("payload", ""),
            "parameter": "",
            "method": "",
            "success": entry.get("success", False),
            "flag_found": entry.get("flag_found", False),
            "flag": "",
            "response_code": entry.get("response_code", 0),
            "response_length": entry.get("response_length", 0),
            "error": entry.get("error_message", ""),
            "duration_ms": entry.get("detection_time_ms", 0.0),
            "source": "autonomous",
            "sequence_position": 0,
            "previous_module": "",
            "previous_result": "",
        }

    def _save(self):
        """Persist to disk in v2 format."""
        entries = self._load()
        doc = {
            "version": self.DB_VERSION,
            "entry_count": len(entries),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "entries": entries,
        }
        try:
            with open(self.db_file, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2, ensure_ascii=False, default=str)
            self._dirty = False
        except IOError:
            pass

    def flush(self):
        """Force write pending changes."""
        if self._dirty:
            self._save()

    # ── Logging ────────────────────────────────────────────────────────────

    def log_attempt(self, attempt: "ExploitAttempt"):
        """Log a single exploit attempt."""
        entries = self._load()
        entry = asdict(attempt)
        entries.append(entry)
        self._dirty = True
        self._save()

    def log_with_context(
        self,
        module: str,
        technique: str,
        success: bool,
        session_id: str = "",
        target_context: Optional[Dict] = None,
        source: str = "autonomous",
        sequence_position: int = 0,
        previous_module: str = "",
        previous_result: str = "",
        payload: str = "",
        parameter: str = "",
        method: str = "",
        flag: str = "",
        response_code: int = 0,
        response_length: int = 0,
        error: str = "",
        duration_ms: float = 0.0,
    ):
        """Log with full context — primary API for v2."""
        attempt = ExploitAttempt(
            session_id=session_id,
            target_context=target_context or {},
            module=module,
            technique=technique,
            success=success,
            flag_found=bool(flag),
            flag=flag,
            source=source,
            sequence_position=sequence_position,
            previous_module=previous_module,
            previous_result=previous_result,
            payload=payload,
            parameter=parameter,
            method=method,
            response_code=response_code,
            response_length=response_length,
            error=error,
            duration_ms=duration_ms,
        )
        self.log_attempt(attempt)

    # ── Query API ──────────────────────────────────────────────────────────

    def get_all_entries(self) -> List[dict]:
        """Return all entries."""
        return list(self._load())

    def get_entries_by_module(self, module: str) -> List[dict]:
        """Entries for a specific module."""
        return [e for e in self._load() if e.get("module") == module]

    def get_entries_by_session(self, session_id: str) -> List[dict]:
        """Entries for a specific session."""
        return [e for e in self._load() if e.get("session_id") == session_id]

    def get_entries_by_context(
        self,
        tech: Optional[str] = None,
        has_login: Optional[bool] = None,
        has_file_param: Optional[bool] = None,
        has_id_param: Optional[bool] = None,
        domain: Optional[str] = None,
    ) -> List[dict]:
        """Filter entries by target context fields."""
        results = self._load()

        if tech:
            results = [
                e for e in results
                if tech.lower() in [t.lower() for t in e.get("target_context", {}).get("tech", [])]
            ]
        if has_login is not None:
            results = [
                e for e in results
                if e.get("target_context", {}).get("has_login_form") == has_login
            ]
        if has_file_param is not None:
            results = [
                e for e in results
                if e.get("target_context", {}).get("has_file_param") == has_file_param
            ]
        if has_id_param is not None:
            results = [
                e for e in results
                if e.get("target_context", {}).get("has_id_param") == has_id_param
            ]
        if domain:
            results = [
                e for e in results
                if e.get("target_context", {}).get("domain", "") == domain
            ]

        return results

    # ── Analytics ──────────────────────────────────────────────────────────

    def get_success_rate(self, module: str) -> float:
        """Success rate (0.0–1.0) for a module."""
        entries = self.get_entries_by_module(module)
        if not entries:
            return 0.0
        return sum(1 for e in entries if e.get("success")) / len(entries)

    def get_context_success_rate(self, module: str, tech: str) -> Tuple[float, int]:
        """Success rate for a module on a specific tech stack. Returns (rate, sample_size)."""
        entries = self.get_entries_by_context(tech=tech)
        module_entries = [e for e in entries if e.get("module") == module]
        if not module_entries:
            return 0.0, 0
        successes = sum(1 for e in module_entries if e.get("success"))
        return successes / len(module_entries), len(module_entries)

    def get_best_techniques(self, module: str, top_n: int = 5) -> List[Dict[str, Any]]:
        """Top techniques by success rate for a module."""
        entries = self.get_entries_by_module(module)
        if not entries:
            return []

        stats: Dict[str, Dict[str, int]] = {}
        for e in entries:
            tech = e.get("technique", "unknown") or "unknown"
            if tech not in stats:
                stats[tech] = {"successes": 0, "attempts": 0}
            stats[tech]["attempts"] += 1
            if e.get("success"):
                stats[tech]["successes"] += 1

        results = []
        for tech, s in stats.items():
            rate = s["successes"] / s["attempts"] if s["attempts"] else 0
            results.append({
                "technique": tech,
                "successes": s["successes"],
                "attempts": s["attempts"],
                "success_rate": round(rate, 4),
            })

        results.sort(key=lambda x: (-x["success_rate"], -x["attempts"]))
        return results[:top_n]

    def get_common_failures(self, module: str, top_n: int = 5) -> List[Dict[str, Any]]:
        """Most common error messages for a module."""
        entries = self.get_entries_by_module(module)
        failed = [e for e in entries if not e.get("success") and e.get("error")]
        if not failed:
            return []
        counter = Counter(e["error"] for e in failed)
        return [{"error_message": msg, "count": cnt} for msg, cnt in counter.most_common(top_n)]

    def get_override_stats(self) -> Dict[str, Any]:
        """Statistics about agent overrides."""
        entries = self._load()
        overrides = [e for e in entries if e.get("source") == "agent_override"]
        autonomous = [e for e in entries if e.get("source") == "autonomous"]

        override_successes = sum(1 for e in overrides if e.get("success"))
        auto_successes = sum(1 for e in autonomous if e.get("success"))

        # Which modules do agents override TO?
        override_modules = Counter(e.get("module", "") for e in overrides)

        return {
            "total_overrides": len(overrides),
            "override_success_rate": (override_successes / len(overrides)) if overrides else 0,
            "autonomous_success_rate": (auto_successes / len(autonomous)) if autonomous else 0,
            "top_override_modules": override_modules.most_common(5),
            "total_entries": len(entries),
        }

    def get_total_stats(self) -> Dict[str, Any]:
        """Global statistics across all modules."""
        entries = self._load()
        total = len(entries)
        successes = sum(1 for e in entries if e.get("success"))
        flags = sum(1 for e in entries if e.get("flag_found"))

        by_module: Dict[str, Dict[str, int]] = {}
        for e in entries:
            mod = e.get("module") or e.get("vulnerability_type") or "unknown"
            if mod not in by_module:
                by_module[mod] = {"attempts": 0, "successes": 0, "flags": 0}
            by_module[mod]["attempts"] += 1
            if e.get("success"):
                by_module[mod]["successes"] += 1
            if e.get("flag_found"):
                by_module[mod]["flags"] += 1

        by_vuln_type = {}
        for mod, stats in by_module.items():
            rate = stats["successes"] / stats["attempts"] if stats["attempts"] else 0
            by_vuln_type[mod] = {
                "attempts": stats["attempts"],
                "successes": stats["successes"],
                "flags": stats["flags"],
                "success_rate": round(rate, 4),
            }

        return {
            "total_attempts": total,
            "total_successes": successes,
            "total_flags": flags,
            "overall_success_rate": round(successes / total, 4) if total else 0.0,
            "by_vuln_type": by_vuln_type,
            "override_stats": self.get_override_stats(),
        }

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Summary for a specific session."""
        entries = self.get_entries_by_session(session_id)
        if not entries:
            return {"session_id": session_id, "found": False}

        return {
            "session_id": session_id,
            "found": True,
            "modules_run": list(set(e.get("module", "") for e in entries)),
            "total_attempts": len(entries),
            "successes": sum(1 for e in entries if e.get("success")),
            "flags": [e.get("flag") for e in entries if e.get("flag")],
            "overrides": sum(1 for e in entries if e.get("source") == "agent_override"),
        }

    def clear(self):
        """Clear all entries."""
        self._cache = []
        self._dirty = True
        self._save()

    def distill_knowledge(self, keep_last: int = 100):
        """
        Safe Knowledge Distillation.
        Compresses old logs into mathematical weights (knowledge_distilled.json)
        and preserves rare anomalies (anomalies.json) to prevent catastrophic forgetting.
        """
        import os
        
        entries = self._load()
        if len(entries) <= keep_last:
            return  # Nothing to distill

        # Sort entries by timestamp (oldest first)
        entries.sort(key=lambda x: x.get("timestamp", ""))
        
        old_entries = entries[:-keep_last]
        kept_entries = entries[-keep_last:]
        
        distilled_file = self.data_dir / "knowledge_distilled.json"
        anomalies_file = self.data_dir / "anomalies.json"
        
        # Load existing distilled and anomalies
        distilled_data = {}
        if distilled_file.exists():
            try:
                with open(distilled_file, "r", encoding="utf-8") as f:
                    distilled_data = json.load(f)
            except Exception:
                pass
                
        anomalies_data = []
        if anomalies_file.exists():
            try:
                with open(anomalies_file, "r", encoding="utf-8") as f:
                    anomalies_data = json.load(f)
            except Exception:
                pass

        # Distill old entries
        for e in old_entries:
            mod = e.get("module", "unknown")
            techs = e.get("target_context", {}).get("tech", [])
            tech_key = "-".join(sorted(techs)) if techs else "none"
            success = e.get("success", False)
            flag_found = e.get("flag_found", False)
            
            key = f"{mod}_{tech_key}"
            if key not in distilled_data:
                distilled_data[key] = {"attempts": 0, "successes": 0, "flags": 0, "success_rate": 0.0}
            
            dist_stats = distilled_data[key]
            dist_stats["attempts"] += 1
            if success:
                dist_stats["successes"] += 1
            if flag_found:
                dist_stats["flags"] += 1
                
            dist_stats["success_rate"] = dist_stats["successes"] / dist_stats["attempts"]
            
            # Anomaly Detection
            # If it found a flag OR (it succeeded when the general success rate for this key is < 5%)
            is_anomaly = False
            if flag_found:
                is_anomaly = True
            elif success and dist_stats["success_rate"] < 0.05 and dist_stats["attempts"] > 10:
                is_anomaly = True
                
            if is_anomaly:
                anomalies_data.append(e)

        # Save distilled data
        with open(distilled_file, "w", encoding="utf-8") as f:
            json.dump(distilled_data, f, indent=2)
            
        # Save anomalies
        with open(anomalies_file, "w", encoding="utf-8") as f:
            json.dump(anomalies_data, f, indent=2)
            
        # Update current experience
        self._cache = kept_entries
        self._dirty = True
        self._save()
        print(f"[*] Knowledge Distillation: Compressed {len(old_entries)} old logs. Kept {keep_last} logs.")
