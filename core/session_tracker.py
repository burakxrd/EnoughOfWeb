"""
EnoughOfWeb — Session Tracker
Tracks scan sessions, records module execution order, and detects agent overrides
by comparing recommended strategy order vs actual execution order.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any


@dataclass
class ModuleRecord:
    """Record of a single module execution within a session."""
    module: str
    status: str = "pending"        # "pending" | "running" | "completed" | "skipped"
    result: str = ""               # "flag_found" | "findings" | "no_findings" | "error"
    source: str = "autonomous"     # "autonomous" | "agent_override" | "agent_retry"
    started_at: str = ""
    completed_at: str = ""
    findings_count: int = 0
    flag: str = ""


@dataclass
class SessionState:
    """Full state of a scan session."""
    session_id: str = ""
    target_url: str = ""
    domain: str = ""
    created_at: str = ""
    updated_at: str = ""

    # Recon state
    recon_done: bool = False
    recon_data_snapshot: Dict[str, Any] = field(default_factory=dict)

    # Strategy
    recommended_order: List[str] = field(default_factory=list)

    # Execution tracking
    actual_order: List[str] = field(default_factory=list)
    modules_run: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Override tracking
    overrides_detected: int = 0

    # Status
    status: str = "active"         # "active" | "completed" | "aborted"
    flags_found: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.session_id:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.session_id = f"{ts}_{uuid.uuid4().hex[:6]}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = datetime.now(timezone.utc).isoformat()


class SessionTracker:
    """
    Manages scan sessions and detects agent overrides.

    A session is created when recon starts and tracks:
    - What the strategy engine recommended
    - What was actually executed
    - Which modules were agent overrides

    Override detection works by comparing recommended_order (from strategy)
    with actual execution order. If agent skips ahead or chooses a different
    module, it's logged as an override.
    """

    def __init__(self, saves_dir: Optional[Path] = None):
        if saves_dir is None:
            saves_dir = Path(__file__).parent.parent / "saves"
        self.saves_dir = Path(saves_dir)
        self.saves_dir.mkdir(parents=True, exist_ok=True)
        self._active_sessions: Dict[str, SessionState] = {}

    # ── Session Lifecycle ──────────────────────────────────────────────────

    def create_session(self, target_url: str) -> str:
        """
        Create a new session for a target.

        Returns:
            session_id string
        """
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        domain = parsed.netloc.replace(":", "_").replace(".", "_") or "unknown"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        state = SessionState(
            session_id=f"{ts}_{domain}",
            target_url=target_url,
            domain=parsed.netloc,
        )

        # Create session directory
        session_dir = self.saves_dir / state.session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        self._active_sessions[state.session_id] = state
        self._save_state(state)

        return state.session_id

    def load_session(self, session_id: str) -> Optional[SessionState]:
        """Load a session by ID."""
        # Check memory cache
        if session_id in self._active_sessions:
            return self._active_sessions[session_id]

        # Load from disk
        state_file = self.saves_dir / session_id / "session_state.json"
        if not state_file.exists():
            return None

        try:
            with open(state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            state = SessionState(**{
                k: v for k, v in data.items()
                if k in SessionState.__dataclass_fields__
            })
            self._active_sessions[session_id] = state
            return state
        except (json.JSONDecodeError, IOError, TypeError):
            return None

    def get_or_create(self, target_url: str, session_id: Optional[str] = None) -> str:
        """Load existing session or create new one."""
        if session_id:
            state = self.load_session(session_id)
            if state:
                return session_id

        return self.create_session(target_url)

    # ── Recording ──────────────────────────────────────────────────────────

    def record_recon(
        self,
        session_id: str,
        recon_data: dict,
        recommended_order: List[str],
    ):
        """Record recon completion and strategy recommendation."""
        state = self.load_session(session_id)
        if not state:
            return

        state.recon_done = True
        state.recommended_order = list(recommended_order)

        # Store minimal recon snapshot for context
        tech = recon_data.get("technology", {})
        state.recon_data_snapshot = {
            "tech": tech,
            "form_count": len(recon_data.get("forms", [])),
            "param_count": len(recon_data.get("parameters", [])),
            "cookie_count": len(recon_data.get("cookies", {})),
            "paths_found": list(recon_data.get("interesting_paths", {}).keys())
                           if isinstance(recon_data.get("interesting_paths"), dict)
                           else recon_data.get("interesting_paths", []),
        }

        self._save_state(state)

    def record_attack(
        self,
        session_id: str,
        module_name: str,
        result: str = "",
        findings_count: int = 0,
        flag: str = "",
    ):
        """
        Record a module execution. Automatically detects if this is an override.

        Args:
            session_id: Active session ID
            module_name: Module being run
            result: "flag_found" | "findings" | "no_findings" | "error"
            findings_count: Number of findings
            flag: Flag string if found
        """
        state = self.load_session(session_id)
        if not state:
            return "autonomous"

        # Detect override
        source = self.detect_override(session_id, module_name)

        # Record
        state.actual_order.append(module_name)

        record = ModuleRecord(
            module=module_name,
            status="completed",
            result=result,
            source=source,
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
            findings_count=findings_count,
            flag=flag,
        )
        state.modules_run[module_name] = asdict(record)

        if source == "agent_override":
            state.overrides_detected += 1

        if flag:
            state.flags_found.append(flag)

        self._save_state(state)
        return source

    # ── Override Detection ─────────────────────────────────────────────────

    def detect_override(self, session_id: str, module_name: str) -> str:
        """
        Detect if running this module constitutes an agent override.

        Logic:
        - If no recommended_order set yet → autonomous (recon not done)
        - If module is the next expected in recommended_order → autonomous
        - If module skips ahead or deviates from recommended → agent_override
        - If module was already run and is being retried → agent_retry

        Returns:
            "autonomous" | "agent_override" | "agent_retry"
        """
        state = self.load_session(session_id)
        if not state:
            return "autonomous"

        # No recommendation yet = can't detect override
        if not state.recommended_order:
            return "autonomous"

        # Already run this module = retry
        if module_name in state.actual_order:
            return "agent_retry"

        # What's the next expected module?
        expected_next = self._get_next_expected(state)

        if expected_next is None:
            # All recommended modules done, agent is trying extras
            return "agent_override"

        if module_name == expected_next:
            return "autonomous"

        # Module doesn't match expected → override
        return "agent_override"

    def _get_next_expected(self, state: SessionState) -> Optional[str]:
        """Get the next module the strategy engine would recommend."""
        already_run = set(state.actual_order)
        for mod in state.recommended_order:
            if mod not in already_run:
                return mod
        return None

    def get_recommended_order(self, session_id: str) -> List[str]:
        """Get the strategy-recommended module order for a session."""
        state = self.load_session(session_id)
        if not state:
            return []
        return list(state.recommended_order)

    # ── Session Completion ─────────────────────────────────────────────────

    def complete_session(self, session_id: str):
        """Mark a session as completed."""
        state = self.load_session(session_id)
        if state:
            state.status = "completed"
            state.updated_at = datetime.now(timezone.utc).isoformat()
            self._save_state(state)

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get a summary of a session for reporting."""
        state = self.load_session(session_id)
        if not state:
            return {"session_id": session_id, "found": False}

        return {
            "session_id": state.session_id,
            "found": True,
            "target_url": state.target_url,
            "status": state.status,
            "recon_done": state.recon_done,
            "recommended_order": state.recommended_order,
            "actual_order": state.actual_order,
            "modules_run": len(state.modules_run),
            "overrides_detected": state.overrides_detected,
            "flags_found": state.flags_found,
            "created_at": state.created_at,
        }

    # ── Listing ────────────────────────────────────────────────────────────

    def list_sessions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent sessions."""
        sessions = []
        if not self.saves_dir.exists():
            return sessions

        dirs = sorted(self.saves_dir.iterdir(), reverse=True)
        for d in dirs[:limit]:
            if not d.is_dir():
                continue
            state_file = d / "session_state.json"
            if state_file.exists():
                try:
                    with open(state_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    sessions.append({
                        "session_id": data.get("session_id", d.name),
                        "target_url": data.get("target_url", ""),
                        "status": data.get("status", "unknown"),
                        "flags": data.get("flags_found", []),
                        "overrides": data.get("overrides_detected", 0),
                        "created_at": data.get("created_at", ""),
                    })
                except (json.JSONDecodeError, IOError):
                    sessions.append({"session_id": d.name, "status": "corrupt"})
            else:
                sessions.append({"session_id": d.name, "status": "no_state"})

        return sessions

    # ── Persistence ────────────────────────────────────────────────────────

    def _save_state(self, state: SessionState):
        """Save session state to disk."""
        state.updated_at = datetime.now(timezone.utc).isoformat()
        session_dir = self.saves_dir / state.session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        state_file = session_dir / "session_state.json"
        try:
            with open(state_file, "w", encoding="utf-8") as f:
                json.dump(asdict(state), f, indent=2, ensure_ascii=False, default=str)
        except IOError:
            pass

    def get_session_dir(self, session_id: str) -> Path:
        """Get the directory path for a session."""
        return self.saves_dir / session_id
