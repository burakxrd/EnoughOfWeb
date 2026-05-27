"""
EnoughOfWeb — Bottleneck Detector
Detects when the tool is stuck in a loop (same module, same target, same errors).
Returns skip=True when retry/error thresholds are exceeded.
"""

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from collections import defaultdict


@dataclass
class BottleneckEntry:
    """Record of a detected bottleneck."""
    timestamp: str = ""
    module_name: str = ""
    target_url: str = ""
    technique: str = ""
    reason: str = ""
    retry_count: int = 0
    similar_error_count: int = 0
    errors: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class BottleneckDetector:
    """
    Detects when the scanner is stuck in a loop and should skip to the next module.

    Tracking keys are (module_name, target_url) tuples. For each key we track:
    - Total retry count
    - Recent error messages (for similarity detection)
    - Timing information
    """

    def __init__(self, config: dict, session_dir: Optional[Path] = None):
        """
        Args:
            config:      Global config dict
            session_dir: Path to the current session save directory
        """
        self.max_retries = config.get("bottleneck_max_retries", 5)
        self.max_similar_errors = config.get("bottleneck_max_similar_errors", 3)
        self.timeout_threshold = config.get("bottleneck_timeout", 30)

        self.session_dir = Path(session_dir) if session_dir else None
        if self.session_dir:
            self.session_dir.mkdir(parents=True, exist_ok=True)

        # Internal tracking: key = (module, target)
        self._retries: Dict[Tuple[str, str], int] = defaultdict(int)
        self._errors: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        self._start_times: Dict[Tuple[str, str], float] = {}
        self._bottlenecks: List[dict] = []

    def check(
        self,
        module_name: str,
        target: str,
        technique: str = "",
        error: str = "",
    ) -> bool:
        """
        Check whether the scanner should skip this module/target combo.

        Call this BEFORE each exploit attempt. It increments the retry counter
        and checks if any threshold is exceeded.

        Args:
            module_name: The module being run (e.g. "sqli")
            target:      The target URL
            technique:   The specific technique being tried
            error:       Error message from the last attempt (empty on first try)

        Returns:
            True if the module should be SKIPPED (bottleneck detected)
        """
        key = (module_name, target)

        # Record start time on first check
        if key not in self._start_times:
            self._start_times[key] = time.time()

        # Increment retry counter
        self._retries[key] += 1

        # Record error if provided
        if error:
            self._errors[key].append(error)

        # ── Check 1: Max retries exceeded ──────────────────────────────────
        if self._retries[key] > self.max_retries:
            self._record_bottleneck(
                module_name, target, technique,
                reason=f"Max retries exceeded ({self._retries[key]}/{self.max_retries})",
            )
            return True

        # ── Check 2: Too many similar errors ───────────────────────────────
        similar_count = self._count_similar_errors(key)
        if similar_count >= self.max_similar_errors:
            self._record_bottleneck(
                module_name, target, technique,
                reason=f"Repeated similar error ({similar_count}/{self.max_similar_errors})",
            )
            return True

        # ── Check 3: Timeout threshold ─────────────────────────────────────
        elapsed = time.time() - self._start_times[key]
        if elapsed > self.timeout_threshold:
            self._record_bottleneck(
                module_name, target, technique,
                reason=f"Timeout exceeded ({elapsed:.1f}s/{self.timeout_threshold}s)",
            )
            return True

        return False

    def reset(self, module_name: str, target: str):
        """Reset tracking for a specific module/target pair."""
        key = (module_name, target)
        self._retries.pop(key, None)
        self._errors.pop(key, None)
        self._start_times.pop(key, None)

    def reset_all(self):
        """Reset all tracking state."""
        self._retries.clear()
        self._errors.clear()
        self._start_times.clear()

    def _count_similar_errors(self, key: Tuple[str, str]) -> int:
        """
        Count runs of similar consecutive errors.
        Two errors are 'similar' if they share the same first 50 characters
        (normalised to lowercase).
        """
        errors = self._errors.get(key, [])
        if len(errors) < 2:
            return 0

        # Normalise
        normalised = [e.strip().lower()[:50] for e in errors]

        # Count consecutive identical normalised errors from the tail
        count = 1
        for i in range(len(normalised) - 2, -1, -1):
            if normalised[i] == normalised[-1]:
                count += 1
            else:
                break

        return count

    def _record_bottleneck(
        self,
        module_name: str,
        target: str,
        technique: str,
        reason: str,
    ):
        """Record a bottleneck event and persist to session dir."""
        key = (module_name, target)
        entry = BottleneckEntry(
            module_name=module_name,
            target_url=target,
            technique=technique,
            reason=reason,
            retry_count=self._retries.get(key, 0),
            similar_error_count=self._count_similar_errors(key),
            errors=list(self._errors.get(key, []))[-5:],  # Keep last 5 errors
        )

        entry_dict = asdict(entry)
        self._bottlenecks.append(entry_dict)
        self._save_bottleneck_log()

    def _save_bottleneck_log(self):
        """Persist bottleneck log to session directory."""
        if not self.session_dir:
            return

        log_file = self.session_dir / "bottlenecks.json"
        try:
            with open(log_file, "w", encoding="utf-8") as f:
                json.dump(self._bottlenecks, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    def log_bottleneck(self, module_name: str, target: str, reason: str):
        """Manually log a bottleneck (e.g. from external detection)."""
        self._record_bottleneck(module_name, target, "", reason)

    def get_bottlenecks(self) -> List[dict]:
        """Return all recorded bottleneck entries."""
        return list(self._bottlenecks)

    def is_stuck(self, module_name: str, target: str) -> bool:
        """Check if a module/target pair has already been flagged as a bottleneck."""
        for b in self._bottlenecks:
            if b.get("module_name") == module_name and b.get("target_url") == target:
                return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics about bottleneck detection."""
        return {
            "total_bottlenecks": len(self._bottlenecks),
            "active_tracking": len(self._retries),
            "modules_blocked": list(set(
                b.get("module_name", "") for b in self._bottlenecks
            )),
        }
