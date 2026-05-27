"""
EnoughOfWeb — Pattern Miner
Analyzes experience DB to extract actionable patterns:
  - Context patterns: "PHP targets → LFI works 80%"
  - Sequence patterns: "Twig fail → Jinja2 success"
  - Override patterns: "Agent always picks auth_bypass for login forms"

Patterns drive the data-driven strategy engine and decay over time
if not validated by new data.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from collections import Counter, defaultdict


# ── Pattern Data Structures ────────────────────────────────────────────────

PATTERN_TYPES = {
    "context_success":      "Module X works well when context has Y",
    "context_failure":      "Module X fails when context has Y",
    "sequence_correction":  "After X fails, Y succeeds",
    "agent_learned":        "Agent overrides to X in context Y → success",
    "technique_preference": "Technique T works best for module M",
}


class PatternMiner:
    """
    Mines the experience database for actionable patterns.
    Patterns are saved to data/patterns.json and used by StrategyEngine.
    """

    PATTERNS_VERSION = 1
    # Minimum samples before a pattern is considered
    MIN_SAMPLES = 3
    # Confidence decay: reduce by this factor per 30 days without validation
    DECAY_FACTOR = 0.9
    # Minimum confidence to keep a pattern
    MIN_CONFIDENCE = 0.2

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            data_dir = Path(__file__).parent.parent / "data"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.patterns_file = self.data_dir / "patterns.json"
        self._cache: Optional[List[dict]] = None

    # ── File I/O ───────────────────────────────────────────────────────────

    def _load_patterns(self) -> List[dict]:
        if self._cache is not None:
            return self._cache

        if not self.patterns_file.exists():
            self._cache = []
            return self._cache

        try:
            with open(self.patterns_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._cache = data.get("patterns", [])
            elif isinstance(data, list):
                self._cache = data
            else:
                self._cache = []
        except (json.JSONDecodeError, IOError):
            self._cache = []

        return self._cache

    def _save_patterns(self, patterns: List[dict]):
        doc = {
            "version": self.PATTERNS_VERSION,
            "pattern_count": len(patterns),
            "last_mined": datetime.now(timezone.utc).isoformat(),
            "patterns": patterns,
        }
        try:
            with open(self.patterns_file, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2, ensure_ascii=False, default=str)
            self._cache = patterns
        except IOError:
            pass

    def get_patterns(self) -> List[dict]:
        """Return all patterns."""
        return list(self._load_patterns())

    def get_active_patterns(self, min_confidence: float = 0.3) -> List[dict]:
        """Return patterns with confidence above threshold."""
        return [
            p for p in self._load_patterns()
            if p.get("confidence", {}).get("success_rate", 0) >= min_confidence
               and p.get("confidence", {}).get("sample_size", 0) >= self.MIN_SAMPLES
        ]

    # ── Mining Engine ──────────────────────────────────────────────────────

    def mine_all(self, entries: List[dict]) -> List[str]:
        """
        Run all pattern miners on the experience entries.

        Returns:
            List of new pattern IDs generated
        """
        existing = self._load_patterns()
        existing_keys = set(self._pattern_key(p) for p in existing)
        new_ids = []

        # Mine each type
        for pattern in self._mine_context_patterns(entries):
            key = self._pattern_key(pattern)
            if key not in existing_keys:
                existing.append(pattern)
                existing_keys.add(key)
                new_ids.append(pattern["id"])

        for pattern in self._mine_sequence_patterns(entries):
            key = self._pattern_key(pattern)
            if key not in existing_keys:
                existing.append(pattern)
                existing_keys.add(key)
                new_ids.append(pattern["id"])

        for pattern in self._mine_override_patterns(entries):
            key = self._pattern_key(pattern)
            if key not in existing_keys:
                existing.append(pattern)
                existing_keys.add(key)
                new_ids.append(pattern["id"])

        # Update confidence of existing patterns with new data
        for pattern in existing:
            if pattern["id"] not in new_ids:
                self._update_confidence(pattern, entries)

        self._save_patterns(existing)
        return new_ids

    def _pattern_key(self, pattern: dict) -> str:
        """Generate a unique key for deduplication."""
        trigger = pattern.get("trigger", {})
        action = pattern.get("action", {})
        return f"{pattern.get('type', '')}:{trigger.get('field', '')}:{trigger.get('value', '')}:{action.get('boost_module', '')}"

    # ── Context Patterns ───────────────────────────────────────────────────

    def _mine_context_patterns(self, entries: List[dict]) -> List[dict]:
        """
        Mine: "When target has tech X, module Y has Z% success rate"
        """
        patterns = []

        # Group by (tech, module) → success/fail counts
        tech_module_stats: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(
            lambda: {"success": 0, "fail": 0}
        )

        for entry in entries:
            ctx = entry.get("target_context", {})
            tech_list = ctx.get("tech", [])
            module = entry.get("module", "")
            if not module:
                continue

            for tech in tech_list:
                key = (tech.lower(), module)
                if entry.get("success"):
                    tech_module_stats[key]["success"] += 1
                else:
                    tech_module_stats[key]["fail"] += 1

        for (tech, module), stats in tech_module_stats.items():
            total = stats["success"] + stats["fail"]
            if total < self.MIN_SAMPLES:
                continue

            rate = stats["success"] / total

            if rate >= 0.6:  # Success pattern
                boost = int(rate * 20)  # Max boost 20
                patterns.append(self._make_pattern(
                    ptype="context_success",
                    trigger={"field": "target.tech", "operator": "contains", "value": tech},
                    action={"boost_module": module, "boost_amount": boost},
                    confidence={"sample_size": total, "success_rate": round(rate, 4)},
                    origin="auto_mined",
                ))

            elif rate <= 0.2 and total >= 5:  # Failure pattern
                penalty = int((1 - rate) * -10)  # Max penalty -10
                patterns.append(self._make_pattern(
                    ptype="context_failure",
                    trigger={"field": "target.tech", "operator": "contains", "value": tech},
                    action={"boost_module": module, "boost_amount": penalty},
                    confidence={"sample_size": total, "success_rate": round(rate, 4)},
                    origin="auto_mined",
                ))

        # Also mine boolean context fields
        bool_fields = [
            ("has_login_form", True),
            ("has_file_param", True),
            ("has_id_param", True),
            ("has_url_param", True),
            ("has_cmd_param", True),
        ]

        for field_name, field_val in bool_fields:
            module_stats: Dict[str, Dict[str, int]] = defaultdict(
                lambda: {"success": 0, "fail": 0}
            )
            for entry in entries:
                ctx = entry.get("target_context", {})
                if ctx.get(field_name) != field_val:
                    continue
                module = entry.get("module", "")
                if not module:
                    continue
                if entry.get("success"):
                    module_stats[module]["success"] += 1
                else:
                    module_stats[module]["fail"] += 1

            for module, stats in module_stats.items():
                total = stats["success"] + stats["fail"]
                if total < self.MIN_SAMPLES:
                    continue
                rate = stats["success"] / total
                if rate >= 0.6:
                    patterns.append(self._make_pattern(
                        ptype="context_success",
                        trigger={"field": f"target.{field_name}", "operator": "equals", "value": field_val},
                        action={"boost_module": module, "boost_amount": int(rate * 15)},
                        confidence={"sample_size": total, "success_rate": round(rate, 4)},
                        origin="auto_mined",
                    ))

        return patterns

    # ── Sequence Patterns ──────────────────────────────────────────────────

    def _mine_sequence_patterns(self, entries: List[dict]) -> List[dict]:
        """
        Mine: "When module X fails, module Y succeeds next"
        """
        patterns = []

        # Group entries by session
        sessions: Dict[str, List[dict]] = defaultdict(list)
        for entry in entries:
            sid = entry.get("session_id", "")
            if sid:
                sessions[sid].append(entry)

        # Look for fail→success transitions within sessions
        transition_stats: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(
            lambda: {"success": 0, "fail": 0}
        )

        for sid, session_entries in sessions.items():
            # Sort by sequence position
            sorted_entries = sorted(session_entries, key=lambda e: e.get("sequence_position", 0))

            for i in range(1, len(sorted_entries)):
                prev = sorted_entries[i - 1]
                curr = sorted_entries[i]

                prev_mod = prev.get("module", "")
                curr_mod = curr.get("module", "")
                prev_failed = not prev.get("success", False)
                curr_succeeded = curr.get("success", False)

                if prev_mod and curr_mod and prev_mod != curr_mod:
                    key = (prev_mod, curr_mod)
                    if prev_failed and curr_succeeded:
                        transition_stats[key]["success"] += 1
                    elif prev_failed and not curr_succeeded:
                        transition_stats[key]["fail"] += 1

        for (prev_mod, curr_mod), stats in transition_stats.items():
            total = stats["success"] + stats["fail"]
            if total < self.MIN_SAMPLES:
                continue

            rate = stats["success"] / total
            if rate >= 0.6:
                patterns.append(self._make_pattern(
                    ptype="sequence_correction",
                    trigger={
                        "field": "action.module",
                        "operator": "equals",
                        "value": prev_mod,
                        "context": {"previous_result": "fail"},
                    },
                    action={
                        "boost_module": curr_mod,
                        "boost_amount": int(rate * 15),
                        "after_fail_of": prev_mod,
                    },
                    confidence={"sample_size": total, "success_rate": round(rate, 4)},
                    origin="auto_mined",
                ))

        return patterns

    # ── Override Patterns ──────────────────────────────────────────────────

    def _mine_override_patterns(self, entries: List[dict]) -> List[dict]:
        """
        Mine: "Agent overrides to module X in context Y → successful"
        """
        patterns = []

        overrides = [e for e in entries if e.get("source") == "agent_override"]
        if len(overrides) < self.MIN_SAMPLES:
            return patterns

        # Group overrides by (context_feature, module) → success rate
        override_contexts: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(
            lambda: {"success": 0, "fail": 0}
        )

        for entry in overrides:
            ctx = entry.get("target_context", {})
            module = entry.get("module", "")
            if not module:
                continue

            # Check each context feature
            if ctx.get("has_login_form"):
                key = ("has_login_form", module)
                if entry.get("success"):
                    override_contexts[key]["success"] += 1
                else:
                    override_contexts[key]["fail"] += 1

            for tech in ctx.get("tech", []):
                key = (f"tech:{tech}", module)
                if entry.get("success"):
                    override_contexts[key]["success"] += 1
                else:
                    override_contexts[key]["fail"] += 1

        for (context_key, module), stats in override_contexts.items():
            total = stats["success"] + stats["fail"]
            if total < 2:  # Lower threshold for agent patterns
                continue

            rate = stats["success"] / total
            if rate >= 0.6:
                # Parse context key
                if context_key.startswith("tech:"):
                    trigger = {
                        "field": "target.tech",
                        "operator": "contains",
                        "value": context_key.split(":", 1)[1],
                    }
                else:
                    trigger = {
                        "field": f"target.{context_key}",
                        "operator": "equals",
                        "value": True,
                    }

                patterns.append(self._make_pattern(
                    ptype="agent_learned",
                    trigger=trigger,
                    action={"boost_module": module, "boost_amount": int(rate * 25)},
                    confidence={"sample_size": total, "success_rate": round(rate, 4)},
                    origin="agent_correction",
                ))

        return patterns

    # ── Confidence Management ──────────────────────────────────────────────

    def _update_confidence(self, pattern: dict, entries: List[dict]):
        """Update a pattern's confidence based on new entries."""
        trigger = pattern.get("trigger", {})
        action = pattern.get("action", {})
        target_module = action.get("boost_module", "")
        if not target_module:
            return

        # Count matching entries
        matching = 0
        successes = 0
        for entry in entries:
            if self._trigger_matches(trigger, entry):
                if entry.get("module") == target_module:
                    matching += 1
                    if entry.get("success"):
                        successes += 1

        if matching > 0:
            new_rate = successes / matching
            old = pattern.get("confidence", {})
            old_size = old.get("sample_size", 0)
            old_rate = old.get("success_rate", 0)

            # Weighted average of old and new
            total_size = old_size + matching
            blended_rate = (old_rate * old_size + new_rate * matching) / total_size

            pattern["confidence"] = {
                "sample_size": total_size,
                "success_rate": round(blended_rate, 4),
                "last_validated": datetime.now(timezone.utc).isoformat(),
            }

    def decay_confidence(self):
        """Reduce confidence of patterns not validated recently."""
        patterns = self._load_patterns()
        now = datetime.now(timezone.utc)
        changed = False

        for pattern in patterns:
            conf = pattern.get("confidence", {})
            last_validated = conf.get("last_validated", "")
            if not last_validated:
                continue

            try:
                last_dt = datetime.fromisoformat(last_validated.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

            days_since = (now - last_dt).days
            if days_since > 30:
                decay_rounds = days_since // 30
                current_rate = conf.get("success_rate", 0)
                decayed = current_rate * (self.DECAY_FACTOR ** decay_rounds)
                conf["success_rate"] = round(max(decayed, 0), 4)
                changed = True

        # Remove patterns below minimum confidence
        filtered = [
            p for p in patterns
            if p.get("confidence", {}).get("success_rate", 0) >= self.MIN_CONFIDENCE
        ]

        if changed or len(filtered) < len(patterns):
            self._save_patterns(filtered)

    def _trigger_matches(self, trigger: dict, entry: dict) -> bool:
        """Check if a trigger condition matches an entry."""
        field = trigger.get("field", "")
        operator = trigger.get("operator", "")
        value = trigger.get("value", "")

        if field.startswith("target."):
            ctx_field = field[7:]  # Remove "target."
            ctx = entry.get("target_context", {})

            if operator == "contains":
                ctx_val = ctx.get(ctx_field, [])
                if isinstance(ctx_val, list):
                    return value in [str(v).lower() for v in ctx_val]
                return str(value).lower() in str(ctx_val).lower()

            elif operator == "equals":
                return ctx.get(ctx_field) == value

        elif field.startswith("action."):
            act_field = field[7:]
            return entry.get(act_field) == value

        return False

    # ── Helpers ────────────────────────────────────────────────────────────

    def _make_pattern(
        self,
        ptype: str,
        trigger: dict,
        action: dict,
        confidence: dict,
        origin: str,
    ) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        confidence["last_validated"] = now
        return {
            "id": f"p_{uuid.uuid4().hex[:8]}",
            "created_at": now,
            "type": ptype,
            "trigger": trigger,
            "action": action,
            "confidence": confidence,
            "origin": origin,
        }
