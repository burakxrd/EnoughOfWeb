"""
EnoughOfWeb — Rulebook
Self-writing rule system. Automatically generates lessons from exploit history
and stores them in data/rulebook.json for future strategy adjustments.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
from collections import Counter


@dataclass
class Rule:
    """A single rule learned from experience."""
    id: str = ""
    created_at: str = ""
    type: str = ""           # "lesson_learned", "mistake", "strategy"
    category: str = ""       # Vulnerability type or general category
    rule_text: str = ""      # Human-readable rule description
    context: Dict[str, Any] = field(default_factory=dict)
    priority_boost: Dict[str, float] = field(default_factory=dict)
    origin: str = "auto_mined"   # "auto_mined" | "agent_correction" | "seed"
    confidence: float = 1.0      # 0.0–1.0, decays over time

    def __post_init__(self):
        if not self.id:
            self.id = uuid.uuid4().hex[:12]
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()



class Rulebook:
    """
    Self-writing rule system. Stores rules in data/rulebook.json.
    Auto-generates rules from exploit history patterns.
    """

    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            data_dir = Path(__file__).parent.parent / "data"
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.rules_file = self.data_dir / "rulebook.json"
        self._cache: Optional[List[dict]] = None

    # ── File I/O ───────────────────────────────────────────────────────────

    def _load(self) -> List[dict]:
        """Load rules from disk."""
        if self._cache is not None:
            return self._cache

        if not self.rules_file.exists():
            self._cache = []
            return self._cache

        try:
            with open(self.rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._cache = data if isinstance(data, list) else []
        except (json.JSONDecodeError, IOError):
            self._cache = []

        return self._cache

    def _save(self):
        """Persist rules to disk."""
        data = self._load()
        try:
            with open(self.rules_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    # ── Rule Management ────────────────────────────────────────────────────

    def add_rule(self, rule: Rule) -> str:
        """
        Add a new rule to the rulebook.

        Args:
            rule: Rule dataclass instance

        Returns:
            The rule's ID
        """
        data = self._load()

        # Check for duplicate rule text in same category
        for existing in data:
            if (existing.get("rule_text") == rule.rule_text
                    and existing.get("category") == rule.category):
                return existing.get("id", "")

        data.append(asdict(rule))
        self._save()
        return rule.id

    def add_quick(
        self,
        rule_type: str,
        category: str,
        rule_text: str,
        context: Optional[Dict[str, Any]] = None,
        priority_boost: Optional[Dict[str, float]] = None,
    ) -> str:
        """Convenience method to add a rule without constructing a Rule object."""
        rule = Rule(
            type=rule_type,
            category=category,
            rule_text=rule_text,
            context=context or {},
            priority_boost=priority_boost or {},
        )
        return self.add_rule(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        data = self._load()
        original_len = len(data)
        self._cache = [r for r in data if r.get("id") != rule_id]
        if len(self._cache) < original_len:
            self._save()
            return True
        return False

    def get_rules(self, category: Optional[str] = None, rule_type: Optional[str] = None) -> List[dict]:
        """
        Get rules, optionally filtered by category and/or type.

        Args:
            category: Filter by vulnerability type or category
            rule_type: Filter by rule type (lesson_learned, mistake, strategy)

        Returns:
            List of rule dicts
        """
        data = self._load()
        results = data

        if category:
            results = [r for r in results if r.get("category") == category]
        if rule_type:
            results = [r for r in results if r.get("type") == rule_type]

        return results

    def get_rule_by_id(self, rule_id: str) -> Optional[dict]:
        """Get a specific rule by its ID."""
        data = self._load()
        for rule in data:
            if rule.get("id") == rule_id:
                return rule
        return None

    # ── Strategy Integration ───────────────────────────────────────────────

    def apply_to_strategy(self) -> Dict[str, float]:
        """
        Aggregate all priority_boost values from rules into a single dict
        that can be applied to the StrategyEngine.

        Returns:
            Dict of {module_name: total_boost}
        """
        data = self._load()
        boosts: Dict[str, float] = {}

        for rule in data:
            pb = rule.get("priority_boost", {})
            for module, boost in pb.items():
                boosts[module] = boosts.get(module, 0) + boost

        return boosts

    # ── Auto-Rule Generation ───────────────────────────────────────────────

    def generate_rules_from_history(self, learner) -> List[str]:
        """
        Analyze the AdaptiveLearner's history and auto-generate rules.
        Rules are created for:
        - 3+ same error message → lesson_learned rule
        - Technique that always succeeds (3+ attempts, 100% rate) → strategy rule
        - Technique that always fails (5+ attempts, 0% rate) → mistake rule
        - Vulnerability type with 0% success after 5+ attempts → strategy rule

        Args:
            learner: AdaptiveLearner instance

        Returns:
            List of generated rule IDs
        """
        generated_ids = []
        existing_rules = self._load()
        existing_texts = {r.get("rule_text", "") for r in existing_rules}

        # Load all attempts from learner
        attempts = learner._load()
        if not attempts:
            return generated_ids

        # ── Rule 1: Repeated errors ────────────────────────────────────────
        error_counter: Dict[str, Dict[str, Any]] = {}
        for a in attempts:
            err = a.get("error", "").strip()
            vuln = a.get("module", "unknown")
            if not err:
                continue
            key = f"{vuln}::{err}"
            if key not in error_counter:
                error_counter[key] = {"vuln": vuln, "error": err, "count": 0}
            error_counter[key]["count"] += 1

        for key, info in error_counter.items():
            if info["count"] >= 3:
                text = (
                    f"Repeated error in {info['vuln']}: \"{info['error']}\" "
                    f"(seen {info['count']} times). Consider alternative approach."
                )
                if text not in existing_texts:
                    rule_id = self.add_quick(
                        rule_type="lesson_learned",
                        category=info["vuln"],
                        rule_text=text,
                        context={"error": info["error"], "count": info["count"]},
                    )
                    generated_ids.append(rule_id)
                    existing_texts.add(text)

        # ── Rule 2: Always-successful techniques ──────────────────────────
        technique_stats: Dict[str, Dict[str, Any]] = {}
        for a in attempts:
            vuln = a.get("module", "unknown")
            tech = a.get("technique", "")
            if not tech:
                continue
            key = f"{vuln}::{tech}"
            if key not in technique_stats:
                technique_stats[key] = {"vuln": vuln, "tech": tech, "total": 0, "success": 0}
            technique_stats[key]["total"] += 1
            if a.get("success"):
                technique_stats[key]["success"] += 1

        for key, info in technique_stats.items():
            if info["total"] >= 3 and info["success"] == info["total"]:
                text = (
                    f"Technique '{info['tech']}' for {info['vuln']} has 100% success rate "
                    f"over {info['total']} attempts. Try this first."
                )
                if text not in existing_texts:
                    rule_id = self.add_quick(
                        rule_type="strategy",
                        category=info["vuln"],
                        rule_text=text,
                        context={"technique": info["tech"], "attempts": info["total"]},
                        priority_boost={info["vuln"]: 10},
                    )
                    generated_ids.append(rule_id)
                    existing_texts.add(text)

            elif info["total"] >= 5 and info["success"] == 0:
                text = (
                    f"Technique '{info['tech']}' for {info['vuln']} has 0% success rate "
                    f"over {info['total']} attempts. Skip or deprioritize."
                )
                if text not in existing_texts:
                    rule_id = self.add_quick(
                        rule_type="mistake",
                        category=info["vuln"],
                        rule_text=text,
                        context={"technique": info["tech"], "attempts": info["total"]},
                        priority_boost={info["vuln"]: -5},
                    )
                    generated_ids.append(rule_id)
                    existing_texts.add(text)

        # ── Rule 3: Vuln types with zero success after many attempts ──────
        vuln_stats: Dict[str, Dict[str, int]] = {}
        for a in attempts:
            vuln = a.get("module", "unknown")
            if vuln not in vuln_stats:
                vuln_stats[vuln] = {"total": 0, "success": 0}
            vuln_stats[vuln]["total"] += 1
            if a.get("success"):
                vuln_stats[vuln]["success"] += 1

        for vuln, info in vuln_stats.items():
            if info["total"] >= 5 and info["success"] == 0:
                text = (
                    f"Module '{vuln}' has 0% success rate after {info['total']} attempts. "
                    f"Deprioritize unless recon strongly suggests it."
                )
                if text not in existing_texts:
                    rule_id = self.add_quick(
                        rule_type="strategy",
                        category=vuln,
                        rule_text=text,
                        context={"attempts": info["total"]},
                        priority_boost={vuln: -10},
                    )
                    generated_ids.append(rule_id)
                    existing_texts.add(text)

        return generated_ids

    # ── Display ────────────────────────────────────────────────────────────

    def display_rules(self, category: Optional[str] = None) -> str:
        """
        Format rules for terminal display.

        Args:
            category: Optional filter by category

        Returns:
            Formatted string of all matching rules
        """
        rules = self.get_rules(category=category)
        if not rules:
            return "[Rulebook] No rules recorded yet."

        lines = [f"╔══ Rulebook ({len(rules)} rules) ══╗"]

        type_icons = {
            "lesson_learned": "📖",
            "mistake": "⚠️",
            "strategy": "🎯",
        }

        for rule in rules:
            icon = type_icons.get(rule.get("type", ""), "•")
            lines.append(f"  {icon} [{rule.get('category', '?')}] {rule.get('rule_text', '')}")
            boosts = rule.get("priority_boost", {})
            if boosts:
                boost_parts = [f"{mod}: {'+' if v > 0 else ''}{v}" for mod, v in boosts.items()]
                lines.append(f"     Priority: {', '.join(boost_parts)}")

        lines.append("╚" + "═" * 30 + "╝")
        return "\n".join(lines)

    def clear(self):
        """Clear all rules. Use with caution."""
        self._cache = []
        self._save()
