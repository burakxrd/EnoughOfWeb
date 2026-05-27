"""
EnoughOfWeb — Strategy Engine (v2: Data-Driven)
Dynamically orders attack modules using a 3-tier priority system:
  1. Learned patterns (from patterns.json — highest trust)
  2. Seed heuristics (hardcoded — cold start fallback)
  3. Default order (from config — base fallback)
"""

from typing import List, Dict, Optional, Any
from pathlib import Path


# ── Default module order ───────────────────────────────────────────────────
DEFAULT_ORDER = [
    "sqli", "ssti", "cmdi", "lfi", "xss",
    "jwt", "ssrf", "idor", "auth_bypass",
]

# ── Seed Heuristics (Cold Start) ──────────────────────────────────────────
# These are used when no learned patterns exist yet.
# As patterns.json grows, these become less influential.

SEED_SIGNALS = {
    "php": [("lfi", 15), ("sqli", 5)],
    "asp": [("sqli", 10)],
    "flask": [("ssti", 20)],
    "jinja2": [("ssti", 25)],
    "django": [("ssti", 10)],
    "express": [("ssti", 5), ("cmdi", 5)],
    "node": [("ssti", 5), ("cmdi", 5), ("ssrf", 5)],
    "werkzeug": [("ssti", 20)],
    "tornado": [("ssti", 15)],
    "python": [("ssti", 10)],
    "jwt_cookie": [("jwt", 30)],
    "login_form": [("auth_bypass", 20), ("sqli", 10)],
    "upload_form": [("cmdi", 10), ("lfi", 5)],
    "file_param": [("lfi", 20), ("ssrf", 5)],
    "id_param": [("sqli", 20), ("idor", 15)],
    "url_param": [("ssrf", 20)],
    "cmd_param": [("cmdi", 25)],
}

SEED_PARAM_BOOSTS = {
    "id": [("sqli", 15), ("idor", 15)],
    "file": [("lfi", 20)],
    "path": [("lfi", 15)],
    "include": [("lfi", 20)],
    "template": [("ssti", 15)],
    "url": [("ssrf", 20)],
    "redirect": [("ssrf", 15)],
    "cmd": [("cmdi", 25)],
    "command": [("cmdi", 25)],
    "search": [("xss", 15), ("sqli", 10)],
    "query": [("sqli", 15), ("xss", 10)],
    "username": [("auth_bypass", 10), ("sqli", 10)],
    "password": [("auth_bypass", 10), ("sqli", 10)],
}


class StrategyEngine:
    """
    Determines optimal module execution order using a 3-tier system:
      Tier 1: Learned patterns from patterns.json (data-driven)
      Tier 2: Seed heuristics (hardcoded fallback for cold start)
      Tier 3: Default order from config

    As the tool accumulates data, Tier 1 patterns gradually overshadow
    Tier 2 seeds. The seed heuristics never disappear (they serve as
    baseline) but their relative weight decreases.
    """

    def __init__(self, config: dict, learner=None, pattern_miner=None):
        """
        Args:
            config: Global config dict
            learner: AdaptiveLearner instance (for historical success rates)
            pattern_miner: PatternMiner instance (for learned patterns)
        """
        self.config = config
        self.learner = learner
        self.pattern_miner = pattern_miner
        self.default_order = list(config.get("module_priority", DEFAULT_ORDER))

    def get_priority_order(self, recon_data: dict) -> List[str]:
        """
        Compute optimal module order.

        Args:
            recon_data: Dict from Recon.run()

        Returns:
            Ordered list of module names (highest priority first)
        """
        scores = self._compute_scores(recon_data)
        ordered = sorted(scores.keys(), key=lambda m: scores[m], reverse=True)
        return ordered

    def get_suggested_order(self, recon_data: dict) -> Dict[str, Any]:
        """
        Get suggested order with reasoning (for agent/brain consumption).

        Returns:
            Dict with order, scores, signals, and reasoning
        """
        scores, breakdown = self._compute_scores(recon_data, explain=True)
        ordered = sorted(scores.keys(), key=lambda m: scores[m], reverse=True)

        return {
            "suggested_order": ordered,
            "scores": {m: round(scores[m], 1) for m in ordered},
            "reasoning": breakdown,
            "tier_info": self._get_tier_info(),
        }

    def _compute_scores(self, recon_data: dict, explain: bool = False):
        """Compute module scores from all 3 tiers."""
        # Base scores from default order position
        scores: Dict[str, float] = {}
        for i, mod in enumerate(self.default_order):
            scores[mod] = (len(self.default_order) - i) * 2

        breakdown = {} if explain else None

        # ── Tier 3: Default order (already applied above) ──────────────

        # ── Tier 2: Seed heuristics ────────────────────────────────────
        seed_boosts = self._apply_seed_heuristics(recon_data, scores)
        if explain:
            breakdown["seed_signals"] = seed_boosts

        # ── Tier 1: Learned patterns (highest priority) ────────────────
        learned_boosts = self._apply_learned_patterns(recon_data, scores)
        if explain:
            breakdown["learned_patterns"] = learned_boosts

        # ── Historical success rate adjustment ─────────────────────────
        if self.learner:
            history_boosts = self._apply_history(scores)
            if explain:
                breakdown["history_boosts"] = history_boosts

        if explain:
            return scores, breakdown
        return scores

    def _apply_seed_heuristics(self, recon_data: dict, scores: Dict[str, float]) -> List[str]:
        """Apply Tier 2 seed heuristics. Returns list of signals detected."""
        signals_detected = []
        signals = self._extract_signals(recon_data)

        for signal in signals:
            signal_lower = signal.lower()
            if signal_lower in SEED_SIGNALS:
                for module, boost in SEED_SIGNALS[signal_lower]:
                    if module in scores:
                        # Seed weight decreases as we have more learned patterns
                        seed_weight = self._get_seed_weight()
                        adjusted_boost = boost * seed_weight
                        scores[module] += adjusted_boost
                        signals_detected.append(f"{signal}→{module}(+{adjusted_boost:.0f})")

        # Parameter name boosts
        params = self._extract_params(recon_data)
        for param_name in params:
            param_lower = param_name.lower()
            if param_lower in SEED_PARAM_BOOSTS:
                for module, boost in SEED_PARAM_BOOSTS[param_lower]:
                    if module in scores:
                        seed_weight = self._get_seed_weight()
                        scores[module] += boost * seed_weight

        return signals_detected

    def _apply_learned_patterns(self, recon_data: dict, scores: Dict[str, float]) -> List[str]:
        """Apply Tier 1 learned patterns. Returns list of applied patterns."""
        applied = []

        if not self.pattern_miner:
            return applied

        patterns = self.pattern_miner.get_active_patterns(min_confidence=0.3)

        # Build a context dict for trigger matching
        from brain.learner import TargetContext
        ctx = TargetContext.from_recon("", recon_data)
        ctx_dict = {
            "target_context": {
                "tech": ctx.tech,
                "has_login_form": ctx.has_login_form,
                "has_upload_form": ctx.has_upload_form,
                "has_file_param": ctx.has_file_param,
                "has_id_param": ctx.has_id_param,
                "has_url_param": ctx.has_url_param,
                "has_cmd_param": ctx.has_cmd_param,
            }
        }

        for pattern in patterns:
            trigger = pattern.get("trigger", {})
            action = pattern.get("action", {})
            confidence = pattern.get("confidence", {})

            if self.pattern_miner._trigger_matches(trigger, ctx_dict):
                module = action.get("boost_module", "")
                boost = action.get("boost_amount", 0)
                rate = confidence.get("success_rate", 0.5)
                samples = confidence.get("sample_size", 0)

                if module in scores:
                    # Weight by confidence
                    weighted_boost = boost * rate
                    scores[module] += weighted_boost
                    applied.append(
                        f"[{pattern.get('type', '')}] {trigger.get('value', '')}→"
                        f"{module}(+{weighted_boost:.0f}, conf={rate:.0%}, n={samples})"
                    )

        return applied

    def _apply_history(self, scores: Dict[str, float]) -> Dict[str, float]:
        """Apply historical success rate boosts/penalties."""
        boosts = {}
        for mod in scores:
            rate = self.learner.get_success_rate(mod)
            if rate > 0:
                boost = rate * 15  # Max +15
                scores[mod] += boost
                boosts[mod] = boost
            # Penalize modules that consistently fail
            failures = self.learner.get_common_failures(mod)
            if failures:
                total_fails = sum(f["count"] for f in failures)
                penalty = min(total_fails * 0.5, 10)
                scores[mod] -= penalty
                boosts[mod] = boosts.get(mod, 0) - penalty
        return boosts

    def _get_seed_weight(self) -> float:
        """
        Seed heuristic weight decreases as learned patterns grow.
        Starts at 1.0, asymptotically approaches 0.3.
        """
        if not self.pattern_miner:
            return 1.0

        pattern_count = len(self.pattern_miner.get_active_patterns())
        if pattern_count == 0:
            return 1.0

        # Sigmoid-like decay: 1.0 → 0.3 as patterns grow
        # At 10 patterns: ~0.7, at 30 patterns: ~0.4, at 50+: ~0.3
        import math
        weight = 0.3 + 0.7 * math.exp(-pattern_count / 15)
        return max(weight, 0.3)

    def _get_tier_info(self) -> Dict[str, Any]:
        """Info about which tier is dominant."""
        seed_weight = self._get_seed_weight()
        pattern_count = 0
        if self.pattern_miner:
            pattern_count = len(self.pattern_miner.get_active_patterns())

        if pattern_count == 0:
            dominant = "seed_heuristics (cold start)"
        elif seed_weight > 0.6:
            dominant = "mixed (seed + learned)"
        else:
            dominant = "learned_patterns (data-driven)"

        return {
            "dominant_tier": dominant,
            "seed_weight": round(seed_weight, 2),
            "active_patterns": pattern_count,
        }

    # ── Signal Extraction (same as v1 for compat) ──────────────────────────

    def _extract_signals(self, recon_data: dict) -> List[str]:
        signals = []
        tech = recon_data.get("technology", {})
        server = (tech.get("server", "") or "").lower()
        powered = (tech.get("x_powered_by", "") or "").lower()

        if "php" in powered or "php" in server:
            signals.append("php")
        if "asp" in powered or "asp" in server:
            signals.append("asp")
        if any(kw in server for kw in ("werkzeug", "flask")):
            signals.extend(["flask", "werkzeug"])
        if "express" in powered or "express" in server:
            signals.append("express")
        if "tornado" in server:
            signals.append("tornado")

        for fw in tech.get("frameworks", []):
            fl = fw.lower()
            if "jinja" in fl:
                signals.append("jinja2")
            if "django" in fl:
                signals.append("django")
            if "flask" in fl:
                signals.append("flask")
            if "node" in fl:
                signals.append("node")

        cookies = recon_data.get("cookies", {})
        for name, value in cookies.items():
            nl = name.lower()
            if nl in ("jwt", "token", "authorization") or _looks_like_jwt(value):
                signals.append("jwt_cookie")

        forms = recon_data.get("forms", [])
        for form in forms:
            inputs = form.get("inputs", {})
            if isinstance(inputs, dict):
                input_names = set(k.lower() for k in inputs.keys())
            elif isinstance(inputs, list):
                input_names = set(inp.get("name", "").lower() for inp in inputs)
            else:
                input_names = set()

            if input_names & {"password", "pass", "passwd", "pwd"}:
                signals.append("login_form")
            if "file" in input_names:
                signals.append("upload_form")

        url_params = recon_data.get("url_params", [])
        for param in (url_params if isinstance(url_params, list) else []):
            pl = param.lower() if isinstance(param, str) else ""
            if pl in ("id", "uid", "user_id"):
                signals.append("id_param")
            if pl in ("file", "path", "page", "include"):
                signals.append("file_param")
            if pl in ("url", "redirect", "next"):
                signals.append("url_param")
            if pl in ("cmd", "command", "exec"):
                signals.append("cmd_param")

        return signals

    def _extract_params(self, recon_data: dict) -> List[str]:
        params = list(recon_data.get("url_params", []))
        for form in recon_data.get("forms", []):
            inputs = form.get("inputs", {})
            if isinstance(inputs, dict):
                params.extend(inputs.keys())
            elif isinstance(inputs, list):
                params.extend(inp.get("name", "") for inp in inputs if inp.get("name"))
        return params

    def explain(self, recon_data: dict) -> str:
        """Human-readable strategy explanation."""
        result = self.get_suggested_order(recon_data)
        lines = ["Strategy order:"]
        for i, mod in enumerate(result["suggested_order"], 1):
            score = result["scores"].get(mod, 0)
            lines.append(f"  {i}. {mod} (score={score})")

        tier = result.get("tier_info", {})
        lines.append(f"\nDominant: {tier.get('dominant_tier', 'unknown')}")
        lines.append(f"Seed weight: {tier.get('seed_weight', 1.0)}")
        lines.append(f"Active patterns: {tier.get('active_patterns', 0)}")

        reasoning = result.get("reasoning", {})
        if reasoning.get("learned_patterns"):
            lines.append("\nLearned patterns applied:")
            for p in reasoning["learned_patterns"]:
                lines.append(f"  • {p}")

        return "\n".join(lines)


def _looks_like_jwt(value: str) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 3:
        return False
    import re
    b64url = re.compile(r'^[A-Za-z0-9_\-]+=*$')
    return all(b64url.match(p) for p in parts if p)
