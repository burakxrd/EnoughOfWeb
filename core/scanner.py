"""
EnoughOfWeb — Scanner (Main Orchestrator) v2
Pipeline: recon → strategy → module loop (detect → exploit → flag check → next).
Now with session tracking, context-aware logging, and override detection.
"""

import time
import json
import importlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any

from core.session import CTFSession
from core.flag_hunter import FlagHunter
from core.recon import Recon
from core.reporter import Reporter
from core.bottleneck import BottleneckDetector
from core.session_tracker import SessionTracker
from brain.learner import AdaptiveLearner, TargetContext
from brain.strategy import StrategyEngine
from brain.pattern_miner import PatternMiner
from brain.rulebook import Rulebook
from modules.base import ModuleResult, Finding, ExploitResult


# Map of module names to their module paths and class names
MODULE_REGISTRY = {
    "sqli": ("modules.sqli", "SQLiExploit"),
    "ssti": ("modules.ssti", "SSTIExploit"),
    "cmdi": ("modules.cmdi", "CMDiExploit"),
    "lfi": ("modules.lfi", "LFIExploit"),
    "xss": ("modules.xss", "XSSExploit"),
    "jwt": ("modules.jwt_attack", "JWTExploit"),
    "ssrf": ("modules.ssrf", "SSRFExploit"),
    "idor": ("modules.idor", "IDORExploit"),
    "auth_bypass": ("modules.auth_bypass", "AuthBypassExploit"),
}


class Scanner:
    """
    Main orchestrator for EnoughOfWeb.

    Pipeline:
    1. Create/load session via SessionTracker
    2. Run reconnaissance (Recon)
    3. Determine module priority (StrategyEngine with learned patterns)
    4. For each module:
       a. Check bottleneck → skip if stuck
       b. Detect override (autonomous vs agent)
       c. Run detect() → findings
       d. For each finding: run exploit() → check for flag
       e. Log attempt with context to AdaptiveLearner
       f. Report findings/flags via Reporter
    5. Mine patterns from history (PatternMiner)
    6. Save session data and final report
    """

    def __init__(self, config: dict, custom_flag_pattern: Optional[str] = None):
        self.config = config
        self.root_dir = Path(__file__).parent.parent
        self.saves_dir = self.root_dir / "saves"
        self.saves_dir.mkdir(parents=True, exist_ok=True)

        # Core components
        flag_pattern = custom_flag_pattern or config.get("flag_format")
        self.flag_hunter = FlagHunter(custom_pattern=flag_pattern)
        self.session = CTFSession(config, flag_hunter=self.flag_hunter)

        # Brain components
        data_dir = self.root_dir / "data"
        self.learner = AdaptiveLearner(data_dir=data_dir)
        self.pattern_miner = PatternMiner(data_dir=data_dir)
        self.rulebook = Rulebook(data_dir=data_dir)
        self.strategy = StrategyEngine(
            config, learner=self.learner, pattern_miner=self.pattern_miner
        )

        # Session tracking
        self.session_tracker = SessionTracker(saves_dir=self.saves_dir)

        # Per-scan state
        self._reporter: Optional[Reporter] = None
        self._bottleneck: Optional[BottleneckDetector] = None
        self._loaded_modules: Dict[str, Any] = {}

    def scan(
        self,
        target_url: str,
        modules: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        output_json: bool = False,
        ask: str = None,
    ) -> dict:
        """
        Run a full scan against a target.

        Args:
            target_url: Target URL
            modules: Optional list of specific modules to run
            session_id: Optional existing session ID to continue
            output_json: If True, print JSON output instead of terminal UI

        Returns:
            Dict with flags, module_results, recon_data, session_dir, stats
        """
        scan_start = time.time()

        # ── 1. Session Setup ───────────────────────────────────────────────
        sid = self.session_tracker.get_or_create(target_url, session_id)
        session_dir = self.session_tracker.get_session_dir(sid)
        self._reporter = Reporter(session_dir=session_dir)
        self._bottleneck = BottleneckDetector(self.config, session_dir=session_dir)

        self._reporter.info(f"Target: {target_url}")
        self._reporter.info(f"Session: {sid}")

        # ── 2. Reconnaissance ──────────────────────────────────────────────
        self._reporter.recon("Starting reconnaissance...")
        recon = Recon(self.session, flag_hunter=self.flag_hunter)
        recon_data = recon.run(target_url)

        recon_summary = recon.summarize(recon_data)
        for line in recon_summary.split("\n"):
            self._reporter.recon(line)
            
        semantic_answer = {}
        if ask:
            self._reporter.recon(f"Initializing Semantic Brain for question: {ask}")
            try:
                resp = self.session.get(target_url)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "lxml")
                dom_text = soup.get_text(separator=' ', strip=True)
                
                from core.semantic_brain import SemanticBrain
                sb = SemanticBrain()
                semantic_answer = sb.ask(dom_text, ask)
                if semantic_answer and semantic_answer.get("answer"):
                    self._reporter.recon(f"[SEMANTIC BRAIN] 💡 A: {semantic_answer['answer']} (Conf: {semantic_answer.get('score', 0):.2%})")
                else:
                    self._reporter.recon(f"[SEMANTIC BRAIN] 💡 A: No answer found in DOM.")
            except Exception as e:
                import traceback
                self._reporter.recon(f"[!] Failed to run Semantic Brain: {e}\n{traceback.format_exc()}")

        # Build target context for learning
        target_context = TargetContext.from_recon(target_url, recon_data)
        ctx_dict = {
            "url": target_context.url,
            "domain": target_context.domain,
            "tech": target_context.tech,
            "has_login_form": target_context.has_login_form,
            "has_upload_form": target_context.has_upload_form,
            "has_file_param": target_context.has_file_param,
            "has_id_param": target_context.has_id_param,
            "has_url_param": target_context.has_url_param,
            "has_cmd_param": target_context.has_cmd_param,
            "cookies": target_context.cookies,
            "interesting_paths": target_context.interesting_paths,
        }

        # Recon flags
        recon_flags = recon_data.get("flags_found", [])
        for flag_str in recon_flags:
            self._reporter.flag(flag_str)

        for path_key, path_info in recon_data.get("interesting_paths", {}).items():
            if isinstance(path_info, dict):
                for flag_str in path_info.get("flags", []):
                    self._reporter.flag(flag_str)
                    recon_flags.append(flag_str)

        self._save_json(session_dir, "recon_data.json", recon_data)

        # ── 3. Strategy ────────────────────────────────────────────────────
        strategy_result = self.strategy.get_suggested_order(recon_data)
        module_order = strategy_result["suggested_order"]
        recommended_order = list(module_order)

        # Record recon + strategy in session tracker
        self.session_tracker.record_recon(sid, recon_data, recommended_order)

        # Apply rulebook boosts
        rulebook_boosts = self.rulebook.apply_to_strategy()
        if rulebook_boosts:
            self._reporter.recon(f"Rulebook boosts: {rulebook_boosts}")

        # Filter to requested modules
        if modules:
            module_order = [m for m in module_order if m in modules]
            # Also add requested modules not in strategy order
            for m in modules:
                if m not in module_order:
                    module_order.append(m)

        self._reporter.recon(f"Module order: {' -> '.join(module_order)}")

        tier_info = strategy_result.get("tier_info", {})
        self._reporter.recon(f"Strategy: {tier_info.get('dominant_tier', 'unknown')}")

        # ── 4. Module Loop ─────────────────────────────────────────────────
        all_results: List[dict] = []
        all_flags: List[str] = list(recon_flags)
        flag_found = bool(recon_flags)
        prev_module = ""
        prev_result = ""

        for seq_pos, module_name in enumerate(module_order, 1):
            if flag_found and self.config.get("stop_on_flag", True):
                self._reporter.info("Flag found, skipping remaining modules")
                break

            if self._bottleneck.is_stuck(module_name, target_url):
                self._reporter.skip(module_name, "previously bottlenecked")
                continue

            module_instance = self._load_module(module_name)
            if module_instance is None:
                self._reporter.skip(module_name, "module not available")
                continue

            # Detect override
            source = self.session_tracker.detect_override(sid, module_name)
            if source == "agent_override":
                self._reporter.recon(f"Override detected: {module_name} (agent chose instead of strategy)")

            # Run the module
            self._reporter.scan(module_name, "starting")
            module_result = self._run_module(module_instance, target_url, recon_data)

            # Determine result string
            if module_result.found_flag:
                result_str = "flag_found"
            elif module_result.has_findings:
                result_str = "findings"
            elif module_result.skipped:
                result_str = "skipped"
            else:
                result_str = "no_findings"

            # Process and log results with context
            result_dict = self._process_module_result(
                module_name=module_name,
                result=module_result,
                target_url=target_url,
                session_id=sid,
                target_context=ctx_dict,
                source=source,
                sequence_position=seq_pos,
                previous_module=prev_module,
                previous_result=prev_result,
            )
            all_results.append(result_dict)

            # Record in session tracker
            self.session_tracker.record_attack(
                session_id=sid,
                module_name=module_name,
                result=result_str,
                findings_count=len(module_result.findings),
                flag=module_result.found_flag or "",
            )

            # Check for flags
            module_flag = module_result.found_flag
            if module_flag:
                all_flags.append(module_flag)
                self._reporter.flag(module_flag)
                flag_found = True

            session_flags = self.session.found_flags
            for sf in session_flags:
                if sf not in all_flags:
                    all_flags.append(sf)
                    self._reporter.flag(sf)
                    flag_found = True

            # Report
            if module_result.has_findings:
                self._reporter.scan(
                    module_name, "complete",
                    f"findings={len(module_result.findings)} "
                    f"duration={module_result.duration_seconds:.1f}s"
                )
            else:
                self._reporter.scan(module_name, "complete", "no findings")

            self._reporter.save_intermediate()

            prev_module = module_name
            prev_result = result_str

        # ── 5. Post-Scan ───────────────────────────────────────────────────
        scan_duration = time.time() - scan_start

        # Mine patterns from accumulated experience
        entries = self.learner.get_all_entries()
        new_patterns = self.pattern_miner.mine_all(entries)
        if new_patterns:
            self._reporter.recon(f"Mined {len(new_patterns)} new patterns")

        # Decay old patterns
        self.pattern_miner.decay_confidence()

        # Generate rules from history
        new_rule_ids = self.rulebook.generate_rules_from_history(self.learner)
        if new_rule_ids:
            self._reporter.recon(f"Generated {len(new_rule_ids)} new rules")

        # Complete session
        self.session_tracker.complete_session(sid)

        # Final stats
        session_summary = self.session_tracker.get_session_summary(sid)
        stats = {
            "target": target_url,
            "session_id": sid,
            "duration_seconds": round(scan_duration, 2),
            "modules_run": len(all_results),
            "total_findings": sum(r.get("findings_count", 0) for r in all_results),
            "flags_found": len(all_flags),
            "flags": all_flags,
            "overrides_detected": session_summary.get("overrides_detected", 0),
            "bottlenecks": len(self._bottleneck.get_bottlenecks()),
            "requests_made": self.session.request_count,
            "strategy_tier": tier_info.get("dominant_tier", "unknown"),
        }

        self._reporter.done(stats)

        self._save_json(session_dir, "scan_results.json", {
            "stats": stats,
            "module_results": all_results,
            "flags": all_flags,
            "recommended_order": recommended_order,
        })

        return {
            "flags": all_flags,
            "module_results": all_results,
            "recon_data": recon_data,
            "session_id": sid,
            "session_dir": str(session_dir),
            "stats": stats,
        }

    # ── Single Module Attack (for agent CLI) ───────────────────────────────

    def attack_single(
        self,
        target_url: str,
        module_name: str,
        session_id: Optional[str] = None,
        recon_data: Optional[dict] = None,
    ) -> dict:
        """
        Run a single attack module — used by `main.py attack` CLI.
        Creates/loads session, runs one module, logs with context.

        Returns:
            Dict with module result, flag, session_id, source
        """
        # Session
        sid = self.session_tracker.get_or_create(target_url, session_id)
        session_dir = self.session_tracker.get_session_dir(sid)
        self._reporter = Reporter(session_dir=session_dir)
        self._bottleneck = BottleneckDetector(self.config, session_dir=session_dir)

        # Recon (use provided or run fresh)
        if recon_data is None:
            recon = Recon(self.session, flag_hunter=self.flag_hunter)
            recon_data = recon.run(target_url)

        # Build context
        target_context = TargetContext.from_recon(target_url, recon_data)
        ctx_dict = {
            "url": target_context.url,
            "domain": target_context.domain,
            "tech": target_context.tech,
            "has_login_form": target_context.has_login_form,
            "has_file_param": target_context.has_file_param,
            "has_id_param": target_context.has_id_param,
            "has_url_param": target_context.has_url_param,
            "has_cmd_param": target_context.has_cmd_param,
            "cookies": target_context.cookies,
        }

        # Detect override
        source = self.session_tracker.detect_override(sid, module_name)

        # Get sequence info
        state = self.session_tracker.load_session(sid)
        seq_pos = len(state.actual_order) + 1 if state else 1
        prev_module = state.actual_order[-1] if state and state.actual_order else ""
        prev_result_raw = state.modules_run.get(prev_module, {}) if state else {}
        prev_result = prev_result_raw.get("result", "") if isinstance(prev_result_raw, dict) else ""

        # Load and run module
        module_instance = self._load_module(module_name)
        if module_instance is None:
            return {
                "success": False,
                "error": f"Module '{module_name}' not available",
                "session_id": sid,
            }

        self._reporter.scan(module_name, "starting")
        module_result = self._run_module(module_instance, target_url, recon_data)

        # Determine result
        if module_result.found_flag:
            result_str = "flag_found"
        elif module_result.has_findings:
            result_str = "findings"
        else:
            result_str = "no_findings"

        # Log with context
        result_dict = self._process_module_result(
            module_name=module_name,
            result=module_result,
            target_url=target_url,
            session_id=sid,
            target_context=ctx_dict,
            source=source,
            sequence_position=seq_pos,
            previous_module=prev_module,
            previous_result=prev_result,
        )

        # Record in session tracker
        self.session_tracker.record_attack(
            session_id=sid,
            module_name=module_name,
            result=result_str,
            findings_count=len(module_result.findings),
            flag=module_result.found_flag or "",
        )

        if module_result.has_findings:
            self._reporter.scan(module_name, "complete",
                f"findings={len(module_result.findings)}")
        else:
            self._reporter.scan(module_name, "complete", "no findings")

        return {
            "success": module_result.has_findings or bool(module_result.found_flag),
            "module": module_name,
            "source": source,
            "findings_count": len(module_result.findings),
            "flag": module_result.found_flag,
            "session_id": sid,
            "result": result_dict,
        }

    # ── Recon Only (for agent CLI) ─────────────────────────────────────────

    def recon_only(self, target_url: str, ask: str = None) -> dict:
        """
        Run only recon and return structured data + session_id + suggested order.
        """
        sid = self.session_tracker.create_session(target_url)
        session_dir = self.session_tracker.get_session_dir(sid)

        recon = Recon(self.session, flag_hunter=self.flag_hunter)
        recon_data = recon.run(target_url)

        # Get strategy suggestion
        strategy_result = self.strategy.get_suggested_order(recon_data)

        # Record in session
        self.session_tracker.record_recon(
            sid, recon_data, strategy_result["suggested_order"]
        )

        # Build context
        ctx = TargetContext.from_recon(target_url, recon_data)

        self._save_json(session_dir, "recon_data.json", recon_data)
        
        semantic_answer = {}
        if ask:
            try:
                resp = self.session.get(target_url)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "lxml")
                dom_text = soup.get_text(separator=' ', strip=True)
                
                from core.semantic_brain import SemanticBrain
                sb = SemanticBrain()
                semantic_answer = sb.ask(dom_text, ask)
            except Exception as e:
                import traceback
                print(f"[!] Failed to run Semantic Brain: {e}\n{traceback.format_exc()}")

        return {
            "session_id": sid,
            "target_url": target_url,
            "recon_data": recon_data,
            "target_context": {
                "tech": ctx.tech,
                "has_login_form": ctx.has_login_form,
                "has_file_param": ctx.has_file_param,
                "has_id_param": ctx.has_id_param,
                "has_url_param": ctx.has_url_param,
                "has_cmd_param": ctx.has_cmd_param,
                "cookies": ctx.cookies,
                "interesting_paths": ctx.interesting_paths,
            },
            "suggested_order": strategy_result["suggested_order"],
            "strategy_scores": strategy_result["scores"],
            "strategy_tier": strategy_result.get("tier_info", {}),
            "session_dir": str(session_dir),
            "semantic_answer": semantic_answer,
        }

    # ── Module Loading ─────────────────────────────────────────────────────

    def _load_module(self, module_name: str):
        if module_name in self._loaded_modules:
            return self._loaded_modules[module_name]

        if module_name not in MODULE_REGISTRY:
            return None

        module_path, class_name = MODULE_REGISTRY[module_name]
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            instance = cls(self.session, self.flag_hunter, self.config)
            self._loaded_modules[module_name] = instance
            return instance
        except (ImportError, AttributeError):
            return None

    def _run_module(self, module_instance, target_url: str, recon_data: dict) -> ModuleResult:
        module_name = module_instance.name

        should_skip = self._bottleneck.check(
            module_name, target_url, technique="full_scan"
        )
        if should_skip:
            return ModuleResult(module_name=module_name, skipped=True, skip_reason="bottleneck")

        try:
            result = module_instance.run(target_url, recon_data)
        except Exception as e:
            self._bottleneck.check(module_name, target_url, technique="full_scan", error=str(e))
            result = ModuleResult(module_name=module_name)
            result.exploit_results.append(ExploitResult(success=False, error=str(e)))

        return result

    # ── Result Processing ──────────────────────────────────────────────────

    def _process_module_result(
        self,
        module_name: str,
        result: ModuleResult,
        target_url: str,
        session_id: str = "",
        target_context: Optional[dict] = None,
        source: str = "autonomous",
        sequence_position: int = 0,
        previous_module: str = "",
        previous_result: str = "",
    ) -> dict:
        """Process a ModuleResult: log with context to learner, return summary."""
        result_dict = {
            "module": module_name,
            "skipped": result.skipped,
            "skip_reason": result.skip_reason,
            "findings_count": len(result.findings),
            "exploit_count": len(result.exploit_results),
            "duration": result.duration_seconds,
            "flag": result.found_flag,
            "source": source,
            "findings": [],
            "exploits": [],
        }

        for finding in result.findings:
            if self._reporter:
                self._reporter.vuln(finding)
            result_dict["findings"].append({
                "vuln_type": finding.vuln_type,
                "parameter": finding.parameter,
                "method": finding.method,
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "target_url": finding.target_url,
            })

        for exploit_result in result.exploit_results:
            # Context-aware logging to Experience DB v2
            self.learner.log_with_context(
                module=module_name,
                technique=exploit_result.technique,
                success=exploit_result.success,
                session_id=session_id,
                target_context=target_context,
                source=source,
                sequence_position=sequence_position,
                previous_module=previous_module,
                previous_result=previous_result,
                payload=exploit_result.payload_used,
                flag=exploit_result.flag or "",
                error=exploit_result.error or "",
                duration_ms=result.duration_seconds * 1000,
            )

            result_dict["exploits"].append({
                "success": exploit_result.success,
                "technique": exploit_result.technique,
                "flag": exploit_result.flag,
                "error": exploit_result.error,
            })

        return result_dict

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _save_json(self, session_dir: Path, filename: str, data: Any):
        filepath = session_dir / filename
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        except IOError:
            pass

    def get_available_modules(self) -> List[str]:
        available = []
        for name in MODULE_REGISTRY:
            module_path, class_name = MODULE_REGISTRY[name]
            try:
                mod = importlib.import_module(module_path)
                getattr(mod, class_name)
                available.append(name)
            except (ImportError, AttributeError):
                pass
        return available

    def get_all_module_names(self) -> List[str]:
        return list(MODULE_REGISTRY.keys())
