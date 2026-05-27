"""
EnoughOfWeb — Base Exploit Module Interface
All attack modules inherit from BaseExploit.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """A detected vulnerability before exploitation."""
    module: str                  # e.g. "sqli"
    vuln_type: str               # e.g. "union-based"
    target_url: str              # Full URL tested
    parameter: str               # Vulnerable parameter name
    method: str                  # GET / POST
    payload: str                 # Payload that triggered detection
    evidence: str                # Response snippet proving the finding
    severity: Severity = Severity.HIGH
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExploitResult:
    """Result of exploiting a finding."""
    success: bool
    flag: Optional[str] = None
    data_extracted: Optional[str] = None  # Other useful data (tables, users, etc.)
    payload_used: str = ""
    technique: str = ""
    raw_response: str = ""
    error: Optional[str] = None


@dataclass
class ModuleResult:
    """Overall result from running a module against a target."""
    module_name: str
    findings: List[Finding] = field(default_factory=list)
    exploit_results: List[ExploitResult] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    duration_seconds: float = 0.0

    @property
    def found_flag(self) -> Optional[str]:
        for r in self.exploit_results:
            if r.flag:
                return r.flag
        return None

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


class BaseExploit:
    """
    Base class for all attack modules.
    Subclasses MUST implement detect() and exploit().

    WAF-Aware: Includes automatic payload mutation when WAF blocking is
    detected. Use _send_with_waf_retry() instead of _send_payload() to
    enable auto-evasion.
    """

    name: str = "base"
    description: str = "Base exploit module"
    priority: int = 99  # Lower = higher priority

    def __init__(self, session, flag_hunter, config: dict):
        """
        Args:
            session:     CTFSession instance for making HTTP requests
            flag_hunter: FlagHunter instance for extracting flags from responses
            config:      Global config dict
        """
        self.session = session
        self.flag_hunter = flag_hunter
        self.config = config

        # WAF detection & payload mutation
        from core.mutator import WAFDetector, PayloadMutator
        self._waf_detector = WAFDetector()
        self._mutator = PayloadMutator()
        self._waf_retry_limit = config.get("waf_retry_limit", 5)
        self._waf_stats = {"detected": 0, "bypassed": 0, "failed": 0}

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        """
        Scan the target for this vulnerability type.

        Args:
            target_url: Base URL to scan
            recon_data: Dict from recon phase (forms, params, technology, etc.)

        Returns:
            List of Finding objects for each discovered vulnerability
        """
        raise NotImplementedError

    def exploit(self, finding: Finding) -> ExploitResult:
        """
        Attempt to exploit a detected vulnerability.

        Args:
            finding: A Finding object from detect()

        Returns:
            ExploitResult with flag if found
        """
        raise NotImplementedError

    def run(self, target_url: str, recon_data: dict) -> ModuleResult:
        """
        Full pipeline: detect -> exploit. Called by Scanner.
        """
        import time
        start = time.time()
        result = ModuleResult(module_name=self.name)

        try:
            findings = self.detect(target_url, recon_data)
            result.findings = findings

            for finding in findings:
                exploit_result = self.exploit(finding)
                result.exploit_results.append(exploit_result)

                # Stop on first flag
                if exploit_result.flag:
                    break

        except Exception as e:
            result.exploit_results.append(
                ExploitResult(success=False, error=str(e))
            )

        result.duration_seconds = time.time() - start

        # Attach WAF stats to result
        if self._waf_stats["detected"] > 0:
            result.exploit_results.append(
                ExploitResult(
                    success=False,
                    error=None,
                    technique="waf_stats",
                    raw_response=(
                        f"WAF detected: {self._waf_stats['detected']} times, "
                        f"bypassed: {self._waf_stats['bypassed']}, "
                        f"failed: {self._waf_stats['failed']}"
                    ),
                )
            )

        return result

    def _request(self, method: str, url: str, **kwargs):
        """Shortcut for session requests with flag checking built in."""
        resp = self.session.request(method, url, **kwargs)
        return resp

    def _check_flag(self, text: str) -> Optional[str]:
        """Check text for flags."""
        flags = self.flag_hunter.search(text)
        return flags[0] if flags else None

    # ── WAF-Aware Methods ──────────────────────────────────────────────

    def _send_with_waf_retry(
        self,
        send_fn,
        payload: str,
        context: str = "sql",
        target_url: str = "",
        max_retries: int = None,
    ):
        """
        Send a payload using send_fn. If WAF blocks, auto-mutate and retry.

        Args:
            send_fn: Callable that takes a payload string and returns a
                     response (or None). Signature: send_fn(payload) -> response
            payload: Original payload string
            context: "sql", "xss", "ssti", "lfi", "cmdi"
            target_url: Target URL for strategy tracking
            max_retries: Override default retry limit

        Returns:
            (response, used_payload, was_mutated)
            - response: The successful response (or last failed one)
            - used_payload: The payload that got through
            - was_mutated: True if a mutation was needed
        """
        if max_retries is None:
            max_retries = self._waf_retry_limit

        # Try original first
        resp = send_fn(payload)

        is_blocked, reason = self._waf_detector.is_waf_response(resp)
        if not is_blocked:
            return resp, payload, False

        # WAF detected!
        self._waf_stats["detected"] += 1
        self._waf_detector.mark_url(target_url)

        # Generate mutations
        variants = self._mutator.mutate(
            payload,
            max_variants=max_retries,
            context=context,
            target_url=target_url,
        )

        # Try each mutation
        for variant in variants:
            resp = send_fn(variant)
            is_blocked, _ = self._waf_detector.is_waf_response(resp)

            if not is_blocked:
                # Mutation worked!
                self._waf_stats["bypassed"] += 1
                # Record which strategy worked
                strategy_name = self._guess_strategy(payload, variant)
                self._mutator.record_success(target_url, strategy_name)
                return resp, variant, True

        # All mutations failed
        self._waf_stats["failed"] += 1
        return resp, payload, False

    def _is_waf_blocked(self, response) -> bool:
        """Quick check if a response is WAF-blocked."""
        is_blocked, _ = self._waf_detector.is_waf_response(response)
        return is_blocked

    @property
    def waf_stats(self) -> dict:
        """Get WAF interaction statistics."""
        return dict(self._waf_stats)

    @staticmethod
    def _guess_strategy(original: str, mutated: str) -> str:
        """Guess which mutation strategy produced the variant."""
        if "/**/" in mutated and "/**/" not in original:
            return "comment_insert"
        if "%25" in mutated:
            return "double_url_encode"
        if "%27" in mutated or "%3C" in mutated:
            return "url_encode"
        if "%00" in mutated:
            return "null_byte"
        if "%09" in mutated or "%0a" in mutated:
            return "whitespace_sub"
        if "0x" in mutated and "0x" not in original:
            return "hex_encode"
        if "CHAR(" in mutated and "CHAR(" not in original:
            return "hex_encode"
        # Check case alternation
        alpha_orig = [c for c in original if c.isalpha()]
        alpha_mut = [c for c in mutated if c.isalpha()]
        if alpha_orig and alpha_mut and len(alpha_orig) == len(alpha_mut):
            case_changes = sum(1 for a, b in zip(alpha_orig, alpha_mut) if a != b)
            if case_changes > len(alpha_orig) * 0.3:
                return "case_alternate"
        return "mixed_combo"

    def __repr__(self):
        return f"<{self.__class__.__name__} priority={self.priority}>"

