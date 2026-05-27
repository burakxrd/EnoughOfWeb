"""
EnoughOfWeb — Flag Hunter
Extracts flags from response body, headers, cookies, and encoded content.
"""

import re
import base64
from typing import List, Optional


# Well-known CTF flag patterns
BUILTIN_PATTERNS = [
    r"flag\{[^\}]+\}",
    r"FLAG\{[^\}]+\}",
    r"CTF\{[^\}]+\}",
    r"ctf\{[^\}]+\}",
    r"HTB\{[^\}]+\}",
    r"THM\{[^\}]+\}",
    r"picoCTF\{[^\}]+\}",
    r"FLAG\{[^\}]+\}",
]


class FlagHunter:
    """
    Searches every surface of an HTTP response for CTF flags.
    Supports custom regex, base64 decoding, and multi-format extraction.
    """

    def __init__(self, custom_pattern: Optional[str] = None):
        """
        Args:
            custom_pattern: Regex pattern for flags. If provided, used as primary.
                            Built-in patterns are always checked as fallback.
        """
        self.patterns = []
        if custom_pattern:
            self.patterns.append(re.compile(custom_pattern, re.IGNORECASE))
        for p in BUILTIN_PATTERNS:
            self.patterns.append(re.compile(p))

    def search(self, text: str) -> List[str]:
        """Search a string for flags."""
        found = []
        for pattern in self.patterns:
            matches = pattern.findall(text)
            found.extend(matches)
        return list(set(found))

    def search_response(self, response) -> List[str]:
        """
        Search an entire HTTP response: body, headers, cookies, base64 content.

        Args:
            response: requests.Response object

        Returns:
            List of unique flag strings found
        """
        found = []

        # 1. Response body
        found.extend(self.search(response.text))

        # 2. Headers
        for name, value in response.headers.items():
            found.extend(self.search(value))

        # 3. Cookies
        for cookie in response.cookies:
            found.extend(self.search(cookie.name))
            found.extend(self.search(cookie.value))

        # 4. HTML comments (sometimes flags hide here)
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        for comment in comment_pattern.findall(response.text):
            found.extend(self.search(comment))

        # 5. Base64 encoded content
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        for b64_match in b64_pattern.findall(response.text):
            try:
                decoded = base64.b64decode(b64_match).decode("utf-8", errors="ignore")
                found.extend(self.search(decoded))
            except Exception:
                pass

        # 6. JavaScript variables (var flag = "...", const flag = "...")
        js_pattern = re.compile(r'(?:var|let|const)\s+\w*[Ff]lag\w*\s*=\s*["\']([^"\']+)["\']')
        for js_match in js_pattern.findall(response.text):
            found.extend(self.search(js_match))

        return list(set(found))

    def search_text_deep(self, text: str) -> List[str]:
        """
        Deep search: tries base64 decode, hex decode, URL decode on the text.
        Use this for command output, file contents, etc.
        """
        found = self.search(text)

        # Base64
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8", errors="ignore")
            found.extend(self.search(decoded))
        except Exception:
            pass

        # Hex
        try:
            hex_clean = text.strip().replace("0x", "").replace(" ", "")
            decoded = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
            found.extend(self.search(decoded))
        except Exception:
            pass

        # URL decode
        try:
            from urllib.parse import unquote
            decoded = unquote(text)
            found.extend(self.search(decoded))
        except Exception:
            pass

        return list(set(found))
