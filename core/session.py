"""
EnoughOfWeb — HTTP Session Manager
Wraps requests.Session with Burp proxy support, auto flag scanning, and logging.
"""

import requests
import urllib3
from typing import Optional, Dict, Any

# Suppress InsecureRequestWarning when SSL verify is off
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CTFSession:
    """
    HTTP session with Burp proxy support and automatic flag scanning.
    Every response is checked for flags.
    """

    def __init__(self, config: dict, flag_hunter=None):
        self.config = config
        self.flag_hunter = flag_hunter
        self.session = requests.Session()
        self.session.trust_env = False  # Ignore OS proxy environment variables
        self._found_flags = []
        self._request_log = []

        # Set User-Agent
        self.session.headers.update({
            "User-Agent": config.get("user_agent", "EnoughOfWeb/1.0")
        })

        # Proxy setup
        if config.get("proxy_enabled"):
            host = config.get("proxy_host", "127.0.0.1")
            port = config.get("proxy_port", 8080)
            self.session.proxies = {
                "http": f"http://{host}:{port}",
                "https": f"http://{host}:{port}",
            }

        # SSL verification
        self.session.verify = config.get("verify_ssl", False)

        # Timeout
        self.timeout = config.get("timeout", 10)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make an HTTP request. Auto-checks response for flags.

        Args:
            method: GET, POST, PUT, etc.
            url:    Target URL
            **kwargs: Passed to requests.Session.request()

        Returns:
            requests.Response
        """
        kwargs.setdefault("timeout", self.timeout)

        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.exceptions.ConnectionError:
            raise ConnectionError(f"Cannot connect to {url}")
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Request to {url} timed out")

        # Log request
        self._request_log.append({
            "method": method,
            "url": url,
            "status": resp.status_code,
            "size": len(resp.content),
        })

        # Auto flag scan
        if self.flag_hunter:
            flags = self.flag_hunter.search_response(resp)
            if flags:
                self._found_flags.extend(flags)

        return resp

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        return self.request("DELETE", url, **kwargs)

    @property
    def found_flags(self) -> list:
        return list(set(self._found_flags))

    @property
    def request_count(self) -> int:
        return len(self._request_log)

    def get_cookies_dict(self) -> Dict[str, str]:
        return dict(self.session.cookies)

    def set_cookie(self, name: str, value: str, domain: str = ""):
        self.session.cookies.set(name, value, domain=domain)

    def set_header(self, name: str, value: str):
        self.session.headers[name] = value

    def reset(self):
        """Clear cookies and session state."""
        self.session.cookies.clear()
        self._found_flags.clear()
        self._request_log.clear()
