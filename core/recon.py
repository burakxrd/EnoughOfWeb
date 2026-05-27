"""
EnoughOfWeb — Reconnaissance Module
Discovers forms, parameters, technology, links, cookies, and interesting paths.
Runs before attack modules to gather intelligence.
"""

import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Any, Optional

from bs4 import BeautifulSoup


# Common paths to probe for interesting resources
INTERESTING_PATHS = [
    ("robots_txt", "/robots.txt"),
    ("sitemap_xml", "/sitemap.xml"),
    ("git_exposed", "/.git/HEAD"),
    ("env_exposed", "/.env"),
    ("admin", "/admin"),
    ("admin_panel", "/admin/"),
    ("login", "/login"),
    ("login_alt", "/signin"),
    ("api", "/api"),
    ("api_docs", "/api/docs"),
    ("swagger", "/swagger.json"),
    ("backup", "/backup"),
    ("backup_zip", "/backup.zip"),
    ("debug", "/debug"),
    ("console", "/console"),
    ("phpmyadmin", "/phpmyadmin"),
    ("wp_admin", "/wp-admin"),
    ("wp_login", "/wp-login.php"),
    ("config_file", "/config.php"),
    ("info_php", "/info.php"),
    ("phpinfo", "/phpinfo.php"),
    ("htaccess", "/.htaccess"),
    ("ds_store", "/.DS_Store"),
    ("web_config", "/web.config"),
    ("server_status", "/server-status"),
    ("graphql", "/graphql"),
    ("flag", "/flag"),
    ("flag_txt", "/flag.txt"),
    ("secret", "/secret"),
]


class Recon:
    """
    Reconnaissance phase: gathers intelligence about a target before attacks.
    Discovers forms, URL parameters, technology stack, links, cookies, and
    checks for interesting/exposed paths.
    """

    def __init__(self, session, flag_hunter=None):
        """
        Args:
            session:     CTFSession instance for making HTTP requests
            flag_hunter: Optional FlagHunter for checking discovered content
        """
        self.session = session
        self.flag_hunter = flag_hunter

    def run(self, target_url: str) -> dict:
        """
        Run full reconnaissance on a target URL.

        Args:
            target_url: Base URL to recon (e.g. http://target.com)

        Returns:
            dict with keys: target_url, base_url, forms, url_params, technology,
            links, interesting_paths, cookies, response_headers, flags_found
        """
        recon_data = {
            "target_url": target_url,
            "base_url": self._get_base_url(target_url),
            "forms": [],
            "url_params": [],
            "technology": {},
            "links": [],
            "interesting_paths": {},
            "cookies": {},
            "response_headers": {},
            "flags_found": [],
            "page_title": "",
            "comments": [],
        }

        # Fetch the main page
        try:
            resp = self.session.get(target_url)
        except Exception:
            return recon_data

        # Parse base response
        recon_data["response_headers"] = dict(resp.headers)
        recon_data["technology"] = self._detect_technology(resp)
        recon_data["cookies"] = self._extract_cookies()

        # Parse HTML
        soup = BeautifulSoup(resp.text, "lxml")
        recon_data["forms"] = self._extract_forms(soup, target_url)
        recon_data["links"] = self._extract_links(soup, target_url)
        recon_data["url_params"] = self._extract_url_params(target_url, soup)
        recon_data["page_title"] = self._extract_title(soup)
        recon_data["comments"] = self._extract_comments(resp.text)

        # Check for flags in main page
        if self.flag_hunter:
            flags = self.flag_hunter.search(resp.text)
            recon_data["flags_found"].extend(flags)

        # Probe interesting paths
        recon_data["interesting_paths"] = self._probe_paths(target_url)

        return recon_data

    # ── Technology Detection ───────────────────────────────────────────────

    def _detect_technology(self, response) -> dict:
        """Detect server technology from response headers and content."""
        tech = {
            "server": "",
            "x_powered_by": "",
            "content_type": "",
            "frameworks": [],
            "language": "",
        }

        headers = response.headers

        # Server header
        tech["server"] = headers.get("Server", "")
        tech["x_powered_by"] = headers.get("X-Powered-By", "")
        tech["content_type"] = headers.get("Content-Type", "")

        server_lower = tech["server"].lower()
        powered_lower = tech["x_powered_by"].lower()

        # Detect language/framework from headers
        if "php" in powered_lower:
            tech["language"] = "PHP"
            tech["frameworks"].append("PHP")
        if "asp.net" in powered_lower:
            tech["language"] = "ASP.NET"
            tech["frameworks"].append("ASP.NET")
        if "express" in powered_lower:
            tech["language"] = "Node.js"
            tech["frameworks"].append("Express")
        if "werkzeug" in server_lower or "flask" in server_lower:
            tech["language"] = "Python"
            tech["frameworks"].append("Flask")
            tech["frameworks"].append("Jinja2")
        if "gunicorn" in server_lower:
            tech["language"] = "Python"
        if "tornado" in server_lower:
            tech["language"] = "Python"
            tech["frameworks"].append("Tornado")
        if "nginx" in server_lower:
            tech["frameworks"].append("Nginx")
        if "apache" in server_lower:
            tech["frameworks"].append("Apache")

        # Detect from cookies
        cookies = self._extract_cookies()
        for name in cookies:
            name_lower = name.lower()
            if name_lower == "phpsessid":
                tech["language"] = tech["language"] or "PHP"
                if "PHP" not in tech["frameworks"]:
                    tech["frameworks"].append("PHP")
            elif name_lower == "connect.sid":
                tech["language"] = tech["language"] or "Node.js"
                if "Express" not in tech["frameworks"]:
                    tech["frameworks"].append("Express")
            elif name_lower in ("csrftoken", "django_session"):
                tech["language"] = tech["language"] or "Python"
                if "Django" not in tech["frameworks"]:
                    tech["frameworks"].append("Django")

        # Detect from response body hints
        body = response.text.lower()
        if "jinja2" in body or "jinja" in body:
            if "Jinja2" not in tech["frameworks"]:
                tech["frameworks"].append("Jinja2")
        if "wp-content" in body or "wordpress" in body:
            if "WordPress" not in tech["frameworks"]:
                tech["frameworks"].append("WordPress")
        if "drupal" in body:
            if "Drupal" not in tech["frameworks"]:
                tech["frameworks"].append("Drupal")

        # Detect from common header patterns
        set_cookie = response.headers.get("Set-Cookie", "")
        if "JSESSIONID" in set_cookie:
            tech["language"] = tech["language"] or "Java"
            if "Java" not in tech["frameworks"]:
                tech["frameworks"].append("Java")
        if "ASP.NET_SessionId" in set_cookie:
            tech["language"] = tech["language"] or "ASP.NET"
            if "ASP.NET" not in tech["frameworks"]:
                tech["frameworks"].append("ASP.NET")

        return tech

    # ── Form Extraction ────────────────────────────────────────────────────

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[dict]:
        """Extract all forms with their actions, methods, and inputs."""
        forms = []

        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url

            method = form_tag.get("method", "GET").upper()

            inputs = []
            for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                input_info = {
                    "name": input_tag.get("name", ""),
                    "type": input_tag.get("type", "text"),
                    "value": input_tag.get("value", ""),
                    "placeholder": input_tag.get("placeholder", ""),
                    "required": input_tag.has_attr("required"),
                }

                # For select elements, grab options
                if input_tag.name == "select":
                    input_info["type"] = "select"
                    options = [
                        opt.get("value", opt.text.strip())
                        for opt in input_tag.find_all("option")
                    ]
                    input_info["options"] = options

                # For textarea
                if input_tag.name == "textarea":
                    input_info["type"] = "textarea"

                if input_info["name"]:
                    inputs.append(input_info)

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
                "id": form_tag.get("id", ""),
                "class": " ".join(form_tag.get("class", [])),
                "enctype": form_tag.get("enctype", ""),
            })

        return forms

    # ── Link Extraction ────────────────────────────────────────────────────

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[dict]:
        """Extract all links from the page."""
        links = []
        seen = set()
        base_domain = urlparse(base_url).netloc

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue

            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)

            # Only include same-domain or relative links
            if parsed.netloc and parsed.netloc != base_domain:
                continue

            if full_url in seen:
                continue
            seen.add(full_url)

            links.append({
                "url": full_url,
                "text": a_tag.get_text(strip=True)[:100],
                "path": parsed.path,
            })

        return links

    # ── Parameter Extraction ───────────────────────────────────────────────

    def _extract_url_params(self, target_url: str, soup: BeautifulSoup) -> List[str]:
        """Extract all unique URL parameter names from the target URL and page links."""
        params = set()

        # From the target URL itself
        parsed = urlparse(target_url)
        query_params = parse_qs(parsed.query)
        params.update(query_params.keys())

        # From all links on the page
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            try:
                parsed_link = urlparse(href)
                link_params = parse_qs(parsed_link.query)
                params.update(link_params.keys())
            except Exception:
                continue

        # From form actions
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            if action:
                try:
                    parsed_action = urlparse(action)
                    action_params = parse_qs(parsed_action.query)
                    params.update(action_params.keys())
                except Exception:
                    continue

        return list(params)

    # ── HTML Comment Extraction ────────────────────────────────────────────

    def _extract_comments(self, html: str) -> List[str]:
        """Extract HTML comments from the page source."""
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        comments = []
        for match in comment_pattern.findall(html):
            comment = match.strip()
            if comment and len(comment) > 2:
                comments.append(comment[:500])  # Cap length
        return comments

    # ── Title Extraction ───────────────────────────────────────────────────

    def _extract_title(self, soup: BeautifulSoup) -> str:
        """Extract page title."""
        title_tag = soup.find("title")
        if title_tag:
            return title_tag.get_text(strip=True)[:200]
        return ""

    # ── Cookie Extraction ──────────────────────────────────────────────────

    def _extract_cookies(self) -> Dict[str, str]:
        """Extract current session cookies."""
        return self.session.get_cookies_dict()

    # ── Path Probing ───────────────────────────────────────────────────────

    def _probe_paths(self, target_url: str) -> dict:
        """
        Check common paths for interesting resources.
        Returns a dict of {path_key: {exists: bool, status: int, content_snippet: str}}
        """
        base_url = self._get_base_url(target_url)
        results = {}

        for key, path in INTERESTING_PATHS:
            probe_url = urljoin(base_url, path)
            try:
                resp = self.session.get(probe_url)
                exists = resp.status_code < 400

                # Check for soft 404s
                if exists and resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if any(phrase in body_lower for phrase in [
                        "not found",
                        "404",
                        "page not found",
                        "does not exist",
                    ]):
                        # Likely a soft 404
                        exists = False

                results[key] = {
                    "exists": exists,
                    "status": resp.status_code,
                    "url": probe_url,
                    "content_snippet": resp.text[:200] if exists else "",
                    "size": len(resp.content),
                }

                # Check for flags in interesting paths
                if exists and self.flag_hunter:
                    flags = self.flag_hunter.search(resp.text)
                    if flags:
                        results[key]["flags"] = flags

            except Exception:
                results[key] = {
                    "exists": False,
                    "status": 0,
                    "url": probe_url,
                    "content_snippet": "",
                    "size": 0,
                }

        return results

    # ── Utilities ──────────────────────────────────────────────────────────

    @staticmethod
    def _get_base_url(url: str) -> str:
        """Extract scheme + netloc from a URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def summarize(self, recon_data: dict) -> str:
        """
        Create a human-readable summary of recon findings.

        Args:
            recon_data: Dict returned by run()

        Returns:
            Formatted summary string
        """
        lines = []

        # Title
        title = recon_data.get("page_title", "")
        if title:
            lines.append(f"Title: {title}")

        # Technology
        tech = recon_data.get("technology", {})
        if tech.get("server"):
            lines.append(f"Server: {tech['server']}")
        if tech.get("x_powered_by"):
            lines.append(f"Powered by: {tech['x_powered_by']}")
        if tech.get("frameworks"):
            lines.append(f"Frameworks: {', '.join(tech['frameworks'])}")
        if tech.get("language"):
            lines.append(f"Language: {tech['language']}")

        # Forms
        forms = recon_data.get("forms", [])
        if forms:
            lines.append(f"Forms: {len(forms)}")
            for f in forms:
                input_names = [i.get("name", "?") for i in f.get("inputs", [])]
                lines.append(f"  {f['method']} {f['action']} → {', '.join(input_names)}")

        # URL params
        params = recon_data.get("url_params", [])
        if params:
            lines.append(f"URL params: {', '.join(params)}")

        # Links
        link_count = len(recon_data.get("links", []))
        if link_count:
            lines.append(f"Links: {link_count}")

        # Interesting paths
        paths = recon_data.get("interesting_paths", {})
        exposed = [k for k, v in paths.items() if v.get("exists")]
        if exposed:
            lines.append(f"Exposed paths: {', '.join(exposed)}")

        # Cookies
        cookies = recon_data.get("cookies", {})
        if cookies:
            lines.append(f"Cookies: {', '.join(cookies.keys())}")

        # Comments
        comments = recon_data.get("comments", [])
        if comments:
            lines.append(f"HTML comments: {len(comments)}")

        # Flags
        flags = recon_data.get("flags_found", [])
        if flags:
            lines.append(f"FLAGS FOUND: {', '.join(flags)}")

        return "\n".join(lines) if lines else "No significant findings"
