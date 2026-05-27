"""
Minimal vulnerable test server for EnoughOfWeb testing.
Intentionally has: SQL error reflection, SSTI-like response, login form,
id parameter, file parameter — just enough to exercise the scanner pipeline.
"""

import http.server
import urllib.parse
import json

HOST, PORT = "127.0.0.1", 9999

HTML_INDEX = """<!DOCTYPE html>
<html>
<head><title>VulnApp - Test Target</title></head>
<body>
<h1>VulnApp CTF Challenge</h1>
<nav>
  <a href="/login">Login</a> |
  <a href="/search?q=test">Search</a> |
  <a href="/profile?id=1">Profile</a> |
  <a href="/view?file=about.txt">View File</a> |
  <a href="/api/users">API</a>
</nav>
<p>Welcome to the vulnerable test application.</p>
<p>Sistem istatistikleri: Bugüne kadar 15000 dosya transfer edilmiştir. Sistem durumu aktif.</p>
<!-- TODO: remove debug flag -->
</body>
</html>"""

HTML_LOGIN = """<!DOCTYPE html>
<html><head><title>Login - VulnApp</title></head>
<body>
<h1>Login</h1>
<form method="POST" action="/login">
  <input type="text" name="username" placeholder="Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Login</button>
</form>
</body></html>"""

HTML_SEARCH = """<!DOCTYPE html>
<html><head><title>Search - VulnApp</title>
<meta name="generator" content="PHP/8.2">
</head>
<body>
<h1>Search Results</h1>
<form method="GET" action="/search">
  <input type="text" name="q" value="{query}">
  <button>Search</button>
</form>
<p>Results for: {query}</p>
{error}
</body></html>"""

HTML_PROFILE = """<!DOCTYPE html>
<html><head><title>Profile - VulnApp</title></head>
<body>
<h1>User Profile</h1>
<p>User ID: {uid}</p>
<p>Username: user_{uid}</p>
<p>Email: user_{uid}@vulnapp.local</p>
</body></html>"""

HTML_VIEW = """<!DOCTYPE html>
<html><head><title>View File - VulnApp</title></head>
<body>
<h1>File Viewer</h1>
<p>Viewing: {filename}</p>
<pre>{content}</pre>
</body></html>"""


class VulnHandler(http.server.BaseHTTPRequestHandler):
    """Intentionally vulnerable request handler."""

    server_version = "Apache/2.4.41"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/":
            self._respond(200, HTML_INDEX, headers={
                "X-Powered-By": "PHP/8.2",
                "Set-Cookie": "PHPSESSID=abc123; Path=/",
            })

        elif parsed.path == "/login":
            self._respond(200, HTML_LOGIN)

        elif parsed.path == "/search":
            query = params.get("q", [""])[0]
            error = ""
            # Simulate SQL error on single quote
            if "'" in query:
                error = ('<div class="error">MySQL Error: You have an error in your SQL syntax; '
                         'check the manual near \'' + query + '\' at line 1</div>')
            # Simulate SSTI
            if "{{" in query and "}}" in query:
                if "7*7" in query:
                    query = query.replace("{{7*7}}", "49")
                if "7*'7'" in query:
                    query = query.replace("{{7*'7'}}", "7777777")
            self._respond(200, HTML_SEARCH.format(query=query, error=error))

        elif parsed.path == "/profile":
            uid = params.get("id", ["1"])[0]
            self._respond(200, HTML_PROFILE.format(uid=uid))

        elif parsed.path == "/view":
            filename = params.get("file", [""])[0]
            content = "File not found"
            if filename == ".env" or ".env" in filename:
                content = "DB_HOST=localhost\nDB_USER=root\nDB_PASS=secret123\n"
            elif "etc/passwd" in filename or ".." in filename:
                content = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
                if "../../../" in filename:
                    content += "\nFLAG{lfi_path_traversal_win}"
            elif filename == "about.txt":
                content = "VulnApp v1.0 — A test application."
            self._respond(200, HTML_VIEW.format(filename=filename, content=content))

        elif parsed.path == "/api/users":
            self._respond(200, json.dumps([
                {"id": 1, "username": "admin", "role": "admin"},
                {"id": 2, "username": "user", "role": "user"},
            ]), content_type="application/json")

        elif parsed.path == "/robots.txt":
            self._respond(200, "User-agent: *\nDisallow: /admin\nDisallow: /backup\n",
                          content_type="text/plain")

        elif parsed.path == "/admin":
            self._respond(403, "<h1>403 Forbidden</h1><p>Admin access only</p>")

        elif parsed.path == "/.env":
            self._respond(200, "DB_HOST=localhost\nDB_USER=root\nDB_PASS=secret123\n",
                          content_type="text/plain")

        else:
            self._respond(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        params = urllib.parse.parse_qs(body)

        if self.path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            # SQLi bypass
            if "' OR " in username.upper() or "' OR " in password.upper():
                self._respond(200, "<h1>Welcome admin!</h1><p>FLAG{sqli_auth_bypass}</p>")
            elif username == "admin" and password == "secret":
                self._respond(302, "", headers={"Location": "/admin"})
            elif username == "root" and password == "secret123":
                self._respond(302, "", headers={"Location": "/admin"})
            elif username == "admin" and password == "admin123":
                self._respond(302, "", headers={"Location": "/admin"})
            else:
                self._respond(401, "<h1>Login Failed</h1><p>Invalid credentials</p>")
        else:
            self._respond(404, "<h1>404</h1>")

    def _respond(self, code, body, content_type="text/html", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", self.server_version)
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        pass  # Suppress request logging


if __name__ == "__main__":
    server = http.server.HTTPServer((HOST, PORT), VulnHandler)
    print(f"[TEST] Vulnerable server running on http://{HOST}:{PORT}")
    print(f"[TEST] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[TEST] Server stopped")
