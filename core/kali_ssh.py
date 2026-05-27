"""
EnoughOfWeb — Kali SSH Bridge
SSH connection to Kali Linux for running external pentesting tools.
Gracefully returns None when Kali is not configured.
"""

import json
import re
import shlex
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False


class KaliSSH:
    """
    SSH connection to a Kali Linux instance for running external tools:
    sqlmap, ffuf, sstimap, commix.

    If Kali SSH is not configured or paramiko is unavailable, all methods
    gracefully return None.
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Global config dict with kali_ssh_* keys
        """
        self.config = config
        self.enabled = config.get("kali_ssh_enabled", False)
        self.host = config.get("kali_ssh_host", "")
        self.port = config.get("kali_ssh_port", 22)
        self.user = config.get("kali_ssh_user", "kali")
        self.key_path = config.get("kali_ssh_key", "")
        self.password = config.get("kali_ssh_password", "")
        self.timeout = config.get("timeout", 10)

        self._client: Optional[Any] = None
        self._connected = False

    @property
    def available(self) -> bool:
        """Check if Kali SSH is configured and usable."""
        return bool(HAS_PARAMIKO and self.enabled and self.host)

    def connect(self) -> bool:
        """
        Establish SSH connection to Kali.

        Returns:
            True if connected successfully, False otherwise
        """
        if not self.available:
            return False

        if self._connected:
            return True

        try:
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs: Dict[str, Any] = {
                "hostname": self.host,
                "port": self.port,
                "username": self.user,
                "timeout": self.timeout,
            }

            if self.key_path:
                key_file = Path(self.key_path).expanduser()
                if key_file.exists():
                    connect_kwargs["key_filename"] = str(key_file)
                else:
                    return False
            elif self.password:
                connect_kwargs["password"] = self.password
            else:
                return False

            self._client.connect(**connect_kwargs)
            self._connected = True
            return True

        except Exception:
            self._connected = False
            self._client = None
            return False

    def disconnect(self):
        """Close the SSH connection."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            finally:
                self._client = None
                self._connected = False

    def run_command(self, cmd: str, timeout: int = 120) -> Optional[str]:
        """
        Execute a command on the Kali machine.

        Args:
            cmd:     Shell command to run
            timeout: Command timeout in seconds

        Returns:
            stdout as string, or None on failure
        """
        if not self._connected:
            if not self.connect():
                return None

        try:
            stdin, stdout, stderr = self._client.exec_command(cmd, timeout=timeout)
            output = stdout.read().decode("utf-8", errors="replace")
            err_output = stderr.read().decode("utf-8", errors="replace")

            # Return combined output, prioritizing stdout
            if output.strip():
                return output
            if err_output.strip():
                return err_output
            return ""

        except Exception:
            return None

    # ── Tool-Specific Methods ──────────────────────────────────────────────

    def run_sqlmap(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        extra_args: str = "",
        timeout: int = 180,
    ) -> Optional[dict]:
        """
        Run sqlmap against a target URL.

        Args:
            url:        Target URL (with or without query params)
            params:     Dict of parameters to test (for GET)
            data:       POST data string
            extra_args: Additional sqlmap arguments
            timeout:    Command timeout

        Returns:
            Dict with keys: vulnerable, dbms, databases, tables, data, raw_output
            None if Kali unavailable
        """
        if not self.available:
            return None

        cmd_parts = ["sqlmap", "-u", shlex.quote(url), "--batch", "--flush-session"]

        if data:
            cmd_parts.extend(["--data", shlex.quote(data)])

        if params:
            param_str = ",".join(params.keys())
            cmd_parts.extend(["-p", param_str])

        # Try to dump basic info
        cmd_parts.extend([
            "--dbs",
            "--level", "2",
            "--risk", "2",
            "--threads", "4",
        ])

        if extra_args:
            cmd_parts.append(extra_args)

        cmd = " ".join(cmd_parts)
        output = self.run_command(cmd, timeout=timeout)

        if output is None:
            return None

        return self._parse_sqlmap_output(output)

    def run_ffuf(
        self,
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extra_args: str = "",
        timeout: int = 120,
    ) -> Optional[dict]:
        """
        Run ffuf for directory/file fuzzing.

        Args:
            url:       Target URL with FUZZ keyword (e.g. http://target/FUZZ)
            wordlist:  Path to wordlist on Kali
            extra_args: Additional ffuf arguments
            timeout:   Command timeout

        Returns:
            Dict with keys: found_paths (list of {path, status, size}), raw_output
            None if Kali unavailable
        """
        if not self.available:
            return None

        # Ensure URL has FUZZ keyword
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"

        cmd_parts = [
            "ffuf",
            "-u", shlex.quote(url),
            "-w", shlex.quote(wordlist),
            "-mc", "200,204,301,302,307,401,403",
            "-o", "/tmp/ffuf_out.json",
            "-of", "json",
            "-s",  # Silent mode
        ]

        if extra_args:
            cmd_parts.append(extra_args)

        cmd = " ".join(cmd_parts)
        self.run_command(cmd, timeout=timeout)

        # Read JSON output
        json_output = self.run_command("cat /tmp/ffuf_out.json 2>/dev/null", timeout=10)
        self.run_command("rm -f /tmp/ffuf_out.json", timeout=5)

        if json_output is None:
            return None

        return self._parse_ffuf_output(json_output)

    def run_sstimap(
        self,
        url: str,
        param: str = "",
        extra_args: str = "",
        timeout: int = 120,
    ) -> Optional[dict]:
        """
        Run SSTImap for Server-Side Template Injection testing.

        Args:
            url:        Target URL
            param:      Parameter to test (e.g. "name")
            extra_args: Additional sstimap arguments
            timeout:    Command timeout

        Returns:
            Dict with keys: vulnerable, engine, os_shell, raw_output
            None if Kali unavailable
        """
        if not self.available:
            return None

        cmd_parts = ["python3", "-m", "sstimap", "-u", shlex.quote(url)]

        if param:
            # sstimap auto-detects params from URL, but we can force one
            # by ensuring the URL has the param
            if f"{param}=" not in url:
                separator = "&" if "?" in url else "?"
                url = f"{url}{separator}{param}=SSTI"
                cmd_parts = ["python3", "-m", "sstimap", "-u", shlex.quote(url)]

        cmd_parts.extend(["--level", "2"])

        if extra_args:
            cmd_parts.append(extra_args)

        cmd = " ".join(cmd_parts)
        output = self.run_command(cmd, timeout=timeout)

        if output is None:
            return None

        return self._parse_sstimap_output(output)

    def run_commix(
        self,
        url: str,
        param: str = "",
        data: Optional[str] = None,
        extra_args: str = "",
        timeout: int = 120,
    ) -> Optional[dict]:
        """
        Run commix for OS command injection testing.

        Args:
            url:        Target URL
            param:      Parameter to test
            data:       POST data string
            extra_args: Additional commix arguments
            timeout:    Command timeout

        Returns:
            Dict with keys: vulnerable, technique, os_info, raw_output
            None if Kali unavailable
        """
        if not self.available:
            return None

        cmd_parts = ["commix", "-u", shlex.quote(url), "--batch"]

        if data:
            cmd_parts.extend(["--data", shlex.quote(data)])

        if param:
            cmd_parts.extend(["-p", param])

        cmd_parts.extend(["--level", "2"])

        if extra_args:
            cmd_parts.append(extra_args)

        cmd = " ".join(cmd_parts)
        output = self.run_command(cmd, timeout=timeout)

        if output is None:
            return None

        return self._parse_commix_output(output)

    # ── Output Parsers ─────────────────────────────────────────────────────

    def _parse_sqlmap_output(self, output: str) -> dict:
        """Parse sqlmap output into structured dict."""
        result = {
            "vulnerable": False,
            "dbms": "",
            "databases": [],
            "tables": [],
            "data": [],
            "injection_type": "",
            "raw_output": output,
        }

        if not output:
            return result

        # Check for vulnerability confirmation
        if any(marker in output for marker in [
            "is vulnerable",
            "injectable",
            "confirmed that",
            "Type: ",
        ]):
            result["vulnerable"] = True

        # Extract DBMS
        dbms_match = re.search(r"back-end DBMS:\s*(.+)", output)
        if dbms_match:
            result["dbms"] = dbms_match.group(1).strip()

        # Extract injection type
        type_match = re.search(r"Type:\s*(.+)", output)
        if type_match:
            result["injection_type"] = type_match.group(1).strip()

        # Extract databases
        db_section = re.search(r"available databases.*?\n((?:\[\*\]\s+.+\n?)+)", output, re.DOTALL)
        if db_section:
            dbs = re.findall(r"\[\*\]\s+(.+)", db_section.group(1))
            result["databases"] = [d.strip() for d in dbs]

        # Extract tables
        table_matches = re.findall(r"\|\s+(\S+)\s+\|", output)
        if table_matches:
            result["tables"] = list(set(table_matches))

        return result

    def _parse_ffuf_output(self, output: str) -> dict:
        """Parse ffuf JSON output into structured dict."""
        result = {
            "found_paths": [],
            "raw_output": output,
        }

        if not output:
            return result

        try:
            data = json.loads(output)
            results = data.get("results", [])
            for entry in results:
                result["found_paths"].append({
                    "path": entry.get("input", {}).get("FUZZ", entry.get("url", "")),
                    "status": entry.get("status", 0),
                    "size": entry.get("length", 0),
                    "words": entry.get("words", 0),
                    "lines": entry.get("lines", 0),
                    "url": entry.get("url", ""),
                })
        except (json.JSONDecodeError, TypeError, KeyError):
            # Fall back to line-by-line parsing for non-JSON output
            for line in output.splitlines():
                match = re.match(
                    r".*?(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
                    line,
                )
                if match:
                    result["found_paths"].append({
                        "path": match.group(1),
                        "status": int(match.group(2)),
                        "size": int(match.group(3)),
                    })

        return result

    def _parse_sstimap_output(self, output: str) -> dict:
        """Parse SSTImap output into structured dict."""
        result = {
            "vulnerable": False,
            "engine": "",
            "os_shell": False,
            "raw_output": output,
        }

        if not output:
            return result

        # Check for confirmed SSTI
        if any(marker in output.lower() for marker in [
            "confirmed",
            "injection point found",
            "identified the following injection point",
            "template engine:",
        ]):
            result["vulnerable"] = True

        # Extract template engine
        engine_match = re.search(
            r"(?:template engine|engine):\s*(.+)",
            output,
            re.IGNORECASE,
        )
        if engine_match:
            result["engine"] = engine_match.group(1).strip()

        # Check for OS shell capability
        if any(marker in output.lower() for marker in [
            "os shell",
            "command execution",
            "rce",
        ]):
            result["os_shell"] = True

        return result

    def _parse_commix_output(self, output: str) -> dict:
        """Parse commix output into structured dict."""
        result = {
            "vulnerable": False,
            "technique": "",
            "os_info": "",
            "raw_output": output,
        }

        if not output:
            return result

        # Check for vulnerability
        if any(marker in output.lower() for marker in [
            "is vulnerable",
            "injectable",
            "the target is vulnerable",
        ]):
            result["vulnerable"] = True

        # Extract technique
        tech_match = re.search(
            r"(?:technique|injection type):\s*(.+)",
            output,
            re.IGNORECASE,
        )
        if tech_match:
            result["technique"] = tech_match.group(1).strip()

        # Extract OS info
        os_match = re.search(
            r"(?:operating system|os):\s*(.+)",
            output,
            re.IGNORECASE,
        )
        if os_match:
            result["os_info"] = os_match.group(1).strip()

        return result

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def __del__(self):
        self.disconnect()
