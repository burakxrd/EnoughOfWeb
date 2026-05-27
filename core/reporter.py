"""
EnoughOfWeb — Reporter
Agent-friendly, minimalist terminal output with structured prefixes.
Also saves full JSON reports to the session saves/ directory.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from colorama import init as colorama_init, Fore, Style

# Force UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Initialize colorama for Windows compatibility
colorama_init(autoreset=True)


class Reporter:
    """
    Minimalist terminal reporter with agent-parseable prefixes.

    Prefix format:
        [RECON] message                     — Reconnaissance phase
        [SCAN]  module | status | detail    — Module scan progress
        [VULN]  type | severity | target    — Vulnerability found
        [FLAG]  flag_value                  — Flag captured
        [SKIP]  module | reason             — Module skipped (bottleneck)
        [DONE]  summary stats              — Scan complete
        [ERR]   error message               — Error occurred

    Colors:
        Green  = flag, success
        Red    = error
        Yellow = warning, skip, vuln
        Cyan   = info, recon, scan
    """

    def __init__(self, session_dir: Optional[Path] = None, quiet: bool = False):
        """
        Args:
            session_dir: Path to save JSON reports (None = no file output)
            quiet:       If True, suppress terminal output (still saves to file)
        """
        self.session_dir = Path(session_dir) if session_dir else None
        if self.session_dir:
            self.session_dir.mkdir(parents=True, exist_ok=True)
        self.quiet = quiet

        # Accumulate report entries for JSON output
        self._entries: List[dict] = []
        self._flags: List[str] = []
        self._start_time = datetime.now(timezone.utc).isoformat()

    # ── Output Methods ─────────────────────────────────────────────────────

    def recon(self, msg: str):
        """Log a reconnaissance finding."""
        self._log("RECON", msg, Fore.CYAN)

    def scan(self, module: str, status: str, detail: str = ""):
        """Log a module scan event."""
        parts = [module, status]
        if detail:
            parts.append(detail)
        msg = " | ".join(parts)
        self._log("SCAN", msg, Fore.CYAN)

    def vuln(self, finding):
        """
        Log a vulnerability finding.

        Args:
            finding: Finding object or dict with vuln_type, severity, target_url
        """
        if hasattr(finding, "vuln_type"):
            # It's a Finding dataclass
            vuln_type = finding.vuln_type
            severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            target = finding.target_url
            param = finding.parameter
            msg = f"{vuln_type} | {severity} | {target} | param={param}"
        elif isinstance(finding, dict):
            vuln_type = finding.get("vuln_type", "unknown")
            severity = finding.get("severity", "unknown")
            target = finding.get("target_url", "")
            msg = f"{vuln_type} | {severity} | {target}"
        else:
            msg = str(finding)

        self._log("VULN", msg, Fore.YELLOW)

    def flag(self, flag_str: str):
        """Log a captured flag."""
        self._flags.append(flag_str)
        self._log("FLAG", flag_str, Fore.GREEN, bright=True)

    def skip(self, module: str, reason: str):
        """Log a skipped module."""
        msg = f"{module} | {reason}"
        self._log("SKIP", msg, Fore.YELLOW)

    def done(self, stats_dict: Optional[Dict[str, Any]] = None):
        """
        Log scan completion with summary.

        Args:
            stats_dict: Optional dict with summary stats
        """
        if stats_dict:
            parts = [f"{k}={v}" for k, v in stats_dict.items()]
            msg = " | ".join(parts)
        else:
            msg = f"flags={len(self._flags)} entries={len(self._entries)}"

        self._log("DONE", msg, Fore.GREEN, bright=True)

        # Save the full JSON report
        self._save_report(stats_dict)

    def error(self, msg: str):
        """Log an error."""
        self._log("ERR", msg, Fore.RED)

    def info(self, msg: str):
        """Log a general info message."""
        self._log("INFO", msg, Fore.WHITE)

    def warning(self, msg: str):
        """Log a warning."""
        self._log("WARN", msg, Fore.YELLOW)

    # ── Internal ───────────────────────────────────────────────────────────

    def _log(self, prefix: str, msg: str, color: str, bright: bool = False):
        """Format and output a log line."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prefix": prefix,
            "message": msg,
        }
        self._entries.append(entry)

        if not self.quiet:
            style = Style.BRIGHT if bright else ""
            line = f"{color}{style}[{prefix}]{Style.RESET_ALL} {msg}"
            print(line, flush=True)

    # ── Report Saving ──────────────────────────────────────────────────────

    def _save_report(self, stats: Optional[Dict[str, Any]] = None):
        """Save the full report as JSON to the session directory."""
        if not self.session_dir:
            return

        report = {
            "start_time": self._start_time,
            "end_time": datetime.now(timezone.utc).isoformat(),
            "flags": self._flags,
            "stats": stats or {},
            "entries": self._entries,
        }

        report_file = self.session_dir / "report.json"
        try:
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    def save_intermediate(self):
        """Save an intermediate report (e.g. mid-scan)."""
        if not self.session_dir:
            return

        report = {
            "start_time": self._start_time,
            "snapshot_time": datetime.now(timezone.utc).isoformat(),
            "flags_so_far": self._flags,
            "entries": self._entries,
            "status": "in_progress",
        }

        report_file = self.session_dir / "report_intermediate.json"
        try:
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except IOError:
            pass

    # ── Accessors ──────────────────────────────────────────────────────────

    @property
    def flags(self) -> List[str]:
        """Return all captured flags."""
        return list(self._flags)

    @property
    def entry_count(self) -> int:
        """Return total number of log entries."""
        return len(self._entries)

    def get_entries(self, prefix: Optional[str] = None) -> List[dict]:
        """
        Get log entries, optionally filtered by prefix.

        Args:
            prefix: Filter by prefix (e.g. "VULN", "FLAG", "ERR")
        """
        if prefix:
            return [e for e in self._entries if e["prefix"] == prefix]
        return list(self._entries)
