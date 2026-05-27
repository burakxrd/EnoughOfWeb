#!/usr/bin/env python3
"""
EnoughOfWeb — Adaptive CTF Web Exploitation Automation Tool
CLI entry point — modular commands for agent-driven and autonomous operation.

Usage:
  python main.py recon --url http://target.com                 # Recon only
  python main.py attack sqli --url http://target.com           # Single module
  python main.py scan --url http://target.com                  # Full auto scan
  python main.py brain status                                  # Experience stats
  python main.py brain suggest --session SESSION_ID            # Strategy advice
  python main.py brain patterns                                # Learned patterns
  python main.py brain history --module sqli                   # Module history
"""

import argparse
import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Force UTF-8 output on Windows to prevent encoding crashes
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


sys.path.insert(0, str(Path(__file__).parent))

from config import load_config, save_config, first_run_setup, SAVES_DIR, DATA_DIR


# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT HELPER
# ═══════════════════════════════════════════════════════════════════════════

def _output(data: dict, as_json: bool = False):
    """Print result either as JSON (for agents) or human-readable."""
    if as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        _pretty_print(data)


def _pretty_print(data: dict):
    """Human-readable output for terminal."""
    for key, val in data.items():
        if isinstance(val, dict):
            print(f"  {key}:")
            for k2, v2 in val.items():
                print(f"    {k2}: {v2}")
        elif isinstance(val, list):
            print(f"  {key}: [{len(val)} items]")
            for item in val[:10]:
                print(f"    - {item}")
        else:
            print(f"  {key}: {val}")


# ═══════════════════════════════════════════════════════════════════════════
# RECON COMMAND
# ═══════════════════════════════════════════════════════════════════════════

def cmd_recon(args):
    """Run reconnaissance only. Returns session_id + structured data."""
    from core.scanner import Scanner

    config = load_config()
    _apply_proxy(config, args)

    scanner = Scanner(config=config, custom_flag_pattern=getattr(args, "flag_format", None))

    if not getattr(args, "json", False):
        print("\n[RECON] Starting reconnaissance...")

    result = scanner.recon_only(args.url, ask=getattr(args, "ask", None))

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"\n[RECON] Session: {result['session_id']}")
        print(f"[RECON] Tech: {', '.join(result['target_context']['tech']) or 'unknown'}")
        print(f"[RECON] Login form: {'yes' if result['target_context']['has_login_form'] else 'no'}")
        print(f"[RECON] Cookies: {', '.join(result['target_context']['cookies']) or 'none'}")
        print(f"[RECON] Interesting paths: {', '.join(result['target_context']['interesting_paths']) or 'none'}")

        if "semantic_answer" in result:
            ans = result["semantic_answer"]
            print(f"\n[SEMANTIC BRAIN] 🧠 Q: {getattr(args, 'ask', '')}")
            if ans.get("answer"):
                print(f"[SEMANTIC BRAIN] 💡 A: {ans['answer']} (Confidence: {ans.get('score', 0):.2%})")
            else:
                print(f"[SEMANTIC BRAIN] 💡 A: No answer found in DOM.")

        tier = result.get("strategy_tier", {})
        print(f"\n[STRATEGY] {tier.get('dominant_tier', 'default')}")
        print(f"[STRATEGY] Suggested: {' → '.join(result['suggested_order'])}")
        print(f"\n[INFO] Session ID: {result['session_id']}")
        print(f"[INFO] Use: python main.py attack <module> --url {args.url} --session {result['session_id']}")


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK COMMAND
# ═══════════════════════════════════════════════════════════════════════════

def cmd_attack(args):
    """Run a single attack module against a target."""
    from core.scanner import Scanner

    config = load_config()
    _apply_proxy(config, args)

    scanner = Scanner(config=config, custom_flag_pattern=getattr(args, "flag_format", None))

    module_name = args.module

    if not getattr(args, "json", False):
        print(f"\n[SCAN] Running module: {module_name}")

    result = scanner.attack_single(
        target_url=args.url,
        module_name=module_name,
        session_id=getattr(args, "session", None),
    )

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        source = result.get("source", "autonomous")
        source_icon = "🤖" if source == "autonomous" else "🧠"
        print(f"\n[SCAN] {module_name} | source: {source_icon} {source}")
        print(f"[SCAN] Findings: {result.get('findings_count', 0)}")

        if result.get("flag"):
            print(f"[FLAG] 🏴 {result['flag']}")
        elif result.get("success"):
            print(f"[VULN] Vulnerability found!")
        else:
            print(f"[SCAN] No findings")

        print(f"[INFO] Session: {result.get('session_id', 'N/A')}")


# ═══════════════════════════════════════════════════════════════════════════
# SCAN COMMAND (full autonomous)
# ═══════════════════════════════════════════════════════════════════════════

def cmd_scan(args):
    """Run a full autonomous scan (all modules)."""
    from core.scanner import Scanner

    config = load_config()
    _apply_proxy(config, args)

    if getattr(args, "threads", None):
        config["threads"] = args.threads
    if getattr(args, "timeout", None):
        config["timeout"] = args.timeout

    scanner = Scanner(config=config, custom_flag_pattern=getattr(args, "flag_format", None))

    modules = [args.module] if getattr(args, "module", None) else None

    if not getattr(args, "json", False):
        print()
        print("╔══════════════════════════════════════╗")
        print("║      EnoughOfWeb — Scanning...       ║")
        print("╚══════════════════════════════════════╝")
        print()

    try:
        results = scanner.scan(args.url, modules=modules, output_json=getattr(args, "json", False), ask=getattr(args, "ask", None))
    except KeyboardInterrupt:
        print("\n[ERR] Scan interrupted by user")
        sys.exit(1)
    except ConnectionError as e:
        print(f"\n[ERR] Connection failed: {e}")
        sys.exit(1)

    if getattr(args, "json", False):
        # JSON output only the essential data
        output = {
            "session_id": results.get("session_id"),
            "flags": results.get("flags", []),
            "stats": results.get("stats", {}),
            "module_results": [
                {
                    "module": r["module"],
                    "findings_count": r["findings_count"],
                    "flag": r.get("flag"),
                    "source": r.get("source"),
                }
                for r in results.get("module_results", [])
            ],
        }
        print(json.dumps(output, indent=2, ensure_ascii=False, default=str))
    else:
        flags = results.get("flags", [])
        stats = results.get("stats", {})
        if flags:
            print(f"\n🏴 Flags captured: {len(flags)}")
            for f in flags:
                print(f"   → {f}")
        else:
            print("\n❌ No flags found this time.")

        overrides = stats.get("overrides_detected", 0)
        if overrides:
            print(f"\n🧠 Agent overrides detected: {overrides}")

        print(f"\n💾 Session: {results.get('session_id', 'N/A')}")
        print(f"📊 Strategy: {stats.get('strategy_tier', 'N/A')}")


# ═══════════════════════════════════════════════════════════════════════════
# BRAIN COMMANDS
# ═══════════════════════════════════════════════════════════════════════════

def cmd_brain_status(args):
    """Display experience database statistics."""
    from brain.learner import AdaptiveLearner

    learner = AdaptiveLearner()
    stats = learner.get_total_stats()

    if getattr(args, "json", False):
        print(json.dumps(stats, indent=2, ensure_ascii=False, default=str))
        return

    if not stats["total_attempts"]:
        print("[INFO] No scan history yet. Run some scans first!")
        return

    print("\n╔══════════════════════════════════════╗")
    print("║       EnoughOfWeb — Brain Status     ║")
    print("╚══════════════════════════════════════╝\n")

    rate = stats.get("overall_success_rate", 0)
    print(f"  Total attempts:  {stats['total_attempts']}")
    print(f"  Successful:      {stats['total_successes']} ({rate:.0%})")
    print(f"  Flags captured:  {stats['total_flags']}")

    override_stats = stats.get("override_stats", {})
    if override_stats.get("total_overrides", 0) > 0:
        print(f"\n  Agent Overrides:")
        print(f"    Total: {override_stats['total_overrides']}")
        print(f"    Override success: {override_stats['override_success_rate']:.0%}")
        print(f"    Autonomous success: {override_stats['autonomous_success_rate']:.0%}")
    print()

    by_vuln = stats.get("by_vuln_type", {})
    if by_vuln:
        print("  Per module:")
        for mod, data in by_vuln.items():
            r = data.get("success_rate", 0)
            bar = "█" * int(r * 10) + "░" * (10 - int(r * 10))
            print(f"    {mod:15s} {bar} {r:.0%} ({data['successes']}/{data['attempts']})")
    print()


def cmd_brain_suggest(args):
    """Get strategy suggestion based on session recon data."""
    from core.session_tracker import SessionTracker
    from brain.learner import AdaptiveLearner
    from brain.strategy import StrategyEngine
    from brain.pattern_miner import PatternMiner

    config = load_config()
    tracker = SessionTracker()

    session_id = args.session
    state = tracker.load_session(session_id)

    if not state:
        print(f"[ERR] Session '{session_id}' not found")
        sys.exit(1)

    if not state.recon_done:
        print(f"[ERR] Recon not done for session '{session_id}'. Run recon first.")
        sys.exit(1)

    # Build strategy with learned patterns
    learner = AdaptiveLearner()
    miner = PatternMiner()
    strategy = StrategyEngine(config, learner=learner, pattern_miner=miner)

    # Load recon data from session dir
    recon_file = tracker.get_session_dir(session_id) / "recon_data.json"
    if recon_file.exists():
        with open(recon_file, "r", encoding="utf-8") as f:
            recon_data = json.load(f)
    else:
        recon_data = state.recon_data_snapshot

    result = strategy.get_suggested_order(recon_data)

    # Add what's already been run
    result["already_run"] = state.actual_order
    result["remaining"] = [m for m in result["suggested_order"] if m not in state.actual_order]

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        tier = result.get("tier_info", {})
        print(f"\n[STRATEGY] {tier.get('dominant_tier', 'unknown')}")
        print(f"[STRATEGY] Seed weight: {tier.get('seed_weight', 1.0)}")
        print(f"[STRATEGY] Active patterns: {tier.get('active_patterns', 0)}")
        print(f"\n[SUGGEST] Full order: {' → '.join(result['suggested_order'])}")

        if result["already_run"]:
            print(f"[DONE]    Already run: {' → '.join(result['already_run'])}")

        if result["remaining"]:
            print(f"[NEXT]    Remaining:   {' → '.join(result['remaining'])}")
            print(f"\n[INFO] Try: python main.py attack {result['remaining'][0]} --url {state.target_url} --session {session_id}")


def cmd_brain_history(args):
    """View module/domain specific history."""
    from brain.learner import AdaptiveLearner

    learner = AdaptiveLearner()

    if getattr(args, "module", None):
        entries = learner.get_entries_by_module(args.module)
        label = f"Module: {args.module}"
    elif getattr(args, "domain", None):
        entries = learner.get_entries_by_context(domain=args.domain)
        label = f"Domain: {args.domain}"
    else:
        entries = learner.get_all_entries()[-50:]  # Last 50
        label = "Recent (last 50)"

    if getattr(args, "json", False):
        print(json.dumps(entries, indent=2, ensure_ascii=False, default=str))
        return

    if not entries:
        print(f"[INFO] No history for {label}")
        return

    print(f"\n[HISTORY] {label} ({len(entries)} entries)\n")

    for e in entries[-20:]:  # Show last 20
        icon = "✅" if e.get("success") else "❌"
        source = e.get("source", "?")
        source_icon = "🤖" if source == "autonomous" else "🧠" if source == "agent_override" else "🔄"
        mod = e.get("module", "?")
        tech = e.get("technique", "?")
        flag = "🏴" if e.get("flag_found") else ""

        print(f"  {icon} {source_icon} {mod}/{tech} {flag}")
        if e.get("error"):
            print(f"       err: {e['error'][:60]}")

    # Summary
    success = sum(1 for e in entries if e.get("success"))
    print(f"\n  Summary: {success}/{len(entries)} successful ({success/len(entries):.0%})")


def cmd_brain_patterns(args):
    """List learned patterns."""
    from brain.pattern_miner import PatternMiner

    miner = PatternMiner()
    patterns = miner.get_patterns()

    if getattr(args, "json", False):
        print(json.dumps(patterns, indent=2, ensure_ascii=False, default=str))
        return

    if not patterns:
        print("[INFO] No patterns learned yet. Run more scans!")
        return

    print(f"\n╔══════════════════════════════════════╗")
    print(f"║    Learned Patterns ({len(patterns):3d} total)     ║")
    print(f"╚══════════════════════════════════════╝\n")

    origin_icons = {
        "auto_mined": "⚙️",
        "agent_correction": "🧠",
        "seed": "🌱",
    }

    for p in patterns:
        icon = origin_icons.get(p.get("origin", ""), "•")
        conf = p.get("confidence", {})
        rate = conf.get("success_rate", 0)
        samples = conf.get("sample_size", 0)
        trigger = p.get("trigger", {})
        action = p.get("action", {})

        bar = "█" * int(rate * 5) + "░" * (5 - int(rate * 5))

        print(f"  {icon} [{p.get('type', '?')}]")
        print(f"     IF {trigger.get('field', '?')} {trigger.get('operator', '?')} {trigger.get('value', '?')}")
        print(f"     → boost {action.get('boost_module', '?')} by {action.get('boost_amount', 0):+d}")
        print(f"     conf: {bar} {rate:.0%} (n={samples})")
        print()


# ═══════════════════════════════════════════════════════════════════════════
# LEGACY COMMANDS
# ═══════════════════════════════════════════════════════════════════════════

def cmd_rulebook(args):
    """Display the self-written rulebook."""
    from brain.rulebook import Rulebook

    rulebook = Rulebook()
    rules = rulebook.get_rules()

    if getattr(args, "json", False):
        print(json.dumps(rules, indent=2, ensure_ascii=False, default=str))
        return

    if not rules:
        print("[INFO] Rulebook is empty. The brain will write rules as you scan more targets.")
        return

    print("\n╔══════════════════════════════════════╗")
    print("║      EnoughOfWeb — Rulebook          ║")
    print("╚══════════════════════════════════════╝\n")

    for rule in rules:
        icon = {"lesson_learned": "📘", "mistake": "⚠️", "strategy": "🎯"}.get(rule.get("type", ""), "•")
        print(f"  {icon} [{rule.get('category', '?')}] {rule.get('rule_text', '')}")
        if rule.get("context"):
            print(f"     ↳ {rule['context']}")
        print()


def cmd_saves(args):
    """List saved scan sessions."""
    from core.session_tracker import SessionTracker

    tracker = SessionTracker()
    sessions = tracker.list_sessions(limit=20)

    if getattr(args, "json", False):
        print(json.dumps(sessions, indent=2, ensure_ascii=False, default=str))
        return

    if not sessions:
        print("[INFO] No saved sessions yet.")
        return

    print("\n╔══════════════════════════════════════╗")
    print("║     EnoughOfWeb — Saved Sessions     ║")
    print("╚══════════════════════════════════════╝\n")

    for s in sessions:
        flags = s.get("flags", [])
        flag_str = f"🏴 {len(flags)} flag(s)" if flags else "No flags"
        overrides = s.get("overrides", 0)
        override_str = f" | 🧠 {overrides} overrides" if overrides else ""

        print(f"  {s['session_id']}")
        print(f"    URL: {s.get('target_url', 'N/A')}")
        print(f"    Status: {s.get('status', '?')} | {flag_str}{override_str}")
        print()


def cmd_setup(args):
    """Re-run first-time setup."""
    from config import CONFIG_FILE
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
    first_run_setup()


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _apply_proxy(config, args):
    """Apply proxy settings from CLI args to config."""
    proxy = getattr(args, "proxy", None)
    if not proxy:
        return

    if proxy == "burp":
        config["proxy_enabled"] = True
    elif proxy == "none":
        config["proxy_enabled"] = False
    else:
        try:
            host, port = proxy.split(":")
            config["proxy_enabled"] = True
            config["proxy_host"] = host
            config["proxy_port"] = int(port)
        except ValueError:
            print(f"[ERR] Invalid proxy format: {proxy}. Use 'burp', 'none', or 'host:port'")
            sys.exit(1)


ALL_MODULES = ["sqli", "ssti", "cmdi", "lfi", "xss", "jwt", "ssrf", "idor", "auth_bypass"]


# ═══════════════════════════════════════════════════════════════════════════
# CLI PARSER
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="enoughofweb",
        description="EnoughOfWeb — Adaptive CTF Web Exploitation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  recon       Reconnaissance only (returns session_id + target info)
  attack      Run a single attack module
  scan        Full autonomous scan (all modules)
  brain       Query the learning brain (status, suggest, history, patterns)
  saves       List saved sessions
  rulebook    View self-written rules
  setup       Re-run first-time setup

Examples:
  python main.py recon --url http://target.com --json
  python main.py attack sqli --url http://target.com --session SESSION_ID
  python main.py scan --url http://target.com
  python main.py brain status
  python main.py brain suggest --session SESSION_ID
  python main.py brain patterns
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Shared args
    def add_common_args(p):
        p.add_argument("--json", "-j", action="store_true", help="Output as JSON (agent-friendly)")
        p.add_argument("--i-have-permission", action="store_true", dest="permission",
                        help="Confirm authorization to test")

    def add_target_args(p):
        p.add_argument("--url", "-u", required=True, help="Target URL")
        p.add_argument("--proxy", "-p", help="Proxy: 'burp', 'none', or 'host:port'")
        p.add_argument("--flag-format", "-f", help="Custom flag regex pattern")

    # ── recon ──────────────────────────────────────────────────────────────
    recon_parser = subparsers.add_parser("recon", help="Run reconnaissance only")
    add_target_args(recon_parser)
    recon_parser.add_argument("--ask", type=str, help="Ask a question to the Semantic Brain using target DOM")
    add_common_args(recon_parser)
    recon_parser.set_defaults(func=cmd_recon)

    # ── attack ─────────────────────────────────────────────────────────────
    attack_parser = subparsers.add_parser("attack", help="Run a single attack module")
    attack_parser.add_argument("module", choices=ALL_MODULES, help="Module to run")
    add_target_args(attack_parser)
    attack_parser.add_argument("--session", "-s", help="Existing session ID (for override tracking)")
    add_common_args(attack_parser)
    attack_parser.set_defaults(func=cmd_attack)

    # ── scan ───────────────────────────────────────────────────────────────
    scan_parser = subparsers.add_parser("scan", help="Full autonomous scan")
    add_target_args(scan_parser)
    scan_parser.add_argument("--module", "-m", choices=ALL_MODULES, help="Run only specific module")
    scan_parser.add_argument("--threads", "-t", type=int, help="Concurrent threads (default: 5)")
    scan_parser.add_argument("--timeout", type=int, help="Request timeout in seconds")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    scan_parser.add_argument("--ask", type=str, help="Ask a question to the Semantic Brain using target DOM")
    add_common_args(scan_parser)
    scan_parser.set_defaults(func=cmd_scan)

    # ── brain ──────────────────────────────────────────────────────────────
    brain_parser = subparsers.add_parser("brain", help="Query the learning brain")
    brain_sub = brain_parser.add_subparsers(dest="brain_command", help="Brain sub-command")

    # brain status
    status_p = brain_sub.add_parser("status", help="Experience database statistics")
    status_p.add_argument("--json", "-j", action="store_true", help="JSON output")
    status_p.set_defaults(func=cmd_brain_status)

    # brain suggest
    suggest_p = brain_sub.add_parser("suggest", help="Strategy suggestion for a session")
    suggest_p.add_argument("--session", "-s", required=True, help="Session ID")
    suggest_p.add_argument("--json", "-j", action="store_true", help="JSON output")
    suggest_p.set_defaults(func=cmd_brain_suggest)

    # brain history
    history_p = brain_sub.add_parser("history", help="Module/domain history")
    history_p.add_argument("--module", "-m", choices=ALL_MODULES, help="Filter by module")
    history_p.add_argument("--domain", "-d", help="Filter by domain")
    history_p.add_argument("--json", "-j", action="store_true", help="JSON output")
    history_p.set_defaults(func=cmd_brain_history)

    # brain patterns
    patterns_p = brain_sub.add_parser("patterns", help="View learned patterns")
    patterns_p.add_argument("--json", "-j", action="store_true", help="JSON output")
    patterns_p.set_defaults(func=cmd_brain_patterns)

    # ── Legacy commands ────────────────────────────────────────────────────
    # stats → brain status (backward compat)
    stats_parser = subparsers.add_parser("stats", help="View stats (alias for 'brain status')")
    stats_parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    stats_parser.set_defaults(func=cmd_brain_status)

    rule_parser = subparsers.add_parser("rulebook", help="View self-written rules")
    rule_parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    rule_parser.set_defaults(func=cmd_rulebook)

    saves_parser = subparsers.add_parser("saves", help="List saved sessions")
    saves_parser.add_argument("--json", "-j", action="store_true", help="JSON output")
    saves_parser.set_defaults(func=cmd_saves)

    setup_parser = subparsers.add_parser("setup", help="Re-run first-time setup")
    setup_parser.set_defaults(func=cmd_setup)

    # ── Parse & Run ────────────────────────────────────────────────────────
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Handle brain without sub-command
    if args.command == "brain" and not getattr(args, "brain_command", None):
        brain_parser.print_help()
        sys.exit(0)

    # Permission check for scan/attack/recon
    if args.command in ("scan", "attack", "recon"):
        if not getattr(args, "permission", False):
            print("[!] You must confirm authorization with --i-have-permission")
            print("    This tool is for CTF competitions and authorized pentesting ONLY.")
            sys.exit(1)

    # First-run setup
    from config import CONFIG_FILE
    if not CONFIG_FILE.exists() and args.command in ("scan", "attack", "recon"):
        first_run_setup()

    args.func(args)


if __name__ == "__main__":
    main()
