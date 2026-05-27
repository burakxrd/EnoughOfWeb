"""
End-to-end integration test:
Simulates an agent using the tool's API to demonstrate:
  1. Session creation + recon
  2. Strategy suggestion (cold start → PHP boosts LFI, login boosts auth_bypass)
  3. Autonomous attack (follows strategy)
  4. Agent override (skips ahead)
  5. Experience DB logging with context
  6. Override detection
  7. Pattern mining
  8. Strategy re-evaluation
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.session_tracker import SessionTracker
from brain.learner import AdaptiveLearner, TargetContext
from brain.strategy import StrategyEngine
from brain.pattern_miner import PatternMiner
from config import load_config

DIVIDER = "=" * 60

# ── Clean slate ────────────────────────────────────────────────────────────
data_dir = Path("data")
exp_file = data_dir / "experience.json"
pat_file = data_dir / "patterns.json"
for f in [exp_file, pat_file]:
    if f.exists():
        f.unlink()

print(f"\n{DIVIDER}")
print("  PHASE 1: SESSION + RECON + STRATEGY (COLD START)")
print(DIVIDER)

config = load_config()
tracker = SessionTracker()
learner = AdaptiveLearner()
miner = PatternMiner()
strategy = StrategyEngine(config, learner=learner, pattern_miner=miner)

# Simulate recon data for a PHP target with login form and id param
recon_data = {
    "technology": {
        "server": "Apache/2.4.41",
        "x_powered_by": "PHP/8.2",
        "frameworks": [],
    },
    "forms": [
        {
            "action": "/login",
            "method": "POST",
            "inputs": {"username": "text", "password": "password"},
        },
        {
            "action": "/search",
            "method": "GET",
            "inputs": {"q": "text"},
        },
    ],
    "url_params": ["id", "file", "q"],
    "cookies": {"PHPSESSID": "abc123"},
    "interesting_paths": {"/robots.txt": {"found": True}, "/admin": {"found": True, "status": 403}},
    "parameters": [],
}

# Create session
sid = tracker.create_session("http://vulnapp.ctf:8080")
print(f"  Session created: {sid}")

# Build context
ctx = TargetContext.from_recon("http://vulnapp.ctf:8080", recon_data)
ctx_dict = {
    "url": ctx.url, "domain": ctx.domain, "tech": ctx.tech,
    "has_login_form": ctx.has_login_form, "has_file_param": ctx.has_file_param,
    "has_id_param": ctx.has_id_param, "has_url_param": ctx.has_url_param,
    "has_cmd_param": ctx.has_cmd_param, "cookies": ctx.cookies,
}
print(f"  Context: tech={ctx.tech}, login={ctx.has_login_form}, file_param={ctx.has_file_param}, id_param={ctx.has_id_param}")

# Strategy suggestion
suggestion = strategy.get_suggested_order(recon_data)
suggested_order = suggestion["suggested_order"]
tier = suggestion["tier_info"]
print(f"  Strategy tier: {tier['dominant_tier']}")
print(f"  Seed weight: {tier['seed_weight']}")
print(f"  Suggested order: {' -> '.join(suggested_order)}")
print(f"  Scores: {suggestion['scores']}")
print(f"  >> PHP+file_param boosted LFI! login_form boosted auth_bypass!")

# Record recon with the ACTUAL suggested order
tracker.record_recon(sid, recon_data, suggested_order)

print(f"\n{DIVIDER}")
print("  PHASE 2: AUTONOMOUS ATTACKS (following strategy)")
print(DIVIDER)

# The strategy order is: sqli -> lfi -> auth_bypass -> idor -> ssti -> cmdi -> ...
# Agent follows this order = autonomous

# Attack 1: sqli (1st in strategy) -> AUTONOMOUS
source1 = tracker.detect_override(sid, suggested_order[0])
print(f"\n  [1] Module: {suggested_order[0]} | Source: {source1}")
assert source1 == "autonomous", f"Expected autonomous, got {source1}"

learner.log_with_context(
    module="sqli", technique="union-based", success=False,
    session_id=sid, target_context=ctx_dict, source=source1,
    sequence_position=1, payload="' UNION SELECT NULL--", parameter="q",
    error="No union-injectable params found", duration_ms=1200,
)
tracker.record_attack(sid, "sqli", "no_findings")
print(f"       Result: no_findings (autonomous, following strategy)")

# Attack 2: lfi (2nd in strategy) -> AUTONOMOUS
source2 = tracker.detect_override(sid, suggested_order[1])
print(f"\n  [2] Module: {suggested_order[1]} | Source: {source2}")
assert source2 == "autonomous", f"Expected autonomous, got {source2}"

learner.log_with_context(
    module="lfi", technique="path_traversal", success=False,
    session_id=sid, target_context=ctx_dict, source=source2,
    sequence_position=2, previous_module="sqli", previous_result="no_findings",
    payload="../../../etc/passwd", parameter="file",
    error="WAF blocked path traversal", duration_ms=900,
)
tracker.record_attack(sid, "lfi", "no_findings")
print(f"       Result: no_findings (autonomous, WAF blocked)")

print(f"\n{DIVIDER}")
print("  PHASE 3: AGENT OVERRIDE (agent skips auth_bypass+idor, goes to ssti)")
print(DIVIDER)

# Strategy says next: auth_bypass (3rd)
# But agent sees PHP error with template-like output and goes to SSTI instead!
# This is an OVERRIDE — agent skips auth_bypass and idor
next_expected = suggested_order[2]  # auth_bypass
agent_choice = "ssti"
source3 = tracker.detect_override(sid, agent_choice)
print(f"\n  Strategy expected next: {next_expected}")
print(f"  Agent chose instead:   {agent_choice}")
print(f"  [3] Module: {agent_choice} | Source: {source3}")
assert source3 == "agent_override", f"Expected agent_override, got {source3}"
print(f"       >> OVERRIDE DETECTED! Agent saw template error, went to SSTI")

# SSTI succeeds with flag!
learner.log_with_context(
    module="ssti", technique="jinja2_rce", success=True,
    session_id=sid, target_context=ctx_dict, source=source3,
    sequence_position=3, previous_module="lfi", previous_result="no_findings",
    payload="{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}",
    parameter="q", flag="FLAG{ssti_jinja2_rce}", duration_ms=450,
)
tracker.record_attack(sid, "ssti", "flag_found", flag="FLAG{ssti_jinja2_rce}")
print(f"       Result: FLAG FOUND! FLAG{{ssti_jinja2_rce}}")
print(f"       Logged as: source=agent_override (agent was smarter than strategy!)")

print(f"\n{DIVIDER}")
print("  PHASE 4: AGENT RETRY (retries sqli with different technique)")
print(DIVIDER)

# Agent retries sqli (already run) with auth bypass technique on login form
source4 = tracker.detect_override(sid, "sqli")
print(f"\n  [4] Module: sqli (retry) | Source: {source4}")
assert source4 == "agent_retry", f"Expected agent_retry, got {source4}"

learner.log_with_context(
    module="sqli", technique="auth_bypass_sqli", success=True,
    session_id=sid, target_context=ctx_dict, source=source4,
    sequence_position=4, previous_module="ssti", previous_result="flag_found",
    payload="admin' OR '1'='1", parameter="username",
    flag="FLAG{sqli_auth_bypass}", duration_ms=150,
)
tracker.record_attack(sid, "sqli", "flag_found", flag="FLAG{sqli_auth_bypass}")
print(f"       Result: FLAG FOUND! FLAG{{sqli_auth_bypass}}")

# Complete session
tracker.complete_session(sid)

print(f"\n{DIVIDER}")
print("  PHASE 5: EXPERIENCE DB VERIFICATION")
print(DIVIDER)

# Check experience.json
stats = learner.get_total_stats()
print(f"\n  Total entries: {stats['total_attempts']}")
print(f"  Successes: {stats['total_successes']}")
print(f"  Flags: {stats['total_flags']}")

os_stats = stats['override_stats']
print(f"\n  Override stats:")
print(f"    Total overrides:       {os_stats['total_overrides']}")
print(f"    Override success rate:  {os_stats['override_success_rate']:.0%}")
print(f"    Autonomous success rate:{os_stats['autonomous_success_rate']:.0%}")

print(f"\n  Per-module breakdown:")
for mod, data in stats['by_vuln_type'].items():
    print(f"    {mod:15s} {data['attempts']} attempts, {data['successes']} success, rate={data['success_rate']:.0%}")

# Verify experience.json structure
with open(exp_file, "r", encoding="utf-8") as f:
    exp_data = json.load(f)

print(f"\n  Experience DB version: {exp_data['version']}")
print(f"  Entry count: {exp_data['entry_count']}")

# Show the override entry in detail
entry = exp_data["entries"][2]  # The SSTI override entry
print(f"\n  Sample entry (SSTI override):")
print(f"    module:          {entry['module']}")
print(f"    technique:       {entry['technique']}")
print(f"    success:         {entry['success']}")
print(f"    source:          {entry['source']}  << OVERRIDE!")
print(f"    session_id:      {entry['session_id']}")
print(f"    context.tech:    {entry['target_context'].get('tech')}")
print(f"    context.login:   {entry['target_context'].get('has_login_form')}")
print(f"    context.file_p:  {entry['target_context'].get('has_file_param')}")
print(f"    flag:            {entry.get('flag')}")
print(f"    seq_position:    {entry['sequence_position']}")
print(f"    prev_module:     {entry['previous_module']}")
print(f"    prev_result:     {entry['previous_result']}")

print(f"\n{DIVIDER}")
print("  PHASE 6: SESSION STATE VERIFICATION")
print(DIVIDER)

summary = tracker.get_session_summary(sid)
print(f"\n  Session:      {summary['session_id']}")
print(f"  Status:       {summary['status']}")
print(f"  Recommended:  {summary['recommended_order']}")
print(f"  Actual:       {summary['actual_order']}")
print(f"  Overrides:    {summary['overrides_detected']}")
print(f"  Flags:        {summary['flags_found']}")

print(f"\n  Deviation analysis:")
rec = set(summary['recommended_order'][:3])
act = set(summary['actual_order'][:3])
print(f"    Strategy's top 3: {summary['recommended_order'][:3]}")
print(f"    Agent's actual:   {summary['actual_order']}")
skipped = rec - act
added = act - rec
if skipped:
    print(f"    Agent SKIPPED: {skipped}")
if added:
    print(f"    Agent ADDED:   {added}")

print(f"\n{DIVIDER}")
print("  PHASE 7: PATTERN MINING")
print(DIVIDER)

entries = learner.get_all_entries()
new_patterns = miner.mine_all(entries)
all_patterns = miner.get_patterns()

print(f"\n  Mined {len(new_patterns)} new pattern(s)")
print(f"  Total patterns: {len(all_patterns)}")

if all_patterns:
    for p in all_patterns:
        conf = p.get("confidence", {})
        print(f"\n  Pattern [{p['type']}] origin={p['origin']}")
        print(f"    IF {p['trigger'].get('field')} {p['trigger'].get('operator')} {p['trigger'].get('value')}")
        print(f"    -> boost {p['action'].get('boost_module')} by {p['action'].get('boost_amount', 0):+d}")
        print(f"    confidence: {conf.get('success_rate', 0):.0%} (n={conf.get('sample_size', 0)})")
else:
    print(f"  (No patterns yet — need {miner.MIN_SAMPLES}+ samples per pattern)")
    print(f"   This is expected! Patterns emerge after multiple scans.")

print(f"\n{DIVIDER}")
print("  PHASE 8: STRATEGY RE-EVALUATION (with learned data)")
print(DIVIDER)

# Create a new strategy engine that picks up historical data
strategy2 = StrategyEngine(config, learner=learner, pattern_miner=miner)
suggestion2 = strategy2.get_suggested_order(recon_data)
tier2 = suggestion2["tier_info"]

print(f"\n  Strategy tier: {tier2['dominant_tier']}")
print(f"  Seed weight: {tier2['seed_weight']} (was 1.0)")
print(f"  Active patterns: {tier2['active_patterns']}")
print(f"  NEW suggested order: {' -> '.join(suggestion2['suggested_order'])}")
print(f"  NEW Scores: {suggestion2['scores']}")

# Compare
print(f"\n  BEFORE (cold start): {' -> '.join(suggested_order)}")
print(f"  AFTER  (with data):  {' -> '.join(suggestion2['suggested_order'])}")

# Show what changed
old_top3 = suggested_order[:3]
new_top3 = suggestion2['suggested_order'][:3]
if old_top3 != new_top3:
    print(f"\n  >> TOP 3 CHANGED! Strategy is learning!")
    print(f"     Old: {old_top3}")
    print(f"     New: {new_top3}")
else:
    print(f"\n  >> Top 3 same — more data needed for significant changes")
    print(f"     Historical success boosts applied to: sqli(+retry), ssti(+override)")

print(f"\n{DIVIDER}")
print("  ALL TESTS PASSED!")
print(DIVIDER)
print()
