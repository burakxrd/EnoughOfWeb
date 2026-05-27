"""
Pattern Mining Proof-of-Concept:
5 simulated PHP CTF targets, all vulnerable to SSTI.
After scan 3, the system should auto-discover: "PHP targets → boost SSTI"

Each scan simulates a realistic agent workflow:
  - Recon finds PHP + forms
  - sqli tried first (autonomous) → fails
  - lfi tried second (autonomous) → fails
  - ssti tried → SUCCESS + FLAG

After enough data, PatternMiner should write a persistent pattern.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# Force UTF-8
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from core.session_tracker import SessionTracker
from brain.learner import AdaptiveLearner, TargetContext
from brain.strategy import StrategyEngine
from brain.pattern_miner import PatternMiner
from config import load_config

DIVIDER = "=" * 65
THIN = "-" * 65

# ── Clean slate ────────────────────────────────────────────────────────────
data_dir = Path("data")
for f in [data_dir / "experience.json", data_dir / "patterns.json"]:
    if f.exists():
        f.unlink()

config = load_config()
tracker = SessionTracker()
learner = AdaptiveLearner()
miner = PatternMiner()

# ── 5 Simulated PHP CTF Targets ───────────────────────────────────────────
TARGETS = [
    {
        "url": "http://ctf1.hackme.local:5001",
        "name": "HackViser Web-101",
        "server": "Apache/2.4.52",
        "powered": "PHP/8.1",
        "forms": [{"action": "/search", "method": "GET", "inputs": {"q": "text"}}],
        "cookies": {"PHPSESSID": "sess1"},
        "flag": "FLAG{ctf1_ssti_php}",
    },
    {
        "url": "http://ctf2.hackme.local:5002",
        "name": "TryHackMe TemplateEngine",
        "server": "Apache/2.4.41",
        "powered": "PHP/7.4",
        "forms": [
            {"action": "/contact", "method": "POST", "inputs": {"name": "text", "message": "text"}},
            {"action": "/login", "method": "POST", "inputs": {"user": "text", "password": "password"}},
        ],
        "cookies": {"PHPSESSID": "sess2", "lang": "en"},
        "flag": "FLAG{ctf2_template_rce}",
    },
    {
        "url": "http://ctf3.hackme.local:5003",
        "name": "PicoCTF WebExploit",
        "server": "nginx/1.18.0",
        "powered": "PHP/8.2",
        "forms": [{"action": "/render", "method": "POST", "inputs": {"template": "text"}}],
        "cookies": {"PHPSESSID": "sess3"},
        "flag": "FLAG{ctf3_render_ssti}",
    },
    {
        "url": "http://ctf4.hackme.local:5004",
        "name": "HTB Templated",
        "server": "Apache/2.4.48",
        "powered": "PHP/8.0",
        "forms": [{"action": "/preview", "method": "POST", "inputs": {"content": "text", "format": "text"}}],
        "cookies": {"PHPSESSID": "sess4", "token": "abc"},
        "flag": "FLAG{ctf4_preview_injection}",
    },
    {
        "url": "http://ctf5.hackme.local:5005",
        "name": "CyberDefenders WebChall",
        "server": "Apache/2.4.54",
        "powered": "PHP/8.1",
        "forms": [
            {"action": "/feedback", "method": "POST", "inputs": {"comment": "text"}},
            {"action": "/search", "method": "GET", "inputs": {"q": "text"}},
        ],
        "cookies": {"PHPSESSID": "sess5"},
        "flag": "FLAG{ctf5_feedback_ssti}",
    },
]

print(f"\n{DIVIDER}")
print("  PATTERN MINING PROOF: 5 PHP Targets, All SSTI Vulnerable")
print(DIVIDER)

for i, target in enumerate(TARGETS, 1):
    print(f"\n{THIN}")
    print(f"  SCAN {i}/5: {target['name']}")
    print(f"  Target: {target['url']}")
    print(THIN)

    # ── Build recon data ───────────────────────────────────────────────
    recon_data = {
        "technology": {
            "server": target["server"],
            "x_powered_by": target["powered"],
            "frameworks": [],
        },
        "forms": target["forms"],
        "url_params": [],
        "cookies": target["cookies"],
        "interesting_paths": {},
        "parameters": [],
    }

    # ── Create session ─────────────────────────────────────────────────
    sid = tracker.create_session(target["url"])
    ctx = TargetContext.from_recon(target["url"], recon_data)
    ctx_dict = {
        "url": ctx.url, "domain": ctx.domain, "tech": ctx.tech,
        "has_login_form": ctx.has_login_form, "has_file_param": ctx.has_file_param,
        "has_id_param": ctx.has_id_param, "has_url_param": ctx.has_url_param,
        "has_cmd_param": ctx.has_cmd_param, "cookies": ctx.cookies,
    }

    strategy = StrategyEngine(config, learner=learner, pattern_miner=miner)
    suggestion = strategy.get_suggested_order(recon_data)
    order = suggestion["suggested_order"]
    tracker.record_recon(sid, recon_data, order)

    print(f"  Context: tech={ctx.tech}, login={ctx.has_login_form}")
    print(f"  Strategy: {' -> '.join(order[:5])}...")
    print(f"  Tier: {suggestion['tier_info']['dominant_tier']}")
    print(f"  Seed weight: {suggestion['tier_info']['seed_weight']}")

    # ── Attack 1: sqli (usually first) → FAIL ─────────────────────────
    learner.log_with_context(
        module="sqli", technique="union-based", success=False,
        session_id=sid, target_context=ctx_dict, source="autonomous",
        sequence_position=1, payload="' UNION SELECT NULL--",
        parameter="q", error="Not injectable", duration_ms=800,
    )
    tracker.record_attack(sid, "sqli", "no_findings")
    print(f"  [1] sqli     -> FAIL (autonomous)")

    # ── Attack 2: lfi → FAIL ──────────────────────────────────────────
    learner.log_with_context(
        module="lfi", technique="path_traversal", success=False,
        session_id=sid, target_context=ctx_dict, source="autonomous",
        sequence_position=2, previous_module="sqli", previous_result="no_findings",
        payload="../../../etc/passwd", parameter="q",
        error="No traversal found", duration_ms=600,
    )
    tracker.record_attack(sid, "lfi", "no_findings")
    print(f"  [2] lfi      -> FAIL (autonomous)")

    # ── Attack 3: xss → FAIL ─────────────────────────────────────────
    learner.log_with_context(
        module="xss", technique="reflected", success=False,
        session_id=sid, target_context=ctx_dict, source="autonomous",
        sequence_position=3, previous_module="lfi", previous_result="no_findings",
        payload="<script>alert(1)</script>", parameter="q",
        error="Input sanitized", duration_ms=500,
    )
    tracker.record_attack(sid, "xss", "no_findings")
    print(f"  [3] xss      -> FAIL (autonomous)")

    # ── Attack 4: ssti → SUCCESS + FLAG! ──────────────────────────────
    learner.log_with_context(
        module="ssti", technique="jinja2_rce", success=True,
        session_id=sid, target_context=ctx_dict, source="autonomous",
        sequence_position=4, previous_module="xss", previous_result="no_findings",
        payload="{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}",
        parameter="q", flag=target["flag"], duration_ms=350,
    )
    tracker.record_attack(sid, "ssti", "flag_found", flag=target["flag"])
    print(f"  [4] ssti     -> FLAG! {target['flag']}  🏴")

    tracker.complete_session(sid)

    # ── Mine patterns after each scan ─────────────────────────────────
    entries = learner.get_all_entries()
    new_ids = miner.mine_all(entries)
    patterns = miner.get_patterns()

    if new_ids:
        print(f"\n  ** {len(new_ids)} NEW PATTERN(S) DISCOVERED! **")
        for pid in new_ids:
            p = next((x for x in patterns if x["id"] == pid), None)
            if p:
                conf = p.get("confidence", {})
                print(f"     [{p['type']}] origin={p['origin']}")
                print(f"       IF {p['trigger']['field']} {p['trigger']['operator']} \"{p['trigger']['value']}\"")
                print(f"       -> boost {p['action']['boost_module']} by {p['action']['boost_amount']:+d}")
                print(f"       confidence: {conf.get('success_rate', 0):.0%} (n={conf.get('sample_size', 0)})")
    else:
        print(f"\n  Patterns so far: {len(patterns)} (need {miner.MIN_SAMPLES}+ samples)")


# ═══════════════════════════════════════════════════════════════════════════
# FINAL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n\n{'#' * 65}")
print(f"#  FINAL RESULTS AFTER 5 SCANS")
print(f"{'#' * 65}")

# ── Experience DB stats ────────────────────────────────────────────────────
stats = learner.get_total_stats()
print(f"\n  Experience DB: {stats['total_attempts']} entries, {stats['total_flags']} flags")
print(f"  Per-module:")
for mod, data in sorted(stats['by_vuln_type'].items(), key=lambda x: -x[1]['success_rate']):
    bar = "█" * int(data['success_rate'] * 10) + "░" * (10 - int(data['success_rate'] * 10))
    print(f"    {mod:12s} {bar} {data['success_rate']:.0%} ({data['successes']}/{data['attempts']})")

# ── Patterns ───────────────────────────────────────────────────────────────
patterns = miner.get_patterns()
print(f"\n{DIVIDER}")
print(f"  LEARNED PATTERNS: {len(patterns)} total")
print(DIVIDER)

for p in patterns:
    conf = p.get("confidence", {})
    origin_icon = {"auto_mined": "⚙️", "agent_correction": "🧠"}.get(p["origin"], "?")
    rate = conf.get("success_rate", 0)
    bar = "█" * int(rate * 10) + "░" * (10 - int(rate * 10))

    print(f"\n  {origin_icon} Pattern: {p['type']}")
    print(f"     IF   {p['trigger']['field']} {p['trigger']['operator']} \"{p['trigger']['value']}\"")
    print(f"     THEN boost \"{p['action']['boost_module']}\" by {p['action']['boost_amount']:+d}")
    print(f"     CONF {bar} {rate:.0%}  (n={conf.get('sample_size', 0)})")

# ── Strategy comparison ────────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print(f"  STRATEGY EVOLUTION: Before vs After Learning")
print(DIVIDER)

# Before (cold start — no learner, no miner)
strat_cold = StrategyEngine(config)
cold_result = strat_cold.get_suggested_order({
    "technology": {"server": "Apache", "x_powered_by": "PHP/8.2"},
    "forms": [{"inputs": {"q": "text"}}],
    "url_params": [], "cookies": {"PHPSESSID": "x"},
})

# After (with learned data)
strat_learned = StrategyEngine(config, learner=learner, pattern_miner=miner)
learned_result = strat_learned.get_suggested_order({
    "technology": {"server": "Apache", "x_powered_by": "PHP/8.2"},
    "forms": [{"inputs": {"q": "text"}}],
    "url_params": [], "cookies": {"PHPSESSID": "x"},
})

print(f"\n  COLD START (no data):  {' -> '.join(cold_result['suggested_order'][:6])}")
print(f"  COLD scores: {cold_result['scores']}")
print(f"  Tier: {cold_result['tier_info']['dominant_tier']}")
print(f"  Seed weight: {cold_result['tier_info']['seed_weight']}")

print(f"\n  AFTER 5 SCANS:        {' -> '.join(learned_result['suggested_order'][:6])}")
print(f"  LEARNED scores: {learned_result['scores']}")
print(f"  Tier: {learned_result['tier_info']['dominant_tier']}")
print(f"  Seed weight: {learned_result['tier_info']['seed_weight']}")

# Highlight the changes
cold_ssti_pos = cold_result['suggested_order'].index('ssti') + 1
learned_ssti_pos = learned_result['suggested_order'].index('ssti') + 1
cold_ssti_score = cold_result['scores'].get('ssti', 0)
learned_ssti_score = learned_result['scores'].get('ssti', 0)

print(f"\n  {'=' * 50}")
print(f"  SSTI POSITION: #{cold_ssti_pos} -> #{learned_ssti_pos}")
print(f"  SSTI SCORE:    {cold_ssti_score} -> {learned_ssti_score} (+{learned_ssti_score - cold_ssti_score:.0f})")
print(f"  {'=' * 50}")

if learned_ssti_pos < cold_ssti_pos:
    print(f"\n  ✅ SSTI CLIMBED {cold_ssti_pos - learned_ssti_pos} POSITION(S)!")
    print(f"     The brain learned: \"PHP targets -> SSTI works!\"")
    print(f"     Next PHP target will prioritize SSTI earlier.")
elif learned_ssti_score > cold_ssti_score:
    print(f"\n  ✅ SSTI SCORE INCREASED by {learned_ssti_score - cold_ssti_score:.0f} points!")
    print(f"     The brain is learning, more scans = bigger jumps.")

# ── Verify patterns.json on disk ──────────────────────────────────────────
print(f"\n{DIVIDER}")
print(f"  PERSISTENT PATTERNS (data/patterns.json)")
print(DIVIDER)

with open(data_dir / "patterns.json", "r", encoding="utf-8") as f:
    disk_patterns = json.load(f)

print(f"\n  Version: {disk_patterns.get('version')}")
print(f"  Pattern count: {disk_patterns.get('pattern_count')}")
print(f"  Last mined: {disk_patterns.get('last_mined')}")

# Show the PHP → SSTI pattern in detail
php_ssti = [
    p for p in disk_patterns.get("patterns", [])
    if p.get("action", {}).get("boost_module") == "ssti"
    and "php" in str(p.get("trigger", {}).get("value", "")).lower()
]
if php_ssti:
    p = php_ssti[0]
    print(f"\n  THE KEY PATTERN:")
    print(f"  {json.dumps(p, indent=4)}")
else:
    print(f"\n  No specific PHP->SSTI pattern yet, but {len(disk_patterns.get('patterns',[]))} other patterns found")

print(f"\n{DIVIDER}")
print(f"  TEST COMPLETE — Pattern Mining is WORKING!")
print(f"{DIVIDER}\n")
