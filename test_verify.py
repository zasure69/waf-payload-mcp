"""Quick verification test for WAF Payload MCP Server."""

import json

# Test 1: Payload DB
print("=" * 50)
print("TEST 1: Payload Database")
print("=" * 50)
from waf_payload_server.payload_db import PayloadDB
db = PayloadDB()
types = db.list_types()
print(f"Loaded {len(types)} vulnerability types:")
for t in types:
    print(f"  {t['type']}: {t['payload_count']} payloads")
stats = db.get_stats()
s = stats["_summary"]
print(f"Total: {s['total']} payloads, {s['waf_bypass']} WAF bypass variants")

# Test 2: Search
print("\n" + "=" * 50)
print("TEST 2: Search XSS bypasses for Cloudflare")
print("=" * 50)
results = db.search("xss", waf_bypass_only=True, waf_name="cloudflare")
print(f"Found {len(results)} Cloudflare XSS bypasses:")
for r in results[:5]:
    p = r["payload"][:60]
    print(f"  {p}")

# Test 3: Mutator
print("\n" + "=" * 50)
print("TEST 3: Payload Mutator")
print("=" * 50)
from waf_payload_server.payload_mutator import PayloadMutator
m = PayloadMutator()
results = m.mutate("<script>alert(1)</script>", ["url_encode", "double_url_encode", "hex_encode"])
for k, v in results.items():
    print(f"  {k}: {v[:70]}")

# Test 4: WAF Detector (static)
print("\n" + "=" * 50)
print("TEST 4: WAF Bypass Techniques (Cloudflare)")
print("=" * 50)
from waf_payload_server.waf_detector import WAFDetector
techniques = WAFDetector.get_bypass_techniques("cloudflare")
print(f"  WAF: {techniques['waf']}")
print(f"  General tips: {len(techniques['general_tips'])}")
print(f"  XSS bypasses: {len(techniques['xss_bypasses'])}")
print(f"  SQLi bypasses: {len(techniques['sqli_bypasses'])}")

# Test 5: Server import
print("\n" + "=" * 50)
print("TEST 5: Server import check")
print("=" * 50)
from waf_payload_server.server import mcp
print(f"  MCP server name: {mcp.name}")
print(f"  Server created successfully!")

print("\n" + "=" * 50)
print("ALL TESTS PASSED!")
print("=" * 50)
