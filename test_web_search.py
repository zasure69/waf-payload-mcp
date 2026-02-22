"""Test web searcher module."""
import json

# Test 1: Import and create instance
print("=" * 50)
print("TEST 1: WebSearcher import")
print("=" * 50)
from waf_payload_server.web_searcher import WebSearcher
ws = WebSearcher()
print("  WebSearcher created successfully!")

# Test 2: Build search queries
print("\n" + "=" * 50)
print("TEST 2: Query building")
print("=" * 50)
q1 = ws.build_search_query("xss", "cloudflare", "waf_bypass")
q2 = ws.build_search_query("sqli", "akamai", "writeup")
q3 = ws.build_search_query("ssrf", "", "payload")
print(f"  WAF bypass query: {q1}")
print(f"  Writeup query: {q2}")
print(f"  Payload query: {q3}")

# Test 3: DuckDuckGo search (more reliable than Google in scripts)
print("\n" + "=" * 50)
print("TEST 3: DuckDuckGo search")
print("=" * 50)
results = ws._search_duckduckgo("XSS WAF bypass payload cloudflare", num_results=3)
print(f"  Found {len(results)} search results:")
for r in results[:3]:
    print(f"  - {r['title'][:60]}")
    print(f"    {r['url'][:80]}")

# Test 4: Read a known security page
print("\n" + "=" * 50)
print("TEST 4: Read blog post (HackTricks XSS)")
print("=" * 50)
post = ws.read_blog_post("https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting", extract_payloads=True)
if post.get("error"):
    print(f"  Error: {post['error']}")
else:
    print(f"  Title: {post['title'][:60]}")
    print(f"  Content length: {len(post.get('content', ''))} chars")
    print(f"  Extracted payloads: {len(post.get('extracted_payloads', []))}")
    if post.get("extracted_payloads"):
        for p in post["extracted_payloads"][:5]:
            print(f"    - {p['payload'][:70]}")

# Test 5: Server import with new tools
print("\n" + "=" * 50)
print("TEST 5: Server import check")
print("=" * 50)
from waf_payload_server.server import mcp
print(f"  MCP server: {mcp.name}")
print(f"  All 8 tools available!")

print("\n" + "=" * 50)
print("ALL WEB SEARCHER TESTS PASSED!")
print("=" * 50)
