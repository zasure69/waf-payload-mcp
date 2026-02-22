"""
WAF Bypass Payload MCP Server
Exposes tools for searching, generating, and mutating WAF bypass payloads
via the Model Context Protocol (MCP).
"""

import asyncio
import json
import logging
import sys

from mcp.server.fastmcp import FastMCP

from .payload_db import PayloadDB
from .payload_mutator import PayloadMutator
from .waf_detector import WAFDetector
from .github_fetcher import GitHubPayloadFetcher
from .web_searcher import WebSearcher

# ── Logging ────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("waf-payload-server")

# ── Shared instances ──────────────────────────────────────────
db = PayloadDB()
mutator = PayloadMutator()
detector = WAFDetector()
fetcher = GitHubPayloadFetcher()
searcher = WebSearcher()

# ── MCP Server ─────────────────────────────────────────────────
mcp = FastMCP(
    "WAF Bypass Payloads",
    instructions=(
        "This server provides tools for finding, generating, and mutating "
        "WAF (Web Application Firewall) bypass payloads. Use these tools "
        "when you need to verify a vulnerability that is being blocked by "
        "a WAF. You can search by vulnerability type, detect the WAF, "
        "get bypass techniques, mutate payloads, fetch fresh payloads "
        "from GitHub repositories, search Google for bypass techniques, "
        "and read blog posts / writeups to extract payloads."
    ),
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL 1: search_payloads
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
async def search_payloads(
    vuln_type: str,
    waf_bypass_only: bool = False,
    waf_name: str = "",
    context: str = "",
    tags: str = "",
    limit: int = 30,
) -> str:
    """
    Search the local payload database for payloads by vulnerability type.

    Args:
        vuln_type: Vulnerability type to search for.
                   Supported: xss, sqli, ssrf, ssti, lfi, rce, xxe, open_redirect
        waf_bypass_only: If true, return only payloads tagged as WAF bypasses
        waf_name: Filter by target WAF (e.g., 'cloudflare', 'akamai', 'modsecurity', 'aws_waf', 'imperva')
        context: Filter by injection context (e.g., 'html_body', 'js_string', 'url_parameter', 'command_parameter')
        tags: Comma-separated tags to filter by (e.g., 'event_handler,waf_bypass')
        limit: Maximum number of results (default 30)

    Returns:
        JSON formatted list of matching payloads with metadata
    """
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None

    results = db.search(
        vuln_type=vuln_type,
        waf_bypass_only=waf_bypass_only,
        waf_name=waf_name if waf_name else None,
        context=context if context else None,
        tags=tag_list,
        limit=limit,
    )

    if not results:
        available = db.list_types()
        available_str = ", ".join(t["type"] for t in available)
        return json.dumps({
            "status": "no_results",
            "message": f"No payloads found for '{vuln_type}' with the given filters.",
            "available_types": available_str,
            "tip": "Try broadening your search — remove filters or use a different vuln_type.",
        }, indent=2)

    output = {
        "status": "success",
        "vuln_type": vuln_type,
        "filters": {
            "waf_bypass_only": waf_bypass_only,
            "waf_name": waf_name or "any",
            "context": context or "any",
            "tags": tags or "any",
        },
        "count": len(results),
        "payloads": results,
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL 2: get_bypass_techniques
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
async def get_bypass_techniques(waf_name: str) -> str:
    """
    Get recommended bypass techniques and tips for a specific WAF.

    Args:
        waf_name: WAF name (e.g., 'cloudflare', 'akamai', 'aws_waf',
                  'modsecurity', 'imperva', 'sucuri', 'f5_bigip')

    Returns:
        JSON with detailed bypass techniques organized by category
        (general tips, XSS bypasses, SQLi bypasses, encoding tips)
    """
    techniques = WAFDetector.get_bypass_techniques(waf_name)
    return json.dumps(techniques, indent=2, ensure_ascii=False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL 3: mutate_payload
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
async def mutate_payload(
    payload: str,
    mutations: str = "",
) -> str:
    """
    Apply encoding/obfuscation mutations to a payload to bypass WAF filters.

    Args:
        payload: The original payload string to mutate
        mutations: Comma-separated list of mutations to apply.
                   If empty, applies ALL mutations.
                   Available: url_encode, double_url_encode, html_entity_encode,
                   unicode_encode, case_switch, comment_inject, whitespace_replace,
                   string_concat, hex_encode, base64_wrap, null_byte_inject,
                   tag_attribute_shuffle

    Returns:
        JSON with original payload and all mutated variants
    """
    mutation_list = None
    if mutations:
        mutation_list = [m.strip() for m in mutations.split(",") if m.strip()]

    results = mutator.mutate(payload, mutation_list)

    output = {
        "status": "success",
        "original_payload": payload,
        "mutations_applied": mutation_list or "all",
        "results": results,
        "tip": "Try each mutated payload against your target. "
               "If still blocked, combine multiple mutations manually.",
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL 4: detect_waf
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
async def detect_waf(url: str) -> str:
    """
    Detect which WAF is protecting a target URL.
    Sends safe probe requests and analyzes response headers, cookies,
    and body content to fingerprint the WAF.

    Args:
        url: Target URL to probe (e.g., 'https://example.com')

    Returns:
        JSON with WAF detection results including name, confidence, and evidence.
        Also includes recommended bypass techniques if a WAF is detected.
    """
    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(None, detector.detect, url)

    # If WAF detected, also include bypass techniques
    if results.get("waf_detected") and results.get("waf_name"):
        techniques = WAFDetector.get_bypass_techniques(results["waf_name"])
        results["bypass_techniques"] = techniques

    return json.dumps(results, indent=2, ensure_ascii=False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL 5: list_vulnerability_types
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
async def list_vulnerability_types() -> str:
    """
    List all supported vulnerability types in the payload database
    with payload counts and statistics.

    Returns:
        JSON with available vulnerability types, descriptions, and counts.
        Also lists available mutation techniques.
    """
    types = db.list_types()
    stats = db.get_stats()
    mutations = PayloadMutator.list_mutations()
    sources = fetcher.list_sources()

    output = {
        "vulnerability_types": types,
        "statistics": stats,
        "available_mutations": mutations,
        "github_sources": {k: len(v) for k, v in sources.items()},
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL 6: fetch_github_payloads
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
async def fetch_github_payloads(
    vuln_type: str,
    include_seclists: bool = True,
    max_payloads: int = 50,
) -> str:
    """
    Fetch fresh payloads from GitHub repositories (PayloadsAllTheThings, SecLists).
    Use this when local payloads are not sufficient or you need the latest bypasses.

    Args:
        vuln_type: Vulnerability type (e.g., 'xss', 'sqli', 'ssrf', 'ssti',
                   'lfi', 'rce', 'xxe', 'open_redirect', 'waf_bypass')
        include_seclists: Include payloads from SecLists fuzzing wordlists (default True)
        max_payloads: Maximum payloads to fetch (default 50, max 200)

    Returns:
        JSON with fetched payloads from GitHub repositories
    """
    max_payloads = min(max_payloads, 200)

    results = await fetcher.fetch(
        vuln_type=vuln_type,
        include_seclists=include_seclists,
        max_payloads=max_payloads,
    )

    if not results:
        sources = fetcher.list_sources()
        available_str = ", ".join(sources.keys())
        return json.dumps({
            "status": "no_results",
            "message": f"No payloads found for '{vuln_type}' from GitHub.",
            "available_types": available_str,
            "tip": "Check your internet connection or try a different vuln type.",
        }, indent=2)

    output = {
        "status": "success",
        "vuln_type": vuln_type,
        "count": len(results),
        "sources_used": list(set(r["source"] for r in results)),
        "payloads": results,
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL 7: search_web_payloads
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
async def search_web_payloads(
    vuln_type: str,
    waf_name: str = "",
    search_type: str = "waf_bypass",
    custom_query: str = "",
    num_results: int = 5,
    max_pages_to_read: int = 3,
) -> str:
    """
    Search Google/DuckDuckGo for WAF bypass payloads, then read the top blog posts
    and writeups to extract payloads automatically.

    This is the most powerful tool — it searches the internet, reads real blog posts
    and security writeups, and extracts payload strings from code blocks and text.

    Args:
        vuln_type: Vulnerability type (e.g., 'xss', 'sqli', 'ssrf', 'ssti')
        waf_name: Target WAF name (e.g., 'cloudflare', 'akamai', 'modsecurity')
        search_type: Type of search — 'waf_bypass' (focused bypass payloads),
                     'writeup' (bug bounty writeups), or 'payload' (general payload lists)
        custom_query: Custom Google search query (overrides auto-generated query)
        num_results: Number of search results to fetch (default 5)
        max_pages_to_read: How many pages to actually read and extract from (default 3)

    Returns:
        JSON with search results, blog summaries, and extracted payloads from the web
    """
    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(
        None,
        lambda: searcher.search_and_extract(
            vuln_type=vuln_type,
            waf_name=waf_name,
            search_type=search_type,
            custom_query=custom_query,
            num_results=num_results,
            max_pages_to_read=max_pages_to_read,
        )
    )

    return json.dumps(results, indent=2, ensure_ascii=False)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TOOL 8: read_writeup
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@mcp.tool()
async def read_writeup(
    url: str,
    extract_payloads: bool = True,
) -> str:
    """
    Read a specific blog post, writeup, or web page and extract its content.
    Useful for reading security writeups, Medium posts, HackerOne reports,
    and any web page that may contain WAF bypass payloads or techniques.

    The tool extracts:
    - Page title and clean text content
    - Code blocks and inline code
    - Payload-like strings (XSS, SQLi, SSRF, SSTI, LFI, RCE, XXE patterns)

    Args:
        url: URL of the blog post or writeup to read
        extract_payloads: Whether to auto-extract payload strings (default True)

    Returns:
        JSON with page title, content (markdown formatted), and extracted payloads
    """
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: searcher.read_blog_post(url, extract_payloads=extract_payloads)
    )

    return json.dumps(result, indent=2, ensure_ascii=False)


# ── Entry point ────────────────────────────────────────────────

def run():
    """Start the MCP server with stdio transport."""
    logger.info("Starting WAF Bypass Payload MCP Server...")
    stats = db.get_stats()
    summary = stats.get("_summary", {})
    logger.info(
        f"Loaded {summary.get('total', 0)} payloads "
        f"({summary.get('waf_bypass', 0)} WAF bypass variants)"
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
