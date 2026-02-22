"""
Web Searcher & Blog Scraper
Searches Google for WAF bypass payloads and reads blog posts / writeups
to extract payload information.
"""

import logging
import re
import time
import random
from typing import List, Dict, Optional
from urllib.parse import quote_plus, urljoin, urlparse

import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# User agents to rotate for Google search
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

# Domains that typically contain good security writeups
SECURITY_DOMAINS = [
    "medium.com",
    "infosecwriteups.com",
    "portswigger.net",
    "hackerone.com",
    "bugcrowd.com",
    "owasp.org",
    "blog.intigriti.com",
    "labs.detectify.com",
    "brutelogic.com.br",
    "security.stackexchange.com",
    "github.com",
    "exploit-db.com",
    "book.hacktricks.xyz",
    "twitter.com",
    "x.com",
]

# Pre-built search query templates
SEARCH_TEMPLATES = {
    "waf_bypass": [
        "{vuln_type} WAF bypass payload {waf_name} {year}",
        "{vuln_type} bypass {waf_name} firewall",
        "{vuln_type} {waf_name} bypass technique",
        "WAF bypass {vuln_type} payload list",
    ],
    "writeup": [
        "{vuln_type} WAF bypass writeup bug bounty",
        "{vuln_type} {waf_name} bypass blog post",
        "{vuln_type} WAF evasion technique writeup",
        "how to bypass {waf_name} {vuln_type} filter",
    ],
    "payload": [
        "{vuln_type} payload cheat sheet {year}",
        "{vuln_type} payload list bypass filter",
        "{vuln_type} obfuscation payloads",
        "latest {vuln_type} payloads {waf_name}",
    ],
}


class WebSearcher:
    """Searches Google and scrapes blog posts for WAF bypass payloads."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = requests.Session()
        self._rotate_ua()

    def _rotate_ua(self):
        """Set a random user agent."""
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

    def search_google(
        self,
        query: str,
        num_results: int = 10,
        security_sites_only: bool = False,
    ) -> List[Dict[str, str]]:
        """
        Search Google and return a list of result URLs with titles and snippets.

        Args:
            query: Search query string
            num_results: Number of results to return
            security_sites_only: If True, restrict to known security domains

        Returns:
            List of dicts with 'title', 'url', 'snippet' keys
        """
        self._rotate_ua()
        results = []

        # Build site: filter if security_sites_only
        site_filter = ""
        if security_sites_only:
            # Pick top 5 relevant domains to avoid too-long query
            top_sites = SECURITY_DOMAINS[:5]
            site_filter = " (" + " OR ".join(f"site:{d}" for d in top_sites) + ")"

        full_query = query + site_filter
        encoded_query = quote_plus(full_query)
        search_url = f"https://www.google.com/search?q={encoded_query}&num={num_results}&hl=en"

        try:
            resp = self.session.get(search_url, timeout=self.timeout)
            if resp.status_code != 200:
                logger.warning(f"Google search returned status {resp.status_code}")
                # Fallback to DuckDuckGo HTML
                return self._search_duckduckgo(query, num_results)

            soup = BeautifulSoup(resp.text, "lxml")

            # Parse Google search results
            for g in soup.select("div.g, div[data-sokoban-container]"):
                # Find link
                link_el = g.select_one("a[href]")
                if not link_el:
                    continue
                url = link_el.get("href", "")
                if not url.startswith("http"):
                    continue
                # Skip Google's own links
                if "google.com" in url:
                    continue

                # Find title
                title_el = g.select_one("h3")
                title = title_el.get_text(strip=True) if title_el else ""

                # Find snippet
                snippet_el = g.select_one("div.VwiC3b, span.st, div[data-sncf]")
                snippet = snippet_el.get_text(strip=True) if snippet_el else ""

                if url and title:
                    results.append({
                        "title": title,
                        "url": url,
                        "snippet": snippet[:300],
                    })

                if len(results) >= num_results:
                    break

        except RequestException as e:
            logger.error(f"Google search failed: {e}")
            # Fallback to DuckDuckGo
            return self._search_duckduckgo(query, num_results)

        # If Google returned nothing (captcha/blocked), try DuckDuckGo
        if not results:
            return self._search_duckduckgo(query, num_results)

        return results

    def _search_duckduckgo(
        self, query: str, num_results: int = 10
    ) -> List[Dict[str, str]]:
        """Fallback search using DuckDuckGo HTML version."""
        self._rotate_ua()
        results = []
        encoded_query = quote_plus(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded_query}"

        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                logger.warning(f"DuckDuckGo returned status {resp.status_code}")
                return results

            soup = BeautifulSoup(resp.text, "lxml")

            for result in soup.select("div.result, div.web-result"):
                link_el = result.select_one("a.result__a, a.result__url")
                if not link_el:
                    continue

                href = link_el.get("href", "")
                title = link_el.get_text(strip=True)

                # DuckDuckGo sometimes wraps URLs in redirects
                if "duckduckgo.com" in href:
                    # Try to extract actual URL from uddg parameter
                    from urllib.parse import parse_qs, urlparse as up
                    parsed = up(href)
                    params = parse_qs(parsed.query)
                    if "uddg" in params:
                        href = params["uddg"][0]

                snippet_el = result.select_one("a.result__snippet, div.result__snippet")
                snippet = snippet_el.get_text(strip=True) if snippet_el else ""

                if href.startswith("http") and title:
                    results.append({
                        "title": title,
                        "url": href,
                        "snippet": snippet[:300],
                    })

                if len(results) >= num_results:
                    break

        except RequestException as e:
            logger.error(f"DuckDuckGo search failed: {e}")

        return results

    def build_search_query(
        self,
        vuln_type: str,
        waf_name: str = "",
        search_type: str = "waf_bypass",
        custom_query: str = "",
    ) -> str:
        """
        Build an optimized search query.

        Args:
            vuln_type: Vulnerability type (xss, sqli, etc.)
            waf_name: WAF name to target
            search_type: Type of search — 'waf_bypass', 'writeup', or 'payload'
            custom_query: Optional custom query (overrides template)

        Returns:
            Formatted search query string
        """
        if custom_query:
            return custom_query

        from datetime import datetime
        year = datetime.now().year

        templates = SEARCH_TEMPLATES.get(search_type, SEARCH_TEMPLATES["waf_bypass"])
        template = templates[0]  # Use first template

        query = template.format(
            vuln_type=vuln_type,
            waf_name=waf_name or "",
            year=year,
        )
        return query.strip()

    def read_blog_post(self, url: str, extract_payloads: bool = True) -> Dict:
        """
        Read a blog post / writeup and optionally extract payloads.

        Args:
            url: URL of the blog post
            extract_payloads: Whether to extract payload-like strings

        Returns:
            Dict with 'title', 'content', 'extracted_payloads', 'url'
        """
        self._rotate_ua()
        result = {
            "url": url,
            "title": "",
            "content": "",
            "extracted_payloads": [],
            "error": None,
        }

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code != 200:
                result["error"] = f"HTTP {resp.status_code}"
                return result

            soup = BeautifulSoup(resp.text, "lxml")

            # Remove unwanted elements
            for el in soup.select(
                "script, style, nav, header, footer, aside, "
                "div.sidebar, div.comments, div.ad, div.social-share, "
                "div.related-posts, iframe, noscript"
            ):
                el.decompose()

            # Get title
            title_el = soup.select_one(
                "h1, title, meta[property='og:title']"
            )
            if title_el:
                if title_el.name == "meta":
                    result["title"] = title_el.get("content", "")
                else:
                    result["title"] = title_el.get_text(strip=True)

            # Get main content — try article/main first, fallback to body
            content_el = soup.select_one(
                "article, main, div.post-content, div.entry-content, "
                "div.article-content, div.blog-post, div.story-content, "
                "div[role='main'], section.post"
            )
            if not content_el:
                content_el = soup.body

            if content_el:
                # Extract text while preserving code blocks
                content_parts = []
                for element in content_el.descendants:
                    if element.name in ("code", "pre"):
                        code_text = element.get_text(strip=True)
                        if code_text:
                            content_parts.append(f"\n```\n{code_text}\n```\n")
                    elif element.name in ("h1", "h2", "h3", "h4", "h5", "h6"):
                        text = element.get_text(strip=True)
                        if text:
                            level = int(element.name[1])
                            content_parts.append(f"\n{'#' * level} {text}\n")
                    elif element.name == "p":
                        text = element.get_text(strip=True)
                        if text:
                            content_parts.append(text + "\n")
                    elif element.name == "li":
                        text = element.get_text(strip=True)
                        if text:
                            content_parts.append(f"• {text}\n")

                # Deduplicate and join
                seen = set()
                unique_parts = []
                for part in content_parts:
                    if part not in seen:
                        seen.add(part)
                        unique_parts.append(part)

                result["content"] = "\n".join(unique_parts)

                # Truncate very long content
                if len(result["content"]) > 15000:
                    result["content"] = result["content"][:15000] + "\n\n[... content truncated ...]"

            # Extract payloads from code blocks and content
            if extract_payloads:
                result["extracted_payloads"] = self._extract_payloads(soup, result["content"])

        except RequestException as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = f"Parse error: {e}"

        return result

    def _extract_payloads(self, soup: BeautifulSoup, text_content: str) -> List[Dict[str, str]]:
        """Extract payload-like strings from page content."""
        payloads = []
        seen = set()

        # 1. Extract from <code> and <pre> elements
        for code_el in soup.select("code, pre"):
            code_text = code_el.get_text(strip=True)
            if not code_text or len(code_text) < 3:
                continue
            # Check if it looks like a payload
            for line in code_text.split("\n"):
                line = line.strip()
                if self._looks_like_payload(line) and line not in seen:
                    seen.add(line)
                    payloads.append({
                        "payload": line,
                        "source": "code_block",
                    })

        # 2. Extract from inline patterns in text
        # Look for common payload patterns
        payload_patterns = [
            # XSS patterns
            r'<\s*(?:script|svg|img|iframe|body|input|details|marquee|video|object|embed|math|a)\b[^>]*>',
            r'(?:on\w+)\s*=\s*["\']?[^"\'>\s]+',
            r'javascript\s*:[^\s"\'<>]+',
            # SQL patterns
            r"(?:UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.*?(?:--|;|#)",
            r"'[^']*(?:OR|AND|UNION)\s+[^']*'",
            r"(?:/\*.*?\*/|--\s|#)\s*(?:UNION|SELECT)",
            # Command injection
            r"(?:;|\||&&|\$\(|`)[^;|&`]*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby)",
            # Path traversal
            r"(?:\.\./|\.\.\\|%2e%2e|%252e){2,}[^\s]*",
            # SSTI
            r"\{\{.*?\}\}",
            r"\$\{.*?\}",
            # SSRF
            r"(?:http|gopher|dict|file)://(?:127\.0\.0\.1|localhost|0x[0-9a-f]+|\[::1\]|169\.254)",
        ]

        for pattern in payload_patterns:
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            for match in matches:
                match = match.strip()
                if match and len(match) > 3 and match not in seen:
                    seen.add(match)
                    payloads.append({
                        "payload": match,
                        "source": "text_pattern",
                    })

        # Limit to 100 payloads
        return payloads[:100]

    def _looks_like_payload(self, text: str) -> bool:
        """Check if a string looks like a security payload."""
        if not text or len(text) < 3 or len(text) > 500:
            return False

        # Skip common non-payload patterns
        skip_patterns = [
            r"^pip install",
            r"^npm ",
            r"^import ",
            r"^from ",
            r"^def ",
            r"^class ",
            r"^#\s",
            r"^//\s",
            r"^\$\s",
            r"^curl\s.*-H",
            r"^git\s",
            r"^cd\s",
            r"^mkdir\s",
            r"^sudo\s",
        ]
        for pattern in skip_patterns:
            if re.match(pattern, text, re.IGNORECASE):
                return False

        # Check for payload indicators
        indicators = [
            "<script", "<svg", "<img", "<iframe", "<body",
            "onerror", "onload", "onfocus", "onclick", "onmouseover",
            "alert(", "prompt(", "confirm(", "eval(",
            "javascript:", "data:text",
            "UNION", "SELECT", "SLEEP(", "BENCHMARK(",
            "../", "..\\", "%2e%2e",
            "{{", "${", "<%",
            "127.0.0.1", "localhost", "0x7f",
            "; cat", "|cat", "&&cat", "$(cat",
            ";id", "|id", "&&id",
            "<?xml", "<!DOCTYPE", "<!ENTITY",
            "%00", "\\x00", "\\u00",
            "passwd", "/etc/",
        ]

        text_lower = text.lower()
        return any(ind.lower() in text_lower for ind in indicators)

    def search_and_extract(
        self,
        vuln_type: str,
        waf_name: str = "",
        search_type: str = "waf_bypass",
        custom_query: str = "",
        num_results: int = 5,
        max_pages_to_read: int = 3,
    ) -> Dict:
        """
        Full pipeline: Search Google → read top results → extract payloads.

        Args:
            vuln_type: Vulnerability type
            waf_name: WAF name to target
            search_type: 'waf_bypass', 'writeup', or 'payload'
            custom_query: Custom search query (overrides template)
            num_results: Number of search results to fetch
            max_pages_to_read: How many pages to actually read and parse

        Returns:
            Dict with search results, blog contents, and extracted payloads
        """
        query = self.build_search_query(vuln_type, waf_name, search_type, custom_query)

        # Step 1: Search Google/DuckDuckGo
        search_results = self.search_google(query, num_results=num_results)

        # Step 2: Read top pages and extract payloads
        all_payloads = []
        blog_summaries = []
        pages_read = 0

        for result in search_results:
            if pages_read >= max_pages_to_read:
                break

            url = result["url"]

            # Skip non-useful URLs
            parsed = urlparse(url)
            if parsed.netloc in ("www.google.com", "google.com", "webcache.googleusercontent.com"):
                continue

            logger.info(f"Reading: {url}")
            blog_data = self.read_blog_post(url, extract_payloads=True)

            if blog_data.get("error"):
                blog_summaries.append({
                    "url": url,
                    "title": result.get("title", ""),
                    "status": "error",
                    "error": blog_data["error"],
                })
                continue

            pages_read += 1

            # Collect payloads
            extracted = blog_data.get("extracted_payloads", [])
            for p in extracted:
                p["source_url"] = url
                p["source_title"] = blog_data.get("title", "")
            all_payloads.extend(extracted)

            # Blog summary (truncated content)
            content_preview = blog_data.get("content", "")[:500]
            blog_summaries.append({
                "url": url,
                "title": blog_data.get("title", ""),
                "status": "success",
                "content_preview": content_preview,
                "payloads_found": len(extracted),
            })

            # Be polite
            time.sleep(0.5)

        # Deduplicate payloads
        seen = set()
        unique_payloads = []
        for p in all_payloads:
            if p["payload"] not in seen:
                seen.add(p["payload"])
                unique_payloads.append(p)

        return {
            "query": query,
            "search_results_count": len(search_results),
            "pages_read": pages_read,
            "search_results": search_results,
            "blog_summaries": blog_summaries,
            "extracted_payloads": unique_payloads,
            "total_payloads": len(unique_payloads),
        }
