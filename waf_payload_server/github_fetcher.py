"""
GitHub Payload Fetcher
Fetches fresh payloads from well-known GitHub repositories.
"""

import logging
import re
from typing import List, Dict, Optional

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

# GitHub raw content URL mappings for payload repositories
GITHUB_SOURCES = {
    "xss": [
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "XSS Injection/README.md",
            "description": "PayloadsAllTheThings - XSS Injection",
        },
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "XSS Injection/WAF Bypass.md",
            "description": "PayloadsAllTheThings - XSS WAF Bypass",
        },
    ],
    "sqli": [
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "SQL Injection/README.md",
            "description": "PayloadsAllTheThings - SQL Injection",
        },
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "SQL Injection/MySQL Injection.md",
            "description": "PayloadsAllTheThings - MySQL Injection",
        },
    ],
    "ssrf": [
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "Server Side Request Forgery/README.md",
            "description": "PayloadsAllTheThings - SSRF",
        },
    ],
    "ssti": [
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "Server Side Template Injection/README.md",
            "description": "PayloadsAllTheThings - SSTI",
        },
    ],
    "lfi": [
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "File Inclusion/README.md",
            "description": "PayloadsAllTheThings - File Inclusion",
        },
    ],
    "rce": [
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "Command Injection/README.md",
            "description": "PayloadsAllTheThings - Command Injection",
        },
    ],
    "xxe": [
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "XXE Injection/README.md",
            "description": "PayloadsAllTheThings - XXE Injection",
        },
    ],
    "open_redirect": [
        {
            "repo": "swisskyrepo/PayloadsAllTheThings",
            "path": "Open Redirect/README.md",
            "description": "PayloadsAllTheThings - Open Redirect",
        },
    ],
    "waf_bypass": [
        {
            "repo": "0xInfection/Awesome-WAF",
            "path": "README.md",
            "description": "Awesome-WAF - WAF bypass techniques and tools",
        },
    ],
}

# Mapping for SecLists fuzzing wordlists
SECLISTS_SOURCES = {
    "xss": "danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt",
    "sqli": "danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt",
    "lfi": "danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
}


class GitHubPayloadFetcher:
    """Fetches payloads from GitHub repositories."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WAF-Payload-MCP/1.0",
            "Accept": "text/plain, application/vnd.github.raw",
        })

    async def fetch(
        self,
        vuln_type: str,
        include_seclists: bool = True,
        max_payloads: int = 100,
    ) -> List[Dict[str, str]]:
        """
        Fetch payloads from GitHub for a given vulnerability type.

        Args:
            vuln_type: Vulnerability type (e.g., 'xss', 'sqli')
            include_seclists: Whether to include SecLists payloads
            max_payloads: Maximum number of payloads to return

        Returns:
            List of dicts with 'payload', 'source', and 'description' keys
        """
        vuln_key = vuln_type.lower().strip()
        # Normalize common aliases
        aliases = {
            "cross-site scripting": "xss",
            "sql injection": "sqli",
            "server-side request forgery": "ssrf",
            "server-side template injection": "ssti",
            "local file inclusion": "lfi",
            "path traversal": "lfi",
            "remote code execution": "rce",
            "command injection": "rce",
            "xml external entity": "xxe",
            "open redirect": "open_redirect",
            "waf bypass": "waf_bypass",
            "waf": "waf_bypass",
        }
        vuln_key = aliases.get(vuln_key, vuln_key)

        results = []

        # Fetch from PayloadsAllTheThings
        sources = GITHUB_SOURCES.get(vuln_key, [])
        for source in sources:
            payloads = self._fetch_markdown_payloads(
                source["repo"], source["path"], source["description"]
            )
            results.extend(payloads)

        # Fetch from SecLists if available
        if include_seclists and vuln_key in SECLISTS_SOURCES:
            seclists_payloads = self._fetch_seclists(vuln_key)
            results.extend(seclists_payloads)

        # Deduplicate and limit
        seen = set()
        unique_results = []
        for r in results:
            payload = r["payload"].strip()
            if payload and payload not in seen:
                seen.add(payload)
                unique_results.append(r)
                if len(unique_results) >= max_payloads:
                    break

        return unique_results

    def _fetch_markdown_payloads(
        self, repo: str, path: str, description: str
    ) -> List[Dict[str, str]]:
        """Fetch and parse payloads from a markdown file on GitHub."""
        url = f"https://raw.githubusercontent.com/{repo}/master/{path}"

        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                # Try 'main' branch
                url_main = url.replace("/master/", "/main/")
                resp = self.session.get(url_main, timeout=self.timeout)
                if resp.status_code != 200:
                    logger.warning(f"Failed to fetch {url}: {resp.status_code}")
                    return []

            content = resp.text
            return self._extract_payloads_from_markdown(content, description, repo)

        except RequestException as e:
            logger.error(f"Error fetching {url}: {e}")
            return []

    def _extract_payloads_from_markdown(
        self, content: str, source_desc: str, repo: str
    ) -> List[Dict[str, str]]:
        """Extract payload strings from markdown content."""
        payloads = []

        # Extract from code blocks (```...```)
        code_blocks = re.findall(
            r"```(?:\w+)?\s*\n(.*?)\n\s*```", content, re.DOTALL
        )
        for block in code_blocks:
            for line in block.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("//"):
                    payloads.append({
                        "payload": line,
                        "source": f"github:{repo}",
                        "description": source_desc,
                    })

        # Extract from inline code (`...`)
        inline_codes = re.findall(r"`([^`]+)`", content)
        for code in inline_codes:
            code = code.strip()
            # Filter out non-payload inline code (file paths, commands, etc.)
            if len(code) > 5 and any(
                indicator in code.lower()
                for indicator in [
                    "<", ">", "alert", "script", "select", "union",
                    "eval", "../", "{{", "${", "<?", "http://", "://",
                    "onerror", "onload", "onfocus", "passwd", "sleep",
                    "%", "\\x", "\\u",
                ]
            ):
                payloads.append({
                    "payload": code,
                    "source": f"github:{repo}",
                    "description": source_desc,
                })

        return payloads

    def _fetch_seclists(self, vuln_key: str) -> List[Dict[str, str]]:
        """Fetch payloads from SecLists wordlists."""
        path = SECLISTS_SOURCES.get(vuln_key)
        if not path:
            return []

        url = f"https://raw.githubusercontent.com/{path}"

        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                logger.warning(f"Failed to fetch SecLists {url}: {resp.status_code}")
                return []

            payloads = []
            for line in resp.text.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append({
                        "payload": line,
                        "source": "github:danielmiessler/SecLists",
                        "description": f"SecLists - {vuln_key.upper()} fuzzing list",
                    })

            return payloads

        except RequestException as e:
            logger.error(f"Error fetching SecLists: {e}")
            return []

    def list_sources(self) -> Dict[str, List[Dict[str, str]]]:
        """List all available GitHub sources."""
        result = {}
        for vuln_type, sources in GITHUB_SOURCES.items():
            result[vuln_type] = [
                {"repo": s["repo"], "path": s["path"], "description": s["description"]}
                for s in sources
            ]
        # Add SecLists
        for vuln_type, path in SECLISTS_SOURCES.items():
            if vuln_type not in result:
                result[vuln_type] = []
            result[vuln_type].append({
                "repo": "danielmiessler/SecLists",
                "path": path,
                "description": f"SecLists {vuln_type.upper()} fuzzing wordlist",
            })
        return result
