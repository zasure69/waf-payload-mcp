"""
Payload Database Manager
Loads and searches local JSON payload files.
"""

import json
import os
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), "payloads")


class PayloadDB:
    """Manages the local payload database loaded from JSON files."""

    def __init__(self):
        self._db: Dict[str, dict] = {}
        self._load_all()

    def _load_all(self):
        """Load all JSON payload files from the payloads directory."""
        if not os.path.isdir(PAYLOADS_DIR):
            logger.warning(f"Payloads directory not found: {PAYLOADS_DIR}")
            return

        for filename in os.listdir(PAYLOADS_DIR):
            if not filename.endswith(".json"):
                continue
            filepath = os.path.join(PAYLOADS_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                vuln_type = data.get("vulnerability_type", "").lower()
                if vuln_type:
                    self._db[vuln_type] = data
                    count = len(data.get("payloads", []))
                    logger.info(f"Loaded {count} payloads for {vuln_type}")
            except Exception as e:
                logger.error(f"Failed to load {filepath}: {e}")

    def list_types(self) -> List[Dict[str, str]]:
        """List all available vulnerability types."""
        result = []
        for vuln_type, data in sorted(self._db.items()):
            result.append({
                "type": data.get("vulnerability_type", vuln_type),
                "description": data.get("description", ""),
                "payload_count": len(data.get("payloads", [])),
            })
        return result

    def search(
        self,
        vuln_type: str,
        waf_bypass_only: bool = False,
        waf_name: Optional[str] = None,
        context: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 50,
    ) -> List[dict]:
        """
        Search payloads by vulnerability type with optional filters.

        Args:
            vuln_type: Vulnerability type (e.g., 'xss', 'sqli')
            waf_bypass_only: If True, return only WAF bypass payloads
            waf_name: Filter by specific WAF target (e.g., 'cloudflare')
            context: Filter by injection context (e.g., 'html_body')
            tags: Filter by tags (payload must have ALL listed tags)
            limit: Maximum results to return

        Returns:
            List of matching payload dicts
        """
        vuln_key = vuln_type.lower().strip()

        # Try exact match first, then partial match
        data = self._db.get(vuln_key)
        if not data:
            for key in self._db:
                if vuln_key in key or key in vuln_key:
                    data = self._db[key]
                    break

        if not data:
            return []

        payloads = data.get("payloads", [])
        results = []

        for p in payloads:
            # WAF bypass filter
            if waf_bypass_only and not p.get("waf_bypass", False):
                continue

            # WAF name filter
            if waf_name:
                waf_lower = waf_name.lower().replace(" ", "_").replace("-", "_")
                bypass_targets = [t.lower() for t in p.get("bypass_target", [])]
                if bypass_targets and waf_lower not in bypass_targets:
                    # Also check partial match
                    if not any(waf_lower in t or t in waf_lower for t in bypass_targets):
                        continue

            # Context filter
            if context:
                p_context = p.get("context", "").lower()
                if context.lower() not in p_context:
                    continue

            # Tags filter (AND logic)
            if tags:
                p_tags = [t.lower() for t in p.get("tags", [])]
                if not all(tag.lower() in p_tags for tag in tags):
                    continue

            results.append(p)
            if len(results) >= limit:
                break

        return results

    def get_stats(self) -> Dict[str, int]:
        """Get payload count statistics."""
        stats = {}
        total = 0
        total_bypass = 0
        for vuln_type, data in self._db.items():
            payloads = data.get("payloads", [])
            count = len(payloads)
            bypass_count = sum(1 for p in payloads if p.get("waf_bypass", False))
            stats[data.get("vulnerability_type", vuln_type)] = {
                "total": count,
                "waf_bypass": bypass_count,
            }
            total += count
            total_bypass += bypass_count
        stats["_summary"] = {"total": total, "waf_bypass": total_bypass}
        return stats
