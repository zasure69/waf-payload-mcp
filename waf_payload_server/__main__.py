"""
Entry point for `python -m waf_payload_server`.
Starts the MCP server with stdio transport.
"""

from .server import run

if __name__ == "__main__":
    run()
