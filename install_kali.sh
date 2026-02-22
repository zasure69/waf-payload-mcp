#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WAF Bypass Payload MCP Server — Kali Linux Installer
#  Installs all dependencies and configures Gemini CLI integration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   WAF Bypass Payload MCP Server — Kali Linux Installer  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: System Dependencies ──────────────────────────────
echo -e "${YELLOW}[1/4] Installing system dependencies...${NC}"
sudo apt-get update -qq || echo -e "${YELLOW}  ⚠ apt-get update had warnings (non-critical)${NC}"
sudo apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    jq \
    2>/dev/null

echo -e "${GREEN}  ✓ System dependencies installed${NC}"

# ── Step 2: Python Virtual Environment ───────────────────────
echo -e "${YELLOW}[2/4] Setting up Python virtual environment...${NC}"

VENV_DIR="${SCRIPT_DIR}/venv"

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}  ✓ Virtual environment created at ${VENV_DIR}${NC}"
else
    echo -e "${GREEN}  ✓ Virtual environment already exists${NC}"
fi

source "${VENV_DIR}/bin/activate"

# ── Step 3: Install Python Dependencies ──────────────────────
echo -e "${YELLOW}[3/4] Installing Python dependencies...${NC}"
pip install --upgrade pip -q
pip install -r "${SCRIPT_DIR}/requirements-waf-mcp.txt" -q

echo -e "${GREEN}  ✓ Python dependencies installed${NC}"

# Verify imports
echo -e "${YELLOW}  Verifying installation...${NC}"
python3 -c "
from waf_payload_server.payload_db import PayloadDB
from waf_payload_server.payload_mutator import PayloadMutator
from waf_payload_server.waf_detector import WAFDetector
from waf_payload_server.github_fetcher import GitHubPayloadFetcher
from waf_payload_server.web_searcher import WebSearcher
from waf_payload_server.server import mcp
db = PayloadDB()
stats = db.get_stats()
s = stats.get('_summary', {})
print(f'  Loaded {s.get(\"total\", 0)} payloads ({s.get(\"waf_bypass\", 0)} WAF bypass)')
print(f'  MCP Server: {mcp.name}')
" 2>/dev/null

echo -e "${GREEN}  ✓ All modules verified${NC}"

# ── Step 4: Configure Gemini CLI ─────────────────────────────
echo -e "${YELLOW}[4/4] Configuring Gemini CLI integration...${NC}"

GEMINI_DIR="$HOME/.gemini"
SETTINGS_FILE="${GEMINI_DIR}/settings.json"

mkdir -p "$GEMINI_DIR"

# Build MCP server config
MCP_CONFIG=$(cat <<EOF
{
  "mcpServers": {
    "waf-payloads": {
      "command": "${VENV_DIR}/bin/python3",
      "args": ["-m", "waf_payload_server"],
      "cwd": "${SCRIPT_DIR}",
      "timeout": 30000,
      "env": {
        "PYTHONPATH": "${SCRIPT_DIR}"
      }
    }
  }
}
EOF
)

if [ -f "$SETTINGS_FILE" ]; then
    echo -e "${YELLOW}  ⚠ Existing settings.json found${NC}"
    cp "$SETTINGS_FILE" "${SETTINGS_FILE}.bak"
    echo -e "${YELLOW}    Backup → ${SETTINGS_FILE}.bak${NC}"

    if command -v jq &> /dev/null; then
        EXISTING=$(cat "$SETTINGS_FILE")
        echo "$EXISTING" | jq --argjson mcp "$(echo "$MCP_CONFIG" | jq '.mcpServers')" \
            '.mcpServers = (.mcpServers // {}) + $mcp' > "$SETTINGS_FILE"
        echo -e "${GREEN}  ✓ MCP server config merged into existing settings.json${NC}"
    else
        echo -e "${RED}  ✗ jq not found — cannot auto-merge${NC}"
        echo -e "${YELLOW}    Please manually add to ${SETTINGS_FILE}:${NC}"
        echo ""
        echo "$MCP_CONFIG"
        echo ""
    fi
else
    echo "$MCP_CONFIG" > "$SETTINGS_FILE"
    echo -e "${GREEN}  ✓ Created ${SETTINGS_FILE}${NC}"
fi

# ── Done! ────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗"
echo -e "║                  Installation Complete!                   ║"
echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Usage:${NC}"
echo -e "  1. Start Gemini CLI:  ${CYAN}gemini${NC}"
echo -e "  2. Try these prompts:"
echo -e "     ${CYAN}\"Search for XSS WAF bypass payloads targeting Cloudflare\"${NC}"
echo -e "     ${CYAN}\"Detect the WAF on https://target.com\"${NC}"
echo -e "     ${CYAN}\"Mutate this payload: <script>alert(1)</script>\"${NC}"
echo -e "     ${CYAN}\"Search web for SQLi WAF bypass writeups\"${NC}"
echo ""
echo -e "${GREEN}Manual test:${NC}"
echo -e "  ${CYAN}source ${VENV_DIR}/bin/activate${NC}"
echo -e "  ${CYAN}python -m waf_payload_server${NC}"
echo ""
echo -e "${GREEN}Available tools (8):${NC}"
echo -e "  Search:    search_payloads, list_vulnerability_types"
echo -e "  Fetch:     fetch_github_payloads"
echo -e "  Web:       search_web_payloads, read_writeup"
echo -e "  WAF:       detect_waf, get_bypass_techniques"
echo -e "  Mutate:    mutate_payload"
echo ""
