# 🛡️ WAF Bypass Payload MCP Server

MCP server cung cấp **8 tools** để tìm kiếm, tạo và biến đổi WAF bypass payloads cho bug bounty testing.

---

## ⚡ Cài đặt trên Kali Linux

```bash
chmod +x install_kali.sh
./install_kali.sh
```

Script tự động:
- Cài system dependencies (`python3`, `libxml2-dev`, `jq`, ...)
- Tạo Python virtual environment
- Cài pip dependencies (`mcp`, `requests`, `beautifulsoup4`, `lxml`)
- Import verification
- Cấu hình Gemini CLI (`~/.gemini/settings.json`)

### Cài thủ công

```bash
cd waf-payload-mcp
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-waf-mcp.txt
```

Thêm vào `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "waf-payloads": {
      "command": "/path/to/waf-payload-mcp/venv/bin/python3",
      "args": ["-m", "waf_payload_server"],
      "cwd": "/path/to/waf-payload-mcp",
      "timeout": 30000,
      "env": { "PYTHONPATH": "/path/to/waf-payload-mcp" }
    }
  }
}
```

---

## 🛠 Tools (8)

| Tool | Mô tả |
|------|--------|
| `search_payloads` | Tìm payload từ DB local theo vuln type, WAF, context, tags |
| `list_vulnerability_types` | Liệt kê vuln types + thống kê |
| `fetch_github_payloads` | Fetch payloads từ PayloadsAllTheThings & SecLists |
| `search_web_payloads` | Search Google/DuckDuckGo → đọc blogs → trích xuất payloads |
| `read_writeup` | Đọc URL cụ thể và trích xuất payloads |
| `detect_waf` | Fingerprint WAF từ URL (12 WAFs) |
| `get_bypass_techniques` | Kỹ thuật bypass cho WAF cụ thể |
| `mutate_payload` | 12 kỹ thuật encoding/obfuscation |

---

## 💡 Ví dụ

```
"Search for XSS WAF bypass payloads targeting Cloudflare"
"Search web for XSS WAF bypass payloads targeting Cloudflare"
"Read this writeup and extract payloads: https://medium.com/..."
"Detect what WAF is protecting https://target.com"
"Mutate this payload: <script>alert(1)</script>"
"Fetch the latest SQL injection payloads from GitHub"
```

---

## 📦 Payload Database

**156 payloads** (108 WAF bypass) — XSS, SQLi, RCE, SSRF, LFI, SSTI, Open Redirect, XXE

**12 WAFs:** Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, Sucuri, F5 BIG-IP, Barracuda, Fortinet, Wordfence, Comodo, Citrix

**12 Mutations:** url_encode, double_url_encode, html_entity_encode, unicode_encode, case_switch, comment_inject, whitespace_replace, string_concat, hex_encode, base64_wrap, null_byte_inject, tag_attribute_shuffle

---

## 📁 Cấu trúc

```
waf-payload-mcp/
├── install_kali.sh            # Kali Linux installer
├── requirements.txt
├── README.md
└── waf_payload_server/
    ├── __init__.py
    ├── __main__.py
    ├── server.py              # MCP server + 8 tools
    ├── payload_db.py          # Local payload database
    ├── payload_mutator.py     # 12 mutation techniques
    ├── waf_detector.py        # WAF fingerprinting + bypass tips
    ├── github_fetcher.py      # GitHub repo fetcher
    ├── web_searcher.py        # Google/DDG search + blog scraper
    └── payloads/              # JSON payload files (8 files)
```
