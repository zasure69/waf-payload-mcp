# 🛡️ WAF Bypass Payload MCP Server

MCP server cung cấp **8 tools** để tìm kiếm, tạo và biến đổi WAF bypass payloads cho bug bounty testing.

Tích hợp payload database local (156 payloads), mutation engine (12 kỹ thuật), WAF fingerprinting (12 WAFs), GitHub fetcher (PayloadsAllTheThings, SecLists), **Google/DuckDuckGo search** và **blog/writeup scraping**.

---

## ⚡ Setup

```bash
cd waf-payload-mcp
pip install -r requirements.txt
```

### Cấu hình Gemini CLI / Antigravity

Thêm vào `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "waf-payloads": {
      "command": "python",
      "args": ["-m", "waf_payload_server"],
      "cwd": "path/to/waf-payload-mcp",
      "timeout": 30000
    }
  }
}
```

---

## 🛠 Tools (8)

### Payload Search & Database

| Tool | Mô tả |
|------|--------|
| `search_payloads` | Tìm payload từ DB local theo vuln type, WAF, context, tags |
| `list_vulnerability_types` | Liệt kê tất cả vuln types + thống kê payload |
| `fetch_github_payloads` | Fetch payloads mới từ PayloadsAllTheThings & SecLists |

### Web Search & Blog Scraping

| Tool | Mô tả |
|------|--------|
| `search_web_payloads` | Search Google/DuckDuckGo → đọc blogs/writeups → trích xuất payloads tự động |
| `read_writeup` | Đọc một URL cụ thể (blog, Medium, HackerOne...) và trích xuất payloads |

### WAF Analysis & Mutation

| Tool | Mô tả |
|------|--------|
| `detect_waf` | Fingerprint WAF từ URL target (12 WAFs) |
| `get_bypass_techniques` | Lấy kỹ thuật bypass chi tiết cho WAF cụ thể |
| `mutate_payload` | Áp dụng 12 kỹ thuật encoding/obfuscation lên payload |

---

## 💡 Ví dụ sử dụng

```
# Tìm XSS payload bypass Cloudflare từ local DB
"Search for XSS WAF bypass payloads targeting Cloudflare"

# Search Google và đọc blog tự động
"Search web for XSS WAF bypass payloads targeting Cloudflare"

# Đọc một writeup cụ thể
"Read this writeup and extract payloads: https://medium.com/..."

# Detect WAF trên target
"Detect what WAF is protecting https://target.com"

# Mutate payload để bypass
"Mutate this payload: <script>alert(1)</script>"

# Fetch mới nhất từ GitHub
"Fetch the latest SQL injection payloads from GitHub"

# Full workflow
"Detect the WAF on target.com, then search web for bypass payloads and mutate them"
```

---

## 📦 Payload Database

**156 payloads** (108 WAF bypass) across 8 loại vuln:

| Type | Total | WAF Bypass |
|------|-------|------------|
| XSS | 30 | 23 |
| SQLi | 25 | 17 |
| RCE | 22 | 15 |
| SSRF | 20 | 14 |
| LFI | 17 | 13 |
| SSTI | 15 | 9 |
| Open Redirect | 15 | 12 |
| XXE | 12 | 5 |

**WAFs covered:** Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, Sucuri, F5 BIG-IP, Barracuda, Fortinet, Wordfence, Comodo, Citrix NetScaler

---

## 🔄 Mutation Engine

| Mutation | Ví dụ |
|----------|-------|
| `url_encode` | `%3Cscript%3E...` |
| `double_url_encode` | `%253Cscript%253E...` |
| `html_entity_encode` | `&#60;&#115;...` |
| `unicode_encode` | `\u003c\u0073...` |
| `case_switch` | `<ScRiPt>aLeRt(1)` |
| `comment_inject` | `SEL/**/ECT` |
| `whitespace_replace` | Spaces → `%09`, `%0a`, `/**/` |
| `string_concat` | `'al'+'ert'(1)` |
| `hex_encode` | `\x3c\x73\x63...` |
| `base64_wrap` | `eval(atob('PHNj...'))` |
| `null_byte_inject` | `%00<script>...` |
| `tag_attribute_shuffle` | Thay tag/event bằng alternatives |

---

## 🔍 Web Search & Blog Scraping

Tool `search_web_payloads` thực hiện pipeline:

1. **Search** Google/DuckDuckGo với query tự động tạo hoặc custom
2. **Đọc** top blog posts/writeups từ kết quả search
3. **Trích xuất** payloads từ code blocks và text patterns
4. **Trả về** danh sách payloads kèm source URL

Hỗ trợ đọc từ: Medium, InfoSec Write-ups, PortSwigger, HackerOne, GitHub, HackTricks, Exploit-DB, v.v.

Tool `read_writeup` đọc một URL cụ thể và trích xuất:
- Tiêu đề & nội dung (markdown formatted)
- Code blocks
- Payload patterns (XSS, SQLi, SSRF, SSTI, LFI, RCE, XXE)

---

## 📁 Cấu trúc

```
waf-payload-mcp/
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
    └── payloads/              # JSON payload files
        ├── xss.json
        ├── sqli.json
        ├── ssrf.json
        ├── ssti.json
        ├── lfi.json
        ├── rce.json
        ├── xxe.json
        └── open_redirect.json
```

---

## 🔧 Troubleshooting

| Vấn đề | Giải pháp |
|---------|-----------|
| MCP server không detect | Kiểm tra `cwd` trong settings trỏ đến `waf-payload-mcp/` |
| Import errors | Chạy `pip install -r requirements-waf-mcp.txt` |
| GitHub fetch fail | Kiểm tra internet; GitHub có rate limit |
| Google search bị chặn | Server tự fallback sang DuckDuckGo |
| WAF detect không chính xác | Thử nhiều URL khác nhau trên target |
