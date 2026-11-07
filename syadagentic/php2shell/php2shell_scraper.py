#!/usr/bin/env python3
"""
php2shell — Target Scraper
Discovers PHP websites via search-engine dorks and optional Shodan API.
Output: targets.json (evidence-gated, deduped, scored)
"""
import json
import re
import time
import random
import argparse
import concurrent.futures as cf
from pathlib import Path
from urllib.parse import quote_plus, urlparse

import requests

requests.packages.urllib3.disable_warnings()

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

# Dork bank — PHP surface + upload endpoints + CMS fingerprints
DORKS = [
    'inurl:*.php?id=',
    'inurl:*.php?page=',
    'inurl:*.php?file=',
    'inurl:*.php?include=',
    'inurl:upload.php',
    'inurl:fileupload.php',
    'inurl:admin/upload',
    'inurl:wp-content/uploads intitle:index.of',
    'inurl:joomla administrator',
    'inurl:drupal admin',
    'intext:"Powered by PHP" filetype:php',
    'inurl:*.php?cat=',
    'inurl:*.php?path=',
    'inurl:*.php?doc=',
    'inurl:*.php?cont=',
]


class TargetScraper:
    def __init__(self, shodan_key=None, timeout=10, threads=20):
        self.shodan_key = shodan_key
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        self.targets = {}

    def _headers(self):
        return {"User-Agent": random.choice(UA_POOL), "Accept-Language": "en-US,en;q=0.9"}

    # ---------- search engine scraping ----------
    def bing_dork(self, dork, pages=3):
        """Scrape Bing results for a dork. Returns list of URLs."""
        urls = []
        for page in range(pages):
            first = page * 10 + 1
            url = f"https://www.bing.com/search?q={quote_plus(dork)}&first={first}&count=10"
            try:
                r = self.session.get(url, headers=self._headers(), timeout=self.timeout)
                if r.status_code != 200:
                    break
                # bing wraps real URLs in <h2><a href="...">
                links = re.findall(r'<h2><a href="(https?://[^"]+)"', r.text)
                if not links:
                    links = re.findall(r'href="(https?://(?!www\.bing|go\.microsoft|support\.microsoft)[^"]+)"', r.text)
                for link in links:
                    clean = link.split("&")[0].split("#")[0]
                    if self._looks_php(clean):
                        urls.append(clean)
                time.sleep(random.uniform(1.0, 2.5))  # polite-ish jitter
            except Exception:
                break
        return urls

    def duckduckgo_dork(self, dork):
        """Scrape DuckDuckGo HTML endpoint for a dork."""
        urls = []
        try:
            r = self.session.post(
                "https://html.duckduckgo.com/html/",
                data={"q": dork},
                headers=self._headers(),
                timeout=self.timeout,
            )
            links = re.findall(r'uddg=([^&"]+)', r.text)
            from urllib.parse import unquote
            for link in links:
                clean = unquote(link).split("&")[0]
                if self._looks_php(clean):
                    urls.append(clean)
        except Exception:
            pass
        return urls

    # ---------- shodan ----------
    def shodan_php(self, query='http.component:"php" country:US', max_results=200):
        """Query Shodan API for PHP hosts. Requires API key."""
        if not self.shodan_key:
            print("[!] no shodan key — skipping")
            return []
        hosts = []
        try:
            r = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": self.shodan_key, "query": query, "limit": max_results},
                timeout=30,
            )
            data = r.json()
            for match in data.get("matches", []):
                ip = match.get("ip_str")
                port = match.get("port", 80)
                scheme = "https" if match.get("ssl") or port == 443 else "http"
                hosts.append(f"{scheme}://{ip}:{port}/")
        except Exception as e:
            print(f"[!] shodan error: {e}")
        return hosts

    # ---------- helpers ----------
    @staticmethod
    def _looks_php(url):
        """Heuristic: URL ends in .php or has php-style query params."""
        parsed = urlparse(url)
        if not parsed.scheme.startswith("http"):
            return False
        path = parsed.path.lower()
        if path.endswith(".php"):
            return True
        if re.search(r"\.php\?", url.lower()):
            return True
        if re.search(r"\?(id|page|file|include|cat|path|doc|cont|lang|mod)=", url.lower()):
            return True
        return False

    def fingerprint(self, url):
        """Grab server banner + PHP hints from a target URL."""
        info = {"url": url, "server": None, "x_powered_by": None, "php_version": None, "status": None}
        try:
            r = self.session.get(url, headers=self._headers(), timeout=self.timeout, allow_redirects=True)
            info["status"] = r.status_code
            info["server"] = r.headers.get("Server")
            xpb = r.headers.get("X-Powered-By", "")
            info["x_powered_by"] = xpb or None
            m = re.search(r"PHP/([\d.]+)", xpb, re.I)
            if m:
                info["php_version"] = m.group(1)
            else:
                # fallback: cookie like PHPSESSID doesn't give version; check body for generator tags
                m = re.search(r'content="WordPress\s*([\d.]+)"', r.text)
                if m:
                    info["cms"] = f"WordPress {m.group(1)}"
                m = re.search(r'content="Joomla!?\s*-?\s*([\d.]+)', r.text)
                if m:
                    info["cms"] = f"Joomla {m.group(1)}"
        except Exception:
            info["status"] = "error"
        return info

    # ---------- main ----------
    def run(self, engines=("bing", "ddg"), dorks=None, pages=2, use_shodan=False, shodan_query=None):
        dorks = dorks or DORKS
        raw_urls = set()

        if "bing" in engines:
            print(f"[*] scraping bing with {len(dorks)} dorks...")
            with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = {ex.submit(self.bing_dork, d, pages): d for d in dorks}
                for fut in cf.as_completed(futs):
                    raw_urls.update(fut.result())

        if "ddg" in engines:
            print("[*] scraping duckduckgo...")
            with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futs = {ex.submit(self.duckduckgo_dork, d): d for d in dorks}
                for fut in cf.as_completed(futs):
                    raw_urls.update(fut.result())

        if use_shodan:
            print("[*] querying shodan...")
            raw_urls.update(self.shodan_php(shodan_query or 'http.component:"php"'))

        print(f"[*] {len(raw_urls)} raw candidates — fingerprinting...")
        results = []
        with cf.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self.fingerprint, u): u for u in raw_urls}
            for fut in cf.as_completed(futs):
                info = fut.result()
                if info["status"] not in (None, "error"):
                    results.append(info)

        # dedupe by host
        seen = {}
        for info in results:
            host = urlparse(info["url"]).netloc
            if host not in seen:
                seen[host] = info
        deduped = list(seen.values())

        # score: PHP version known + old = higher priority
        for info in deduped:
            score = 0
            ver = info.get("php_version")
            if ver:
                try:
                    major_minor = tuple(int(x) for x in ver.split(".")[:2])
                    if major_minor < (7, 4):
                        score += 40
                    elif major_minor < (8, 1):
                        score += 25
                except Exception:
                    pass
            if info.get("x_powered_by"):
                score += 15
            if info.get("cms"):
                score += 20
            if re.search(r"\.php\?(id|page|file|include|cat|path|doc|cont)=", info["url"], re.I):
                score += 15
            info["score"] = score

        deduped.sort(key=lambda x: -x["score"])
        return deduped


def main():
    ap = argparse.ArgumentParser(description="php2shell target scraper")
    ap.add_argument("--engines", default="bing,ddg", help="comma list: bing,ddg,shodan")
    ap.add_argument("--pages", type=int, default=2)
    ap.add_argument("--shodan-key", default=None)
    ap.add_argument("--shodan-query", default=None)
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("-o", "--output", default="targets.json")
    args = ap.parse_args()

    engines = tuple(e.strip() for e in args.engines.split(",") if e.strip())
    scraper = TargetScraper(shodan_key=args.shodan_key, threads=args.threads)
    targets = scraper.run(
        engines=engines,
        pages=args.pages,
        use_shodan="shodan" in engines,
        shodan_query=args.shodan_query,
    )

    out = Path(args.output)
    out.write_text(json.dumps(targets, indent=2))
    print(f"[+] {len(targets)} targets → {out.resolve()}")
    for t in targets[:15]:
        print(f"  [{t['score']:>3}] {t['url']}  server={t.get('server')} php={t.get('php_version')} cms={t.get('cms')}")


if __name__ == "__main__":
    main()
