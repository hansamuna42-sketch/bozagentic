# FIX LOG — /root/rework

Scan: Bandit 1.9.4 + runtime test 135 file Python.
Hasil: 37 file gagal runtime → 134/135 jalan. Bandit HIGH 17 → 0 (2 sisa by design).

---

## 1. BUG: `datetime.UTC` tidak ada di Python 3.10

**File:**
- `.hermes/skills/productivity/google-workspace/scripts/google_api.py`
- `.hermes/skills/productivity/google-workspace/scripts/gws_bridge.py`

**Sebelum:**
```python
from datetime import datetime, timedelta, timezone, UTC
```
`datetime.UTC` baru ada di Python 3.11+. Sistem ini Python 3.10 → `ImportError`.

**Sesudah:**
```python
from datetime import datetime, timedelta, timezone
try:  # Python 3.11+
    from datetime import UTC
except ImportError:  # Python 3.10 and older
    UTC = timezone.utc
```

---

## 2. BUG: module `memory/rotation.py` hilang

**File:**
- `syadagentic/arsenal-skills/skills-lengkap/bug-bounty/bug-bounty/tools/memory/rotation.py` (BARU)
- `syadagentic/arsenal-skills/skills-lengkap/bug-bounty/bug-bounty/tools/memory_gc.py` (consumer, tidak diubah)

**Sebelum:** `memory_gc.py` import 6 simbol dari `memory.rotation`, tapi folder `memory/` tidak ada → `ModuleNotFoundError`.

**Sesudah:** module lengkap dibuat:
- `DEFAULT_MAX_BYTES` = 10 MB, `DEFAULT_KEEP` = 3
- `list_backups(path, keep)` — daftar backup, newest first
- `total_bytes(path, keep)` — ukuran live + semua backup
- `rotate_if_needed(path, max_bytes, keep)` — rotate kalau ≥ cap
- `purge_backups(path, keep)` — hapus backup di luar keep

**Diuji:** rotate file 11 MB → `audit.jsonl.1` (11 MB), live hilang. Purge `--keep 0` → 1 file dibuang.

---

## 3. BUG KEAMANAN: `shell=True` + f-string → command injection

**File:**
- `syadagentic/arsenal-skills/skills-lengkap/affiliate/threads-auto-post/scripts/cron_post.py` (9 lokasi)
- `syadagentic/arsenal-skills/skills-lengkap/bug-bounty/bug-bounty/tools/hunt.py` (4 lokasi)
- `syadagentic/arsenal-skills/skills-lengkap/bug-bounty/bug-bounty/tools/zero_day_fuzzer.py` (1)
- `syadagentic/gate/gate.py` (1)

**Sebelum:**
```python
subprocess.run(f'camoufox --session {session_name} click {ref_id}', shell=True, ...)
```
`session_name` / `ref_id` / `domain` / `script` masuk shell mentah. Path dengan spasi, `;`, `$(...)` bisa inject.

**Sesudah:**
```python
subprocess.run(['camoufox', '--session', session_name, 'click', str(ref_id)], ...)
```
List-form, tanpa shell. Argumen dikirim literal.

Catatan `gate.py`: `stage3_evidence()` sekarang terima string ATAU list — string di-split otomatis biar caller lama gak rusak.

---

## 4. BUG: hash lemah MD5

**File:** `syadagentic/arsenal-skills/skills-lengkap/bug-bounty/bug-bounty/tools/zero_day_fuzzer.py:102`

**Sebelum:** `hashlib.md5(body.encode()[:1000])`
**Sesudah:** `hashlib.sha256(body.encode()[:1000])`

Signature tetap 8 char pertama, jadi format output gak berubah.

---

## 5. BUG: `requests` tanpa timeout → bisa hang selamanya

**File (5):**
- `syadagentic/arsenal-skills/skills-lengkap/affiliate/threads-auto-reply/scripts/threads_comment_cdp.py`
- `syadagentic/arsenal-skills/skills-lengkap/affiliate/threads-auto-reply/scripts/threads_full_flow.py`
- `syadagentic/arsenal-skills/skills-lengkap/affiliate/threads-auto-reply/scripts/threads_reply_cdp.py`
- `syadagentic/arsenal-skills/skills-lengkap/affiliate/threads-auto-post/scripts/threads_comment_cdp.py`
- `syadagentic/arsenal-skills/skills-lengkap/affiliate/threads-auto-post/scripts/threads_full_flow.py`

**Sebelum:** `requests.get(f"http://localhost:{CHROME_PORT}/json").json()`
**Sesudah:** `requests.get(f"http://localhost:{CHROME_PORT}/json", timeout=10).json()`

---

## 6. DOKUMENTASI (tanpa perubahan kode)

**File:**
- `syadagentic/arsenal-skills/skills-lengkap/bug-bounty/bug-bounty/tools/breach_checker.py`
- `syadagentic/php2shell/tests/mock_vuln_target.py`

Ditambah komentar penjelas kenapa pola "berbahaya" di sini memang disengaja:
- `breach_checker.py` — SHA-1 diwajibkan API HIBP k-anonymity `/range/`, bukan hash penyimpanan password.
- `mock_vuln_target.py` — `shell=True` sengaja, ini mock server rentan untuk tes deteksi shell upload.

---

## TIDAK DIUBAH (false positive Bandit)

| Item | Jumlah | Alasan |
|---|---|---|
| `assert` dipakai | 379 | Wajar di test file |
| import `random` / `telnetlib` | 58 | Normal untuk tooling |
| `try/except/pass` | 51 | Bikin bug senyap, tapi bukan bug |
| hardcoded `/tmp/` | 25 | Bisa symlink attack, tapi risiko rendah di single-user |
| `security_scan.py` regex `shell=True` | 1 | Ini **regex deteksi**, bukan eksekusi |
| `hai_payload_builder.py` string `shell=True` | 1 | Ini **payload SSTI string**, bukan subprocess |

---

## DEPENDENCY (bukan bug — install package)

34 file gagal karena package belum terinstall. Sudah diinstall:

```
websocket-client  browser-cookie3  web3  pytest
python-pptx  lxml  openpyxl  python-docx
```

---

## HASIL AKHIR

| Metrik | Sebelum | Sesudah |
|---|---|---|
| Syntax error | 0 | 0 |
| Runtime gagal | 37 | **1** (by design) |
| Bandit HIGH | 17 | **0** |
| Bandit MEDIUM | 71 | 65 |
| Bandit LOW | 611 | 633 |
