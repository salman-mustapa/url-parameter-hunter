# 🐙 Hunter Aja — Bug Hunting Platform (V7.1)
### Evidence-First Deep Validation & Professional Disclosure Architecture

Catatan implementasi terkini: [audit AI-first, policy HackerOne, realtime, dan batas cakupan](docs/AI_FIRST_RELIABILITY_AUDIT_2026-09-03.md) serta [validasi rilis Docker 4 September 2026](docs/RELEASE_VALIDATION_2026-09-04.md). Hasil tes lokal tidak menjamin bebas timeout/error atau deteksi seluruh kerentanan. Validator legacy belum memiliki executor produksi untuk target eksternal.

<p align="center">
  <img src="https://img.shields.io/badge/Version-7.1_V5-7C3AED?style=for-the-badge&logo=shield&logoColor=white" alt="Version 7.1" />
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Realtime-SSE_Stream-FF6B6B?style=for-the-badge" alt="SSE" />
  <img src="https://img.shields.io/badge/Evidence-SHA--256_Integrity-10B981?style=for-the-badge" alt="Integrity" />
  <img src="https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge" alt="License" />
</p>

---

## 🎯 1. Filosofi & Prinsip Utama (V7.1 Architecture)

**Hunter Aja V7.1** mengubah paradigma platform keamanan dari sekadar pemindai pasif (*Scanner ➔ Finding ➔ Report*) menjadi sistem validasi mendalam berorientasi bukti (**Evidence-First Deep Validation Architecture**). 

Tujuan utamanya adalah mentransformasikan observasi mentah scanner menjadi **temuan terverifikasi, dapat direproduksi, tahan bantahan (defensible), dengan evidence package berkualitas tinggi dan laporan disclosure profesional**.

```text
DISCOVER
   ↓
CORRELATE
   ↓
TRIAGE
   ↓
APPLICABILITY
   ↓
CONTROLLED VALIDATION
   ↓
IMPACT PROOF
   ↓
EVIDENCE PACKAGE (SHA-256 Sealed)
   ↓
PROOF QUALITY GATE (12 Checks)
   ↓
PROFESSIONAL DISCLOSURE (PDF / Bug Bounty / CVE / Markdown)
   ↓
LIVE RETEST (Before vs After Diff)
```

Setiap temuan yang dihasilkan sistem harus mampu menjawab 5 pertanyaan kunci:
1. **What was found?** (Apa yang ditemukan?)
2. **Why is it actually vulnerable?** (Mengapa ini benar-benar rentan?)
3. **What can an authorized attacker achieve?** (Apa dampak konkret yang dapat dicapai?)
4. **What evidence proves that impact?** (Bukti apa yang memvalidasi dampak tersebut?)
5. **How can the owner reproduce, understand, and fix it?** (Bagaimana pemilik sistem mereproduksi dan memperbaikinya?)

---

## 💎 2. Model Kualitas Bukti (Evidence Quality Model: E0 – E4)

Setiap temuan diklasifikasikan ke dalam tingkatan bukti yang ketat. **Status code 200, open port, atau error 500 semata BUKAN merupakan temuan CONFIRMED**:

| Level | Klasifikasi | Status | Kriteria Bukti |
|---|---|---|---|
| **E0** | **Observation** | `OBSERVED` | Port terbuka, respon HTTP 200, banner versi, teknologi terdeteksi, atau kandidat CVE (belum diverifikasi). |
| **E1** | **Technical Indicator** | `CANDIDATE` | Respon anomali diferensial, parameter terefleksi, potensi kelemahan otentikasi. |
| **E2** | **Reproducible Vulnerability** | `VALIDATED` | Kondisi keamanan dapat direproduksi secara terkontrol dan non-destruktif. |
| **E3** | **Demonstrated Security Impact** | `CONFIRMED` | Dampak keamanan terbukti nyata dengan bukti minimal yang diperlukan (*Minimum Necessary Proof*). |
| **E4** | **Full Impact Evidence** | `CONFIRMED` | Pembuktian dampak menyeluruh terotorisasi dengan audit trail lengkap dan sanitasi data sensitif. |

### Formula Skor Bukti (Evidence Score: 0 – 100):
- **Base Level:** `E0` = 10 · `E1` = 30 · `E2` = 55 · `E3` = 75 · `E4` = 85
- **Bonus Kualitas:** Corroboration (+10) · Screenshot/Payload (+5) · Controlled Reproduction (+10)
- **Maksimum:** 100 poin (Metrik kualitas bukti, terpisah dari Severity keparahan).

---

## ⚡ 3. Fitur Unggulan (Core Capabilities)

### 🌐 A. Dynamic Subdomain & Active Reconnaissance
- **Multi-Source Passive Harvesting:** Mengintegrasikan Certificate Transparency (crt.sh), AlienVault OTX, HackerTarget, Anubis Dataset, dan Archive.org Wayback DNS.
- **Wildcard DNS Detection & Filter:** Menguji token canary acak untuk memetakan IP catch-all wildcard DNS, mencegah ribuan subdomain palsu masuk ke graf aset.
- **Smart Permutation Engine (Alter-DNS):** Menghasilkan mutasi prefiks/sufiks dinamis (`dev-`, `staging-`, `-api`, `-v1`, `-internal`, `-auth`) berdasarkan aset aktif yang ditemukan.
- **Active Reachability Verification:** Resolusi DNS konkuren multi-record (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`) untuk memvalidasi host yang benar-benar aktif.

### 🕷️ B. Intelligent Dynamic Web Crawler & JavaScript Route Miner
- **Multi-Depth Recursive Crawler:** Menjelajahi tautan HTML (`<a>`, `<form>`, `<iframe src>`, `<button formaction>`) secara rekursif hingga kedalaman terkonfigurasi.
- **JavaScript Route & Endpoint Scraper (`extract_js_endpoints`):** Membedah berkas `.js` dan webpack chunks untuk mengekstrak route REST API (`/api/v1/...`), GraphQL queries, dan endpoint `fetch()` / `axios`.
- **Passive URL Harvester:** Mengambil daftar endpoint historis dari AlienVault OTX dan Archive.org Wayback CDX API.
- **Recursive Sitemap & Robots Parser:** Membaca `sitemap.xml`, `sitemap_index.xml`, `.well-known/`, dan `robots.txt` secara otomatis.
- **Dynamic Parameter Mining (Heuristic Differential Analysis):** Fuzzing parameter cerdas pada endpoint fungsional untuk menemukan parameter tersembunyi (`id`, `file`, `redirect`, `token`, `next`, `debug`, dll) berbasis refleksi nilai dan anomali ukuran respons.

### 🛡️ C. Anti-Noise Rules & Strict Content Signature Verification (§40, §44)
- **Soft-404 Baseline Detector:** Mengirim token acak (`/_hunter_canary_404_<uuid>`) untuk mengukur baseline status code, content-length, dan body hash. Menghilangkan false positive pada server SPA / custom 404 handler yang mengembalikan status 200 OK.
- **Content Signature & Magic Byte Verification:**
  - `/.git/HEAD` & `/.git/config`: Wajib berformat ref git asli (`ref: refs/heads/` atau hash SHA commit 40-karakter / `[core]`). Menolak semua respons berformat HTML webpage.
  - `/.env`: Wajib memuat pasangan key-value konfigurasi (`APP_KEY=`, `DB_PASSWORD=`, `SECRET=`).
  - `/backup.sql`: Wajib memuat sintaks DDL/DML SQL dump (`CREATE TABLE`, `INSERT INTO`, `-- MySQL dump`).
  - `/phpinfo.php`: Wajib memuat tabel diagnostik PHP resmi (`PHP Version`, `phpinfo()`).
  - `/swagger.json` & `/openapi.json`: Wajib lolos validasi skema JSON OpenAPI/Swagger.

### 🔬 D. Deep Validation Adapters & Proof Quality Gate (§38, §40)
- **Vulnerability Adapters:** Modul validasi mendalam untuk SQL Injection (Error/Time/Union-based), Reflected XSS, Server-Side Request Forgery (SSRF), Path Traversal, Open Redirect, dan Information Exposure.
- **12-Point Proof Quality Gate Checklist:**
  1. `Scope authorized`
  2. `Target identified`
  3. `Vulnerability reproducible`
  4. `Impact demonstrated (Impact Matrix: C/I/A/Auth/DataExposure)`
  5. `Evidence payload captured`
  6. `ISO timestamp recorded`
  7. `SHA-256 cryptographic hash generated`
  8. `Cleanup verified`
  9. `False-positive anti-noise checks passed`
  10. `Severity calculated`
  11. `CWE mapping assigned`
  12. `CVE applicability checked`

### 🔄 E. Live Non-Destructive Retest Engine (§34, §42)
- Menjalankan retest langsung ke endpoint target menggunakan parameter dan payload PoC asli.
- Membandingkan **Before Evidence** vs **After Evidence** secara komparatif.
- Mengubah lifecycle status secara otomatis menjadi `FIXED` (Passed) atau `REOPENED` (Failed) disertai catatan putusan verifikasi.

### 📄 F. Multi-Format Professional Disclosure Reporting (§24, §31, §32, §33)
- **Executive PDF Report:** Laporan resmi berstandar audit dengan kop, ringkasan telemetri, matriks port, inventaris teknologi, dan PoC terstruktur.
- **Bug Bounty Disclosure Report (.md):** Format terstruktur siap-kirim untuk platform HackerOne dan Bugcrowd.
- **CVE-Ready Research Report (.md):** Format pelaporan riset kerentanan baru untuk koordinasi CNA / vendor disclosure.
- **Reproduction Bundle (`reproduction.md`):** Panduan reproduksi langkah-demi-langkah terisolasi untuk tim pengembang.
- **Cryptographic Evidence Package (`.json`):** Berkas paket bukti terenkapsulasi dengan hash integritas SHA-256.

---

## 🏛️ 4. Arsitektur Teknis Sistem

```text
                                  Client Browser UI (Dark Theme)
                                                │
                                ┌───────────────┴───────────────┐
                                │ REST API & Realtime SSE Stream │
                                └───────────────┬───────────────┘
                                                │
                                        FastAPI Gateway
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 ▼                              ▼                              ▼
           Scope Engine                   Scan Manager                     Event Bus
          (ScopeGuard §5)               (Orchestrator)                 (Realtime SSE)
                 │                              │                              │
                 ▼                              ▼                              │
         Target Normalization          Pipeline Lifecycle                      │
                                       ┌─────────────────┐                     │
                                       │ 1. Subdomain    │ ➔ CT/OTX/DNS        │
                                       │    Discovery    │ ➔ Wildcard Filter   │
                                       ├─────────────────┤                     │
                                       │ 2. DNS & Ports  │ ➔ TCP Banner        │
                                       │    Probing      │ ➔ TLS Cert Audit    │
                                       ├─────────────────┤                     │
                                       │ 3. Dynamic Web  │ ➔ JS Route Scraper  │
                                       │    Crawler      │ ➔ Parameter Miner   │
                                       ├─────────────────┤                     │
                                       │ 4. Validation   │ ➔ Content Signature │
                                       │    & Proof Gate │ ➔ Anti-Noise Check  │
                                       ├─────────────────┤                     │
                                       │ 5. Evidence     │ ➔ SHA-256 Hashes    │
                                       │    Packaging    │ ➔ Evidence Package  │
                                       ├─────────────────┤                     │
                                       │ 6. Reporting &  │ ➔ PDF / Bug Bounty  │
                                       │    Live Retest  │ ➔ Before/After Diff │
                                       └─────────────────┘                     │
                                                │                              │
                                                ▼                              ▼
                                     PostgreSQL / SQLite ◀─────────────────────┘
```

---

## 🚀 5. Panduan Instalasi & Menjalankan

### Prasyarat
- Python 3.12+
- Git

### Langkah 1: Clone Repository
```bash
git clone https://github.com/salman-mustapa/url-parameter-hunter.git
cd url-parameter-hunter
```

### Langkah 2: Buat Virtual Environment & Install Dependencies
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# Linux/macOS:
source venv/bin/activate

# Install dependencies:
pip install -r requirements.txt
```

### Langkah 3: Konfigurasi Environment (`.env`)
Salin berkas konfigurasi template:
```bash
copy .env.example .env   # Windows
cp .env.example .env     # Linux/macOS
```

Isi variabel konfigurasi di `.env`:
```ini
APP_NAME=Hunter Aja
APP_ENV=development
JWT_SECRET=replace_with_a_random_secret_at_least_32_characters
COOKIE_SECURE=false
DATABASE_URL=sqlite+aiosqlite:///./storage/hunter.db
PORT=9001
RATE_LIMIT_RPS=15
MAX_WEB_HOSTS=25
MAX_URLS_PER_SCAN=300
HTTP_TIMEOUT_SECONDS=8.0
```

### Langkah 4: Jalankan Server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 9001 --reload
```

Buka antarmuka web di browser: **`http://localhost:9001`**

---

## 🐳 6. Menjalankan dengan Docker Compose

Untuk instalasi pertama, salin template lalu isi `.env`. Minimal gunakan
`JWT_SECRET` acak minimal 32 karakter dan kredensial administrator awal yang kuat.
AI default-nya nonaktif sampai endpoint, key, model, dan mode routing yang nyata
diisi; ini mencegah placeholder dianggap sebagai kredensial.

```bash
cp .env.example .env
# edit .env; untuk NineRouter isi LLM_ENABLED=true, LLM_BASE_URL,
# LLM_API_KEY, LLM_MODEL, dan LLM_ROUTING_MODE
docker compose config --quiet
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:9001/health
```
Akses platform di `http://localhost:9001`.

Untuk memperbarui server yang sudah mempunyai `.env`:

```bash
git pull --ff-only origin master
docker compose config --quiet
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:9001/health
```

Jangan menimpa `.env` server dengan `.env.example`; `.env` tidak masuk Git. Compose
meneruskan timeout/mode routing AI, batas scan, SSE, dan fallback Hermes yang baru.
Biarkan `HERMES_BASE_URL` serta `HERMES_API_KEY` kosong untuk mode NineRouter-only.

---

## 🧪 7. Pengujian & status audit

```bash
python -m pytest -q -p no:cacheprovider
node --test tests/frontend_runtime.test.cjs
python -m pip check
```

Tes memakai database sementara dan fixture lokal. Hasilnya bukan sertifikasi keamanan target atau bukti performa produksi.
Lihat [audit 28 Agustus 2026](docs/PROJECT_AUDIT_2026-08-28.md) untuk perubahan, hasil verifikasi, prasyarat deployment, dan pekerjaan lanjutan.

Alur utama: isi target dan izin → mulai/antrekan scan → tinjau temuan dan bukti → lengkapi identitas pada Laporan → buat export baru.
Scan aktif memerlukan `authorization_reference`. Form UI juga meminta pengakuan izin; aturan terstruktur mendukung host, pengecualian, port (default 80/443), periode, dan batas HTTP RPS.
Metadata laporan dapat diperbarui melalui `GET/PUT /api/scans/{scan_id}/report-profile`; endpoint ini tidak mengubah scope/izin yang telah direkam.

`MAX_CONCURRENT_SCANS=2` dan `MAX_PENDING_SCANS=20` membatasi runner API per proses. Domain yang sama diserialkan.
Gunakan satu proses runner ini; deployment banyak worker membutuhkan koordinasi antrean dan limit terdistribusi, belum dijamin oleh semaphore lokal.

Screenshot asli bersifat opsional (`BROWSER_CAPTURE_ENABLED=false` secara default). Siapkan extra `browser` dari `pyproject.toml`, Chromium Playwright, sandbox browser, dan kontrol egress sebelum mengaktifkan.
Tidak ada gambar pengganti ketika capture gagal. Capture membatasi GET/HEAD satu host, memblokir resource eksternal/worker/socket, dan menyimpan provenance/hash.
Logo laporan diunggah sebagai PNG/JPEG maksimal 256 KiB; URL logo tidak diambil otomatis. Branding bukan bukti kerentanan.

Untuk produksi: `APP_ENV=production`, JWT acak minimal 32 karakter, HTTPS dan `COOKIE_SECURE=true`, serta kredensial database yang unik.

---

## 📡 8. Ringkasan API Endpoints Utama

### Otentikasi & Pengguna
- `POST /api/auth/register` — Pendaftaran akun pengguna baru.
- `POST /api/auth/login` — Autentikasi dan penerbitan JWT token.
- `GET /api/auth/me` — Profil pengguna aktif & status role.

### Scan Management
- `POST /api/scans` — Memulai sesi scan baru (Target domain, Profile, Recursive toggle).
- `GET /api/scans` — Daftar seluruh riwayat scan pengguna.
- `GET /api/scans/{id}` — Detail status & progres scan.
- `GET /api/scans/{id}/events` — Real-time Server-Sent Events (SSE) log stream.
- `POST /api/scans/{id}/pause` / `resume` / `stop` — Kontrol status scan aktif.

### Asset Graph & Explorers
- `GET /api/assets/tree?scan_id={id}` — Graf hierarki aset pohon (Root ➔ Subdomain ➔ IP).
- `GET /api/scans/{id}/ports/all` — Matriks port & layanan global seluruh subdomain.
- `GET /api/scans/{id}/parameters/all` — Explorer parameter terdeteksi & hasil mining.
- `GET /api/diff?current={id}&previous={id}` — Analisis diferensial perbandingan 2 scan.

### Findings, Evidence & Reporting
- `GET /api/findings?scan_id={id}` — Daftar temuan beserta tingkat bukti dan status validasi; tidak semuanya terverifikasi.
- `GET /api/findings/{id}/detail` — Detail temuan mendalam, Impact Matrix, dan Root Cause.
- `GET /api/findings/{id}/evidence-package` — Unduh Evidence Package terenkapsulasi (.json).
- `GET /api/findings/{id}/bugbounty` — Unduh laporan format Bug Bounty HackerOne (.md).
- `GET /api/findings/{id}/cve-ready` — Unduh laporan format CVE Research Disclosure (.md).
- `GET /api/findings/{id}/reproduction` — Unduh panduan reproduksi PoC (`reproduction.md`).
- `POST /api/findings/{id}/retest` — Retest yang memerlukan otorisasi tersimpan; timeout atau respons kosong berstatus inconclusive.
- `GET /api/scans/{id}/report/pdf` — Unduh laporan eksekutif resmi format PDF.
- `GET /api/scans/{id}/report/html` — Buka laporan web HTML interaktif.
- `GET /api/scans/{id}/report/markdown` — Unduh laporan teknis format Markdown.

---

## 📄 9. Lisensi & Penafian Keamanan (Disclaimer)

Didistribusikan di bawah lisensi **MIT License**.

> [!CAUTION]
> **Peringatan Penggunaan Terotorisasi:** Platform Hunter Aja dirancang khusus untuk pengujian keamanan defensif, audit internal organisasi, dan program Bug Bounty terotorisasi. Selalu pastikan Anda memiliki izin tertulis yang sah sebelum memindai sistem atau domain pihak ketiga. Penggunaan tanpa izin melanggar hukum yang berlaku.
