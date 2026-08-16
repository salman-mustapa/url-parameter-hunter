# 🐙 Hunter Aja — Attack Surface & Parameter Intelligence Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Realtime-SSE_Stream-FF6B6B?style=for-the-badge" alt="SSE" />
  <img src="https://img.shields.io/badge/Database-PostgreSQL_%2F_SQLite-336791?style=for-the-badge&logo=postgresql&logoColor=white" alt="Database" />
  <img src="https://img.shields.io/badge/Architecture-Asynchronous_Pipeline-10B981?style=for-the-badge" alt="Async" />
  <img src="https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge" alt="License" />
</p>

---

## 🎯 Overview

**Hunter Aja** adalah platform *Continuous Attack Surface Discovery*, *Dynamic Subdomain Intelligence*, dan *Web Parameter Hunting* berbasis web modern. Dirancang dengan filosofi **Single-Menu Operation**, platform ini memungkinkan *security researcher*, *bug bounty hunter*, dan *DevSecOps engineer* untuk cukup memasukkan **root domain** target, dan secara otomatis menjalankan seluruh alur *reconnaissance* multi-tahap secara paralel di background.

Hasil pemindaian disajikan secara **real-time melalui Server-Sent Events (SSE)** ke antarmuka web bergaya *Neo-Brutalist Sketch* yang bersih, interaktif, dan responsif.

---

## ✨ Fitur Utama

- 🌐 **Dynamic & Active Subdomain Discovery**
  - Menggabungkan sumber pasif (*Certificate Transparency* crt.sh, AlienVault OTX, HackerTarget) dan enumerasi aktif *wordlist*.
  - **Active Reachability Verification**: Melakukan resolusi DNS konkuren untuk memastikan hanya subdomain yang **benar-benar aktif/resolvable** yang dimasukkan ke dalam graf aset (menghilangkan *noise* domain mati).
  - Pembentukan hierarki parent-child otomatis (`root` ➔ `subdomain` ➔ `child subdomain`).

- 🔒 **Strict Scope Enforcement Engine**
  - Normalisasi domain berbasis *Public Suffix List* (`tldextract`).
  - Pencegahan pemindaian aset di luar scope resmi (validasi target redirect, CNAME eksternal, dan batasan CIDR).

- 📡 **Multi-Record DNS Resolution & IP Mapping**
  - Resolusi otomatis untuk `A`, `AAAA`, `CNAME`, `MX`, `TXT`, dan `NS`.
  - Pemetaan hubungan aset IP ke Hostname secara dinamis.

- 🔌 **Adaptive TCP Port Scanner**
  - Pemindaian port non-blocking dengan *rate-limiter* adaptif (mencegah kelebihan beban jaringan).
  - *Banner grabbing* ringan untuk identifikasi versi service (HTTP, SSH, SMTP, MySQL, Redis, dll).
  - Profil fleksibel: `Standard` (Port umum) & `Deep` (1-1024 + extended ports).

- 🌐 **HTTP/HTTPS Probing & TLS Inspection**
  - Deteksi otomatis respons HTTP/HTTPS, kode status, waktu latensi, dan judul halaman.
  - Ekstraksi sertifikat TLS: Subject CN, Issuer, Subject Alternative Names (SAN), tanggal masa berlaku, serta algoritma tanda tangan.
  - Audit *Security Headers* (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).

- ⚙️ **Technology Fingerprinting Engine**
  - Mengidentifikasi Web Server (Nginx, Apache, IIS, Caddy), CMS (WordPress), Framework (Laravel, Django, Spring Boot, Express, Rails, Next.js, Nuxt), dan CDN/WAF (Cloudflare, Fastly).

- 🕷️ **Endpoint Crawler & Parameter Hunter**
  - Ekstraksi endpoint otomatis dari `robots.txt`, `sitemap.xml`, jalur API umum, dan *shallow link crawling*.
  - Pemetakan parameter query URL dan input form HTML (`query`, `body`, `header`).

- 🛡️ **Non-Destructive Security Audit Engine**
  - Pemisahan ketat antara *Observation* dan *Finding* untuk meminimalkan *false positive*.
  - Deteksi eksposur file sensitif (`.env`, `.git/HEAD`, arsip cadangan `.zip`/`.sql`, phpinfo).
  - Deteksi sertifikat SSL/TLS yang kedaluwarsa atau mendekati masa kedaluwarsa.
  - Deteksi portal administrasi publik dan dokumentasi API interaktif (Swagger/OpenAPI).

- 📊 **Riwayat Persistent & Differential Scan (Diff Analyzer)**
  - Semua aset dan event tersimpan secara persisten.
  - **Diff Analyzer**: Membandingkan 2 scan pada domain yang sama untuk menemukan subdomain baru (+), subdomain mati (-), port baru, dan temuan baru.

- 🎨 **Neo-Brutalist Sketch UI**
  - Estetika modern, bersih, dan playful terinspirasi dari gaya *sketch-doodle*.
  - Live terminal stream dengan filter kategori (Discovery, DNS, Port, HTTP, URL, Param, Tech, Finding).
  - Interactive Expandable Asset Tree dan panel inspeksi detail aset.
  - Fitur triaging temuan (*Open*, *Confirmed*, *False Positive*, *Fixed*).
  - Ekspor laporan pemindaian instan dalam format JSON.

---

## 🏛️ Arsitektur Sistem

```text
                             Browser Web Client
                                     │
                     ┌───────────────┴───────────────┐
                     │ REST API & Realtime SSE Stream │
                     └───────────────┬───────────────┘
                                     │
                             FastAPI Gateway
                                     │
                 ┌───────────────────┼───────────────────┐
                 │                   │                   │
                 ▼                   ▼                   ▼
           Scope Engine        Scan Manager         Event Bus
                 │                   │                   │
                 │         ┌─────────┴─────────┐         │
                 ▼         ▼                   ▼         ▼
             Validated   Task Pipeline      Task Pipeline
              Domain       (Phase 1-3)        (Phase 4-5)
                           ┌─────────┐        ┌─────────┐
                           │Discovery│        │Crawler &│
                           │  & DNS  │        │ Params  │
                           └────┬────┘        └────┬────┘
                                │                  │
                           ┌────┴────┐        ┌────┴────┐
                           │Port Scan│        │Security │
                           │ & HTTP  │        │ Engine  │
                           └────┬────┘        └────┬────┘
                                │                  │
                                └─────────┬────────┘
                                          │
                                    Result Engine
                                          │
                       ┌──────────────────┴──────────────────┐
                       ▼                                     ▼
             PostgreSQL / SQLite Database              Live SSE Clients
              (Persistent Graph & History)          (Realtime Browser Logs)
```

---

## 🚀 Panduan Instalasi & Menjalankan

### Opsi 1: Menjalankan Lokal (Development Cepat dengan SQLite)

Hunter Aja memiliki dukungan *zero-configuration* bawaan untuk SQLite lokal:

1. **Clone Repository & Siapkan Virtualenv**:
   ```bash
   git clone <repository_url>
   cd url-parameter-hunter
   python -m venv .venv
   
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. **Instal Dependensi**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Jalankan Server Aplikasi**:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 9001 --reload
   ```

4. **Buka Aplikasi**:
   Akses antarmuka browser di **[http://localhost:9001](http://localhost:9001)**.
   Dokumentasi Swagger API interaktif tersedia di **[http://localhost:9001/docs](http://localhost:9001/docs)**.

---

### Opsi 2: Menjalankan dengan Docker Compose (Production Ready)

Untuk skalabilitas penuh dengan PostgreSQL:

1. **Salin Environment Template**:
   ```bash
   cp .env.example .env
   ```

2. **Jalankan Multi-Container**:
   ```bash
   docker compose up -d --build
   ```

3. **Periksa Status Container**:
   ```bash
   docker compose ps
   ```

4. Buka **[http://localhost:9001](http://localhost:9001)**.

---

## ⚙️ Konfigurasi Environment (`.env`)

| Variabel | Default | Keterangan |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///storage/bughunter.db` | URL koneksi basis data (PostgreSQL atau SQLite) |
| `CORS_ORIGINS` | `*` | Alamat domain yang diizinkan untuk CORS |
| `RATE_LIMIT_RPS` | `15` | Batas maksimum request per detik per target |
| `MAX_CONCURRENT_HOSTS` | `12` | Jumlah probe host simultan |
| `MAX_ASSETS_PER_SCAN` | `2500` | Batas maksimum aset per satu kali scan |
| `MAX_URLS_PER_SCAN` | `20000` | Batas maksimum URL yang dicrawl per scan |
| `MAX_RUNTIME_MINUTES` | `45` | Batas waktu timeout pemindaian (menit) |
| `PORT_TIMEOUT_SECONDS` | `1.5` | Timeout probe TCP socket (detik) |
| `HTTP_TIMEOUT_SECONDS` | `8.0` | Timeout request HTTP (detik) |
| `SECURITY_MODE` | `SAFE` | Mode pengujian keamanan (`SAFE` / `STANDARD`) |

---

## 📡 Ringkasan REST API

| Method | Endpoint | Deskripsi |
|---|---|---|
| `POST` | `/api/scans?target={domain}&profile={p}` | Memulai pemindaian baru |
| `GET` | `/api/scans` | Menampilkan seluruh riwayat scan |
| `GET` | `/api/scans/{scan_id}` | Mengambil informasi status scan |
| `POST` | `/api/scans/{scan_id}/pause` | Menjeda proses scan yang berjalan |
| `POST` | `/api/scans/{scan_id}/resume` | Melanjutkan scan yang dijeda |
| `POST` | `/api/scans/{scan_id}/stop` | Menghentikan scan secara permanen |
| `GET` | `/api/scans/{scan_id}/events` | Stream realtime event SSE (`text/event-stream`) |
| `GET` | `/api/assets/tree?scan_id={id}` | Struktur hierarki pohon aset (Parent-Child) |
| `GET` | `/api/assets/{asset_id}` | Rincian lengkap aset (Port, URL, Param, Tech, Cert) |
| `GET` | `/api/findings?scan_id={id}` | Daftar temuan keamanan pada scan |
| `PATCH` | `/api/findings/{id}?status={s}` | Mengubah status triaging temuan |
| `GET` | `/api/domains` | Daftar domain yang pernah discan terkelompok |
| `GET` | `/api/domains/{domain}/history` | Riwayat kronologis scan pada domain tertentu |
| `GET` | `/api/diff?current={id}&previous={id}` | Perbandingan diferensial antara 2 scan |
| `GET` | `/api/scans/{scan_id}/export` | Unduh laporan lengkap scan (JSON) |
| `GET` | `/api/metrics` | Metrik agregasi sistem dan aset |

---

## 📂 Struktur Direktori Proyek

```text
url-parameter-hunter/
├── app/
│   ├── api/
│   │   └── router.py             # Router REST API & SSE Endpoints
│   ├── core/
│   │   ├── config.py             # Pengaturan Pydantic & Defaults
│   │   ├── db.py                 # Engine Async SQLAlchemy (Postgres/SQLite)
│   │   ├── events.py             # In-memory Event Bus & Pub/Sub
│   │   ├── logging.py            # Konfigurasi Structured Logging
│   │   ├── rate_limit.py         # Leaky-Bucket Rate Limiter
│   │   ├── retry.py              # Exponential Backoff Decorator
│   │   └── scope.py              # Scope Enforcement & PSL Normalizer
│   ├── models/
│   │   └── models.py             # Skema Tabel Database (Asset, Port, URL, Finding, dll)
│   ├── scanners/
│   │   ├── base.py               # Interface ScanContext & Kontrak Scanner
│   │   ├── subdomain.py          # Dynamic Active Subdomain Discovery
│   │   ├── dns.py                # Multi-Record DNS Resolver & IP Graph
│   │   ├── port.py               # Async TCP Socket Port Scanner
│   │   ├── http.py               # HTTP Probe, TLS Analyzer & Tech Detection
│   │   ├── web.py                # Web Crawler & Parameter Hunter
│   │   └── security.py           # Non-destructive Security Engine
│   ├── services/
│   │   ├── assets.py             # Query Builder Pohon Aset Hierarkis
│   │   ├── results.py            # Result Engine, Normalizer & Deduplicator
│   │   └── scan_manager.py       # Orchestrator Siklus Hidup Scan
│   └── main.py                   # Entrypoint FastAPI & SPA Static Mounter
├── frontend/
│   ├── css/
│   │   └── styles.css            # Desain Neo-Brutalist Sketch System
│   ├── js/
│   │   └── app.js                # Frontend Reactive SPA & SSE Handler
│   └── index.html                # Antarmuka Dashboard Satu Pintu
├── wordlists/
│   └── subdomains.txt            # Wordlist Subdomain Terpilih
├── storage/                      # Direktori Basis Data SQLite Lokal
├── logs/                         # Direktori Berkas Log Sistem
├── docker-compose.yml            # Konfigurasi Multi-Container Docker
├── Dockerfile                    # Docker Image Build
├── pyproject.toml                # Project Metadata
├── requirements.txt              # Daftar Dependensi Python
└── README.md                     # Dokumentasi Resmi Platform
```

---

## 🛡️ Etika & Disclaimer Keamanan

> [!IMPORTANT]
> Platform ini dibangun secara khusus untuk **tujuan riset keamanan yang beretika (*Authorized Penetration Testing*)**, pengujian sistem milik sendiri, dan program *Bug Bounty* yang sah. Dilarang keras menggunakan instrumen ini untuk melakukan pemindaian atau pengujian terhadap aset digital tanpa izin tertulis dari pemilik sah sistem target. Penulis dan kontributor tidak bertanggung jawab atas segala bentuk penyalahgunaan atau kerusakan yang ditimbulkan.

---

## 📜 Lisensi

Didistribusikan di bawah lisensi **MIT License**. Silakan gunakan, modifikasi, dan kembangkan untuk kebutuhan riset keamanan Anda.
