# Validasi Rilis — 4 September 2026

Dokumen ini merekam pemeriksaan yang benar-benar dijalankan sebelum rilis. Hasil
ini membuktikan fixture dan lingkungan QA yang diuji, bukan jaminan bahwa setiap
server, provider AI, target, atau kerentanan akan selalu bekerja tanpa error.

## Hasil verifikasi

- Suite Python penuh: **309 lulus** dalam 127,73 detik.
- Runtime frontend: **19 lulus**; mencakup stale fetch, reconnect/replay SSE,
  burst 10.000 event, perubahan scan, serta sinkronisasi draft konfigurasi AI.
- `compileall`, `pip check`, `git diff --check`, dan validasi konfigurasi Compose
  lulus.
- Image `bug-hunter:latest` berhasil dibangun dari awal. Dependency Python di
  dalam image tidak rusak dan binary `nmap`, `subfinder`, `katana`, `naabu`,
  `nuclei`, `ffuf`, `gau`, `waybackurls`, `trufflehog`, `httpx`, `pd-httpx`,
  `dirsearch`, serta `arjun` ditemukan.
- Smoke test image ephemeral lulus: 158 operasi API privat menolak guest, lab
  loopback melakukan 7 request sintetis, SSE diterima, export asynchronous
  selesai, dan laporan MD/HTML/PDF/JSON serta format Bug Bounty/Reproduction/
  CVE-ready berhasil dibuat. Readiness 50 request dengan konkurensi 5 mencatat
  median 78,73 ms, p95 142,61 ms, maksimum 146,53 ms.
- Stack Compose QA terisolasi berhasil membuat API, PostgreSQL, dan Redis dalam
  keadaan `healthy`. `/health` menghasilkan `{"status":"ok"}`, `/ready`
  menghasilkan `{"ready":true}`, dan endpoint privat tanpa login menghasilkan
  HTTP 401. Seluruh container, network, dan volume QA kemudian dibersihkan.
- OpenAPI sekarang mempunyai operation ID unik. Endpoint Copilot tunggal memakai
  gateway AI terpadu; konteks scan memerlukan login dan pemeriksaan kepemilikan.

## AI pada server

Template baru sengaja memakai `LLM_ENABLED=false`. Untuk NineRouter, isi secret
di `.env` server (bukan di Git), aktifkan AI, kemudian tentukan `LLM_MODEL` dan
`LLM_ROUTING_MODE`. `single` mengirim ID model persis; `router_combo` mengirim
nama combo persis; `task_router` memakai cascade aplikasi. Hermes tidak wajib:
biarkan `HERMES_BASE_URL` dan `HERMES_API_KEY` kosong untuk NineRouter-only.

Pengujian nyata menemukan combo NineRouter dapat memilih anggota yang sehat atau
anggota upstream yang sudah dihentikan. Aplikasi sekarang menolak pesan model
retired, jawaban kosong/terpotong, tool-call tanpa jawaban akhir, dan JSON invalid
sebagai analisis sukses. Status harga `free` atau kuota `unlimited` tidak dapat
disimpulkan dari respons inference dan harus diverifikasi pada provider.

## Update server

Pertahankan `.env` server yang sudah ada; file itu diabaikan Git.

```bash
git pull --ff-only origin master
docker compose config --quiet
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:9001/health
curl -fsS http://127.0.0.1:9001/ready
```

Sebelum production, pastikan `APP_ENV=production`, `JWT_SECRET` unik minimal 32
karakter, HTTPS aktif, `COOKIE_SECURE=true`, database memiliki kredensial unik,
dan konfigurasi NineRouter diuji dari panel Admin. Satu proses runner adalah
konfigurasi yang divalidasi; limit scan/runtime masih bersifat per proses.

## Batas yang tetap berlaku

Tidak ada perangkat lunak yang dapat dijamin bebas timeout, bug, miss, atau
false positive. Full dan focused memakai kedalaman probe yang sama, tetapi hasil
dapat berbeda karena scope, budget, autentikasi, rate limit, tool availability,
atau perilaku target. Selalu tinjau coverage gap. Executor validator legacy untuk
target eksternal belum lengkap; ketiadaannya dicatat sebagai gap, bukan hasil
bersih. Rilis ini tidak melakukan scan ke target eksternal.
