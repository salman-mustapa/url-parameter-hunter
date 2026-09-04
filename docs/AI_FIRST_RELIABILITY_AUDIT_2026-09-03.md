# Audit AI-first, scope, dan keandalan — 3 September 2026

## Kesimpulan

Perbaikan ini meningkatkan konsistensi dan keterlihatan kegagalan, **bukan jaminan tanpa bug, timeout, false negative, atau pelanggaran scope pada semua adapter**. Sistem belum dapat dinyatakan sebagai pentest otomatis penuh siap produksi. Tidak ada pemindaian target eksternal dalam verifikasi ini.

## Perubahan yang diterapkan

- AI preflight sebelum discovery dan AI review setelah tools; hasil disimpan di `Scan.options.ai_analysis` dan digunakan dalam laporan. Baseline deterministik tetap berjalan bila provider gagal. Rekomendasi AI tidak boleh menghapus coverage gap atau mengonfirmasi temuan tanpa bukti.
- Form policy HackerOne: in-scope/out-of-scope, port, waktu, RPS, teknik, jenis temuan di luar scope, dan referensi izin nyata. Tidak lagi membuat otorisasi L4 otomatis. API default L2; UI controlled membutuhkan acknowledgement nyata.
- Tombol analisis policy berbahasa Indonesia sebelum scan. Draft tidak otomatis diterapkan sebagai izin. URL policy hanya referensi; teks harus ditempel, halaman HackerOne tidak diambil otomatis. Pengguna harus memastikan policy privat boleh dikirim ke provider AI.
- Full/focused memakai profil kedalaman yang sama. Alias `deep_bug_hunt`/`pentest` dikenali sebagai deep; URL input asli (path, query, port) diprioritaskan. Host/URL yang dipotong budget dicatat pada fase yang diperbarui. Ini bukan bukti seluruh temuan selalu identik.
- Timeout keseluruhan dan kegagalan fase menghasilkan `degraded`/coverage gap, bukan sukses palsu. Temuan tersimpan dipertahankan. Deadlock recursive crawl yang menunggu child sambil memegang semaphore diganti penelusuran per tingkat.
- Eksekusi rencana AI ditunggu, duplikasi fuzzer crawler tanpa pemilik dihentikan, ingest event diberi backpressure, dan query URL untuk audit aset tidak lagi memakai satu AsyncSession secara paralel.
- Deadline AI mencakup antrean semaphore, percobaan provider, dan fallback. Kredensial provider tidak lagi dicoba ke endpoint berbeda. TLS diverifikasi pada completion utama.
- SSE: subscriber dipasang sebelum replay, ID/waktu event dipertahankan di DB, replay tidak dipotong oleh ukuran antrean live, cursor reconnect dipakai, dan overflow memberi `stream.gap`. Frontend menolak event scan lama dan deduplikasi replay; counter diselaraskan ke DB.
- Event lokal tidak bergantung pada listener Redis. Terminal scan tanpa runner tidak dapat dipalsukan menjadi resumed. Modal ganda (12 pasang salinan) dibuang, preview evidence dibatasi, dan animasi beranda diberi label DEMO.
- Template laporan bug bounty satu temuan berbahasa Inggris ditambahkan ke jalur laporan yang ada; missing evidence tetap ditandai NEEDS_REVIEW. Kontrak serializer sekarang membaca bukti terstruktur dari engine lab agar tampilan ringkasan konsisten.
- Nuclei yang tidak terpasang/timeout/nonzero exit bukan hasil clean. Validator legacy tanpa executor dibukukan sebagai coverage gap, bukan bukti target aman.

## Verifikasi yang dilakukan

Tes memakai database/storage sementara, mock, atau loopback. Data scan pengguna tidak dihapus dan `.env` aktif tidak diubah.

- Suite Python mencakup scope, otorisasi, lifecycle, antrean terisolasi, pembatasan scan paralel, HTTP probe parity full/focused, deadline AI, cursor SSE, dan unavailable-tool semantics. Beberapa tes lama menganggap tool yang tidak berjalan sebagai sukses; kontraknya diperbaiki, jalur sukses menggunakan mock deterministik.
- Hasil verifikasi tahap awal: 260 tes Python lulus. Pemeriksaan startup sempat menemukan ketidakcocokan nested router dengan pengurutan route lama; diperbaiki sebelum pengujian berikutnya.
- Tahap awal: 12 tes frontend, termasuk 10.000 event (buffer 500, DOM 120, satu render terjadwal), tab tersembunyi, respons lama saat pindah scan, dan SSE duplicate/stale connection.
- Smoke test server lokal: 158 operasi API terproteksi menolak akses tanpa login; lab sintetis menemukan pelanggaran authorization dengan 7 request. SSE diterima; MD/HTML/PDF/JSON dan export asynchronous berhasil. Hash dan hasil mesin ada di `scratch/verification/ai-first-final/`.
- 50 request readiness, konkurensi 5: median 50,9 ms, p95 99,72 ms, maksimum 111,08 ms. **Ini bukan benchmark pentest penuh atau banyak browser.**
- Browser aktual: login, dashboard, formulir policy, data lab, report hub, tombol resume terminal, dan label demo diperiksa. Browser QA menunjukkan preview evidence terlalu panjang dan label demo menyesatkan; keduanya diperbaiki.
- `compileall` dan `git diff --check` dijalankan. Warning CRLF Git pada Windows bukan error aplikasi.

## NineRouter dan Hermes

### Pemeriksaan lanjutan: combo, model tunggal, dan sinkronisasi UI

Katalog provider yang dikonfigurasi mengembalikan 69 entri: 7 `owned_by=combo` dan 62 entri model. Ini metadata katalog, bukan pembuktian kemampuan chat, harga, atau ketersediaan setiap entri.

- Mode `single` mengirim satu ID persis, tanpa fallback aplikasi ke ID lain atau Hermes.
- Mode `router_combo` mengirim nama combo persis; NineRouter mengatur anggota dan fallback internalnya.
- Mode `task_router` memakai alias per tugas dengan cascade aplikasi. Konfigurasi lama `LLM_MODEL=combo` + mode `auto` dipetakan ke mode ini. Untuk combo yang benar-benar bernama `combo`, pilih mode `router_combo` secara eksplisit.
- Gateway AI, scan intelligence, dan chat memakai implementasi routing yang sama. Request yang sedang berjalan mempertahankan snapshot konfigurasi asal; cache respons lama tidak masuk ke konfigurasi baru.
- `/ai/config` dan `/ai/settings` memakai kontrak validasi yang sama. Revisi konfigurasi mencegah overwrite dari sesi lama. Perubahan UI bersifat **runtime satu proses**, tidak ditulis ke `.env` dan bukan konfigurasi terdistribusi multi-worker.
- Test Connection sekarang menguji completion readiness sungguhan pada model/mode yang dipilih. Key terisi atau daftar model tersedia tidak lagi cukup untuk menyatakan sukses. Mode disabled tetap memblokir chat, walaupun API key tersimpan.
- Daftar model frontend berasal dari metadata provider; tidak ada katalog hardcoded ketika fetch gagal. Draft, konfigurasi tersimpan, dan hasil uji dibedakan. Fetch/test lama tidak boleh menimpa edit baru. Konfigurasi dipoll setiap 15 detik saat panel terlihat; ini bukan push real-time konfigurasi lintas proses.
- Riwayat/status/tree/findings menolak request usang, termasuk pergantian scan. Refresh yang datang saat fetch berlangsung dikoaleskan dan dijalankan ulang. Tab yang kembali terlihat meminta snapshot baru.
- Browser aktual menemukan HTML baru memakai JavaScript lama dari cache. Versi JS/CSS diperbarui bersama dan respons aset mutable diberi `must-revalidate`. Browser juga menemukan kontras chat/code kurang jelas; warna disesuaikan ke tema gelap.

Uji live tambahan (prompt readiness sintetis, deadline 12 detik, tanpa target atau evidence pengguna):

| Pilihan | Mode | Hasil |
| --- | --- | --- |
| security | router_combo | Berhasil 7.268 s; respons provider melaporkan `minimax/minimax-m2.7:free` |
| groq/llama-3.3-70b-versatile | single | HTTP 404 dalam 1.345 s; tidak dialihkan ke ID lain |

Nama model yang dilaporkan respons bukan verifikasi independen model dasar. HTTP 404 model yang tercantum menunjukkan konfigurasi/provider perlu diperbaiki di NineRouter; aplikasi tidak menyamarkan kegagalan itu. Semantik combo mengikuti [dokumentasi resmi NineRouter](https://github.com/decolua/9router/blob/master/gitbook/content/en/features/combos.md).

### Pelaporan dan private research

Form mendukung HackerOne, Bugcrowd, Intigriti, Private, dan Other. Private tanpa program tetap memerlukan referensi izin pemilik/aset sendiri dan scope eksplisit. Engagement dengan allowlist kosong ditolak; waktu izin diperiksa ulang setelah menunggu antrean.

Laporan per temuan memuat ID, endpoint/method, klasifikasi, prasyarat, reproduksi tercatat, expected/actual, manifest capture, konteks izin/scope, dampak, remediasi, coverage gap, dan checklist researcher. Langkah generik tidak dianggap sebagai reproduksi tercatat. Capture non-HTTP terakhir tidak lagi menutupi pertukaran HTTP valid sebelumnya. Header terstruktur disanitasi **sebelum** diubah menjadi string agar cookie tidak lolos ke cuplikan respons. Judul yang teredaksi diganti label klasifikasi netral tanpa mengembalikan rahasianya.

Laporan dapat tetap `NEEDS_REVIEW`, misalnya jika impact atau prasyarat belum dicatat. `READY_FOR_HUMAN_REVIEW` bukan auto-submit, bukan jaminan diterima platform, dan bukan jaminan coverage seluruh target. Draft lab/manifest hasil terakhir ada di `scratch/verification/router-report-checked/`.

Smoke test lanjutan: 158 operasi terproteksi, 7 request lab sintetis, SSE, MD/HTML/PDF/JSON, tiga jalur disclosure (`bugbounty`, `reproduction`, `cve-ready`), dan export asynchronous berhasil. Readiness 50 request dengan konkurensi 5: median 150.53 ms, p95 249.59 ms, maksimum 259.98 ms. Run sebelumnya p95 656.08 ms saat aktivitas pengujian lain berjalan; angka ini tidak membuktikan latensi produksi konstan. Tes frontend terbaru 19/19; suite Python penuh 280/280 sebelum dua regresi laporan tambahan, lalu 10/10 tes laporan khusus lulus.

Benchmark kecil langsung ke NineRouter yang sudah dikonfigurasi, hanya prompt JSON sintetis; maksimal 2 request bersamaan, deadline 12 detik:

| Alias | Hasil | Waktu per percobaan |
| --- | --- | --- |
| free | 1 berhasil, 1 gagal | 3,283 s berhasil; 5,684 s gagal |
| security | 2 berhasil | 3,386 s; 1,661 s |

Sampel ini tidak membuktikan kualitas analisis keamanan, harga gratis, quota unlimited, atau stabilitas jangka panjang. Alias router bukan nama model dasar yang terverifikasi. Ulangi benchmark dengan `python -m scripts.benchmark_ai --models free security --samples 2 --timeout 12` memakai Python virtualenv.

Fallback Hermes disiapkan melalui `HERMES_BASE_URL`, `HERMES_API_KEY`, `HERMES_MODEL=hermes-agent`. Belum ada endpoint Hermes pengguna yang dikonfigurasi/diuji langsung. Klien memeriksa `/toolsets` dan menolak profil dengan toolset aktif; gunakan profil khusus analisis. Hermes sendiri memiliki akses tools, sehingga prompt saja bukan pengaman scope. Lihat [dokumentasi resmi Hermes API Server](https://hermes-agent.nousresearch.com/docs/user-guide/features/api-server/).

HackerOne membedakan tipe aset dan scope. Form saat ini mendukung host/wildcard dan port, **belum** semua jenis aset (aplikasi mobile, repo, rentang CIDR, pembatasan path URL). Jangan mengubah scope sempit berbasis path menjadi izin seluruh host. Lihat [HackerOne Asset Types](https://docs.hackerone.com/en/articles/8486276-asset-types).

## Pekerjaan penting yang masih tersisa

1. Integrasi executor produksi untuk validator legacy: executor yang ada sengaja loopback-only. Tidak dibuka paksa dalam perubahan ini. Banyak binding registry hanya metadata; AI belum dapat mengeksekusi semua tools secara aman/end-to-end. Rekomendasi preflight terutama advisory, bukan scheduler penuh yang sudah terbukti.
2. Audit seluruh jalur egress (subprocess, HTTP langsung, redirect, DNS rebinding, screenshot, adapter) dengan satu kontrak policy dan rate budget. Field policy yang ditambahkan belum membuktikan enforcement semua teknik pada semua adapter.
3. Buat corpus regresi kerentanan positif/negatif untuk membuktikan recall full vs focused dengan parameter, auth/session, policy, dan budget setara. Prioritas input tidak menjamin semua aset yang ditemukan full mendapat kedalaman sama saat budget habis.
4. Soak/load test kampanye paralel, banyak subscriber SSE, reconnect/restart, database contention, dan Redis lintas proses. Antrean persister event masih bisa menjatuhkan event saat saturasi; log audit belum lossless walaupun snapshot DB dapat memulihkan tampilan.
5. Pause bersifat checkpoint/cooperative, bukan penghentian instan setiap request yang sudah berjalan. Timeout tetap diperlukan; menghapusnya akan meningkatkan risiko hang.
6. Benchmark provider dengan prompt analisis/evidence realistis yang tersanitasi, ukur kualitas dan latensi p95 berkali-kali; verifikasi kuota/biaya dari provider. Jangan menganggap `free` berarti unlimited.
7. Tinjau route duplikat copilot/OpenAPI yang sudah ada dan rendering daftar finding yang masih belum virtualized untuk kampanye sangat besar. Tidak ada klaim zero-error produksi dari tes ini.

Sebelum uji program nyata: diperlukan policy program lengkap, scope eksplisit, batas teknik/request, dan konfigurasi Hermes yang terkonfirmasi. Jangan submit laporan otomatis ke HackerOne tanpa tinjauan bukti dan policy.

## Verifikasi penutup

- Suite Python penuh terakhir: **282/282 lulus** (137.93 detik). Setelah perbaikan terakhir redaksi header, suite terfokus routing/laporan **23/23 lulus**, termasuk regresi baru yang memastikan tanda kutip dan URL perintah curl tidak ikut terpotong. Angka suite terfokus tumpang tindih dengan suite penuh, bukan untuk dijumlahkan.
- Frontend: **19/19 lulus**. Browser aktual memverifikasi pemisahan combo/model, Save & Apply → revisi backend 1, pembuangan draft, reload aset baru, dan kontras chat gelap. Console warning/error kosong pada inspeksi terakhir.
- Smoke test penutup berhasil: 158 operasi API terproteksi, lab loopback 7 request, SSE, MD/HTML/PDF/JSON, tiga format disclosure, dan export asynchronous. Sintaks curl hasil redaksi diuji dengan parser shell dan endpoint loopback tetap dipertahankan.
- Hasil penutup: `scratch/verification/router-report-final-release/summary.json` dan `synthetic-bugbounty.md`. Readiness 50 request, konkurensi 5: median **84.66 ms**, p95 **142.09 ms**, maksimum **150.90 ms**. Ini pengukuran readiness lokal, bukan benchmark pentest penuh.
- `compileall`, syntax check JavaScript, dan `git diff --check` lulus. Warning OpenAPI route duplikat yang sudah ada masih tercatat; lihat daftar pekerjaan tersisa.
- Pada tahap QA awal ini, `.env` pengguna tidak diubah dan proses produksi tidak direstart. Uji konfigurasi via browser hanya memodifikasi proses QA sementara, bukan layanan pengguna. Status validasi rilis dan deployment berikutnya dicatat terpisah pada `RELEASE_VALIDATION_2026-09-04.md`.

Lihat [panduan penggunaan dalam Bahasa Indonesia](AI_BUG_BOUNTY_QUICKSTART_ID.md). Hasil ini memperkuat alur yang diuji, bukan sertifikasi bebas error atau pentest penuh siap produksi.
