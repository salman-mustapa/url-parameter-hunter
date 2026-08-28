# Audit proyek Hunter Aja — 28 Agustus 2026

## Status

Backend, laporan, kontrol akses, dan frontend telah diperbaiki serta diuji lokal. Ini **bukan** sertifikasi keamanan, jaminan bebas bug, bukti kapasitas produksi, atau bukti kerentanan target. Tidak ada scan terhadap BMKG atau target eksternal dalam pekerjaan ini. Perubahan belum dideploy.

Lingkungan verifikasi: Windows, Python 3.14, database SQLite sementara, fixture sintetis, browser desktop dengan viewport mobile. Pipeline scan dalam tes dimock; tidak menjalankan serangan terhadap target nyata. Redis pada server QA sengaja tidak tersedia sehingga fallback lokal dapat dipakai tanpa layanan produksi.

## Referensi pengguna dan penerapannya

NDA dan template DOCX pengguna dibaca sebagai referensi; dokumen asli tidak diubah, ditandatangani, atau dikirim. Nama/kontak contoh tidak disalin menjadi identitas laporan.

| Referensi | Hal yang diambil | Batas penerapan |
| --- | --- | --- |
| Gambar ruang lingkup BMKG | Scope web/API, host, daftar pengecualian dan aktivitas terlarang | Gambar bukan izin pengujian bagi akun ini; aturan setiap instansi harus diperiksa kembali |
| NDA BMKG | Referensi izin, periode, kerahasiaan, batas tindakan dan perubahan sistem | Tidak menyimpulkan legalitas atau persetujuan dari dokumen kosong |
| Template laporan | Identitas penguji/aset, ringkasan, register temuan, reproduksi, bukti, dampak CIA, perbaikan dan referensi | Data yang belum ada ditandai, tidak diisi dengan klaim buatan |
| Poster penghargaan | Kebutuhan laporan jelas dan dampak yang dapat dibuktikan | Poster menyebut Best Report/Best Value dan juara, tetapi tidak memuat bobot/rubrik penilaian |

Periode pada poster adalah 15–31 Juli 2026. Referensi itu tidak membuktikan izin aktif pada tanggal audit ini. High/Critical harus berasal dari dampak dan bukti, bukan target angka, judul CVE, atau banyaknya payload.

## Perbaikan yang tersedia di kode

### Backend, scope dan keamanan aplikasi

- Router API memeriksa autentikasi, pemilik scan dan peran admin; akses lintas pemilik ke temuan, aset, export, screenshot dan objek terkait ditolak.
- Autentikasi memakai validasi JWT yang lebih ketat dan cookie HttpOnly. Token tidak disimpan persisten di localStorage. Penggantian password membatalkan token lama melalui stamp password. Minimum password 10 karakter.
- Ditambahkan pemeriksaan Origin untuk mutasi berbasis cookie, pembatasan login per IP, batas ukuran body, timeout request, header keamanan, dan pemeriksaan containment lokasi file. CSP masih mengizinkan pola inline aplikasi lama; belum setara CSP ketat berbasis nonce.
- Scan aktif memerlukan referensi izin. Default L2; pipeline aktif tidak diberi label pasif. L3/L4 memerlukan admin dan referensi otorisasi. Label level sendiri bukan bukti persetujuan atas setiap teknik.
- Form engagement menyediakan host exact/wildcard, pengecualian, port yang diizinkan (default 80/443), waktu mulai/akhir, batas HTTP RPS, referensi izin dan pengakuan operator. URL dengan kredensial/port tidak valid ditolak oleh scope engine.
- Scope program diiriskan dengan batas target awal. Expiry diperiksa saat mulai dan setelah antrean, serta membatasi runtime. Port discovery/probe HTTP utama memakai aturan port. Catatan bebas **bukan** aturan yang otomatis ditegakkan pada setiap adapter.
- Retry admin mempertahankan pemilik, profil, target dan aturan; tidak membuat ulang scan dengan konteks berbeda. Scan lama tanpa referensi izin tidak otomatis menjadi berizin.
- Credential audit otomatis dimatikan pada runner ini. Feed kredensial global tidak lagi digunakan untuk melakukan lateral movement otomatis. Pengujian lanjutan memerlukan rencana dan izin khusus.

### Proses, antrean dan responsivitas

- Runner API dibatasi default 2 scan aktif dan 20 scan belum selesai per proses; antrean penuh mengembalikan HTTP 429. Scan pada registered domain yang sama diserialkan.
- Opportunity queue runner dipisahkan per scan, dibatasi 2.000 entri, dan menolak konteks scan lain. Pemulihan checkpoint tidak menghilangkan pekerjaan akibat deduplikasi terlalu awal.
- Export memakai 2 slot renderer, antrean terbatas, deduplikasi pekerjaan yang masih berjalan, nama unik, penulisan atomik, hash, serta status gagal yang nyata. Rendering CPU dipindah dari event loop ke thread.
- Query daftar scan/admin menggunakan agregasi, hasil daftar dibatasi, dan refresh mendapat pengaman respons terlambat agar scan lama tidak menimpa halaman scan baru.
- Log frontend menyimpan maksimum 500 event dan menampilkan maksimum 120 baris. Render dibatch; tab tersembunyi tidak terus melakukan pekerjaan DOM. Cache workspace dibatasi tiga scan.
- Retest timeout/tanpa respons menjadi INCONCLUSIVE dan tidak otomatis dinyatakan berhasil atau merusak status sebelumnya.

### Laporan dinamis dan kualitas bukti

- Identitas instansi, program, penguji, aset, versi aplikasi, kontak, klasifikasi dan konteks bisnis dapat disimpan per scan melalui panel Laporan. Mengubah identitas tidak menulis ulang scope/izin eksekusi.
- Logo PNG/JPEG dapat diunggah, divalidasi dan di-encode ulang untuk membuang metadata. Maksimum unggahan 256 KiB/4 megapiksel. Logo dipakai pada PDF/HTML; bukan bukti kerentanan.
- Data laporan memakai serializer bersama: endpoint, waktu, status, tingkat bukti, CVSS/CWE/CVE, dampak dan remediasi. Waktu pembuatan record tidak lagi disamarkan sebagai waktu mulai eksekusi.
- Ringkasan mencatat temuan yang tersimpan dan kekurangan bukti. Tidak lagi mengarang response HTTP 200, CVSS, persentase coverage, tingkat keyakinan, atau rantai eksploitasi yang tidak tercatat.
- Template replay Python/cURL diberi label belum dijalankan, mengikuti request yang tercatat, dan tidak menganggap respons sukses sebagai bukti eksploitasi. Endpoint kosong tidak diganti dengan target buatan.
- Secret pada data terstruktur/teks disamarkan; hash evidence dihitung setelah redaksi. Ini tetap memerlukan pemeriksaan manusia sebelum dibagikan, terutama gambar dan data personal.
- XLSX benar-benar workbook dengan sheet temuan/aset/layanan, bukan CSV yang diberi ekstensi XLSX. Sel ekspor dinetralkan dari formula injection.
- Korelasi produk/versi CVE diberi status **CANDIDATE**, provenance dan tautan NVD; tidak otomatis VALIDATED. Versi/vector CVSS hanya ditampilkan jika tercatat.
- Sepuluh jenis pekerjaan export: full PDF, executive PDF, technical PDF, findings CSV, findings XLSX, investigation JSON, assets CSV, services CSV, evidence index JSON dan artifact manifest JSON. Endpoint MD/HTML tetap tersedia; alias `/report/md` diperbaiki.
- PDF menggunakan tabel, heading, nomor halaman dan identitas dinamis; wrapping kode serta pemisahan halaman ditinjau visual.

Pemetaan produk saja belum cukup: applicability harus memeriksa versi, konfigurasi dan prasyarat. Referensi: [NVD CPE FAQ](https://nvd.nist.gov/general/faq-sections/cpe-faqs). Skor/vector harus menyebut versi penilaian dan didukung kondisi yang dibuktikan; jangan mengganti label v3.1 menjadi v4.0 tanpa penilaian ulang. Referensi: [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document).

### Frontend dan alur tombol

- Mobile memakai empat navigasi utama: Dashboard, History, Laporan dan Lainnya. Menu tambahan menjadi panel, dengan safe area dan ruang bawah agar konten tidak tertutup.
- Elemen flex/grid dapat mengecil, teks host panjang membungkus, tabel scroll di wilayahnya, modal dibatasi viewport. Input mobile 16 px dan target sentuh diperbesar.
- Navigasi laporan mobile memakai pemilih tab. Overflow subtab admin diperbaiki. Modal yang sebelumnya bersarang dan ID pencarian duplikat dipisahkan.
- Tombol Temuan & Bukti, Panduan CVE, Evidence JSON, export, detail, dan perubahan status temuan disinkronkan dengan kontrak backend. Status yang ditampilkan mengikuti record dan transisi yang diizinkan.
- Notifikasi scan selesai memakai jumlah terbaru. Durasi yang tidak tercatat tidak terus berjalan. Pembuatan scan menampilkan QUEUED sebelum eksekusi.
- Tombol koneksi SSO yang belum tersedia dinonaktifkan; membuka pengaturan AI tidak otomatis meminta daftar model eksternal.
- Contoh target landing menggunakan domain contoh, dan copy tidak lagi menjanjikan scan tanpa batas.

## Alur penggunaan yang disarankan

1. Masuk, isi target dan pilih lingkup host.
2. Catat referensi izin, periode, host/pengecualian, port dan batas request sesuai program. Pastikan program mengizinkan tindakan yang akan digunakan.
3. Mulai scan; pantau status antrean, event, sumber daya dan kondisi penghentian.
4. Tinjau temuan. Bedakan candidate/observed/confirmed, verifikasi baseline serta dampak dengan akun uji yang berizin, dan lengkapi bukti yang kurang.
5. Di Laporan, isi identitas instansi/penguji, konteks bisnis, klasifikasi dan logo bila diizinkan.
6. Buat export baru, periksa redaksi, reproduksi, dampak, remediasi dan batas cakupan. Export lama tidak berubah ketika identitas diedit.
7. Kirim hanya melalui kanal yang ditentukan pemilik program; retest harus masih berada dalam periode dan scope izin.

## Verifikasi lokal

| Pemeriksaan | Hasil / batas |
| --- | --- |
| Backend pytest | 188 lulus; 2 peringatan deprecation asyncio lama |
| Frontend Node test | 11 lulus, termasuk burst 10.000 event, stale response, scope form dan waktu eksekusi |
| Syntax JavaScript | 19 file lolos pemeriksaan syntax |
| Ruff terarah | F821 dan PLE1206 lolos; seluruh aturan lint belum bersih |
| Dependensi terpasang | `pip check` lolos; audit dependency tersimpan tidak menemukan advisory pada paket yang diaudit saat pemeriksaan; bukan jaminan bebas kerentanan |
| Export | Seluruh 10 jenis dibuat, status selesai dan berkas diunduh dalam tes; magic/signature/hash diperiksa |
| PDF visual | Full, executive, technical pada fixture dengan logo lokal, judul dan host panjang; tidak memakai temuan target nyata |
| Mobile width | Report/profile 320, 360, 390, 768, 960, 1280 px; semua 10 tab laporan pada 390 px; dashboard/admin/diff/history pada ukuran yang dicatat di QA |
| Overflow | `documentElement.scrollWidth == clientWidth` pada skenario yang diperiksa; tabel lokal tetap dapat discroll |
| Interaksi UI | Navigasi bawah/menu tambahan, pemilih laporan, simpan identitas, transisi temuan, detail/PoC, modal akun, validasi diff dan pencarian diperiksa dengan fixture |
| Tidak diuji di target | Tidak ada scan eksternal, eksploitasi live, benchmark load target, atau pembuktian lateral movement |

Perintah pengujian utama:

```text
.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
node --test tests/frontend_runtime.test.cjs
.venv\Scripts\python.exe -m ruff check app tests --select F821,PLE1206
.venv\Scripts\python.exe -m pip check
git diff --check
```

Artefak QA lokal berada di direktori `scratch/` yang diabaikan Git. Isinya data sintetis; jangan mengirimnya sebagai laporan pentest nyata. Angka tes bukan jumlah semua tombol/halaman yang telah dibuktikan untuk seluruh kondisi.

## Belum selesai / prioritas sebelum produksi

| Prioritas | Kebutuhan | Alasan |
| --- | --- | --- |
| P1 | Audit setiap jalur egress/adapter terhadap host, DNS/IP, port, redirect, RPS, izin tindakan dan expiry | Kontrol di runner/probe utama belum membuktikan kepatuhan semua tool; gunakan kontrol egress independen sebelum target sensitif |
| P1 | Worker/antrean terdistribusi, limit per instansi, pemulihan job/export setelah restart, cancel/retry idempotent | Semaphore dan antrean saat ini per proses; jangan menambah banyak worker dengan asumsi limit global |
| P1 | Benchmark lab berizin: p95/p99, RAM/CPU, koneksi DB, event backlog, cancellation, scan paralel dan outage Redis/DB | Tes mock concurrency bukan bukti throughput scan enterprise atau browser tidak pernah hang |
| P1 | Validasi detector dengan baseline/control, akun multi-peran dan dataset rentan/tidak rentan | Mengukur false positive/negative dan bukti BOLA/IDOR lebih bernilai daripada sekadar menambah payload |
| P1 | Konfigurasi produksi: HTTPS, COOKIE_SECURE, JWT acak >=32 karakter, kredensial DB unik, backup, audit akses, batas retention | Pemeriksaan lokal tidak mensertifikasi deployment; tinjau juga container non-root dan pinning dependency |
| P1 | Paket browser dan QA capture asli | Implementasi opsional tersedia, **default nonaktif**, Playwright/Chromium belum terpasang/diuji live di lingkungan ini |
| P2 | CVE feed terversi dan terverifikasi, CPE/vendor advisory, umur data dan applicability per konfigurasi | Katalog saat ini lokal; bukan sinkronisasi NVD mutakhir dan belum mencakup semua framework |
| P2 | Penyuntingan bukti/impact/reproduksi dengan review, version history, retest sign-off dan rubrik instansi | Profile dinamis belum merupakan sistem pengelolaan NDA/report lengkap; ekspor DOCX mengikuti template belum ditambahkan |
| P2 | Pengambilan logo otomatis dan embedding screenshot live pada PDF | Saat ini logo unggahan manual. Capture tersimpan/galeri belum berarti semua gambar otomatis menjadi lampiran PDF |
| P2 | Pagination workspace besar, render bertahap, pengujian iOS/Android fisik dan aksesibilitas keyboard/screen reader | Emulasi viewport tidak menguji keyboard OS, Safari, memori perangkat atau seluruh dataset |
| P2 | SSO, beberapa preferensi audio/compact, konsistensi bahasa UI dan sisa technical debt lint | Fitur belum tersedia harus tetap jelas/nonaktif; hindari label yang menjanjikan fungsi yang belum terhubung |

### Catatan khusus screenshot

Capture opsional menggunakan browser sungguhan dengan satu slot, timeout, batas jumlah request/ukuran gambar, scope public IP/DNS, satu host, GET/HEAD, dan metadata/hash. Capture gagal tidak membuat gambar pengganti. Rekaman screenshot lama tanpa provenance browser diberi label legacy/unverified. Resource lintas host diblokir sehingga beberapa halaman dapat tampil tidak lengkap. Siapkan Chromium sandbox, dependency browser dan jaringan egress yang benar; lakukan verifikasi di lab sebelum diaktifkan. Screenshot juga harus diperiksa/redaksi manual sebelum dibagikan.

### Catatan toolchain dan operasional

Tool scanner eksternal yang diperiksa pada PATH lokal (antara lain nmap, subfinder, naabu, katana, nuclei, dnsx, ffuf, amass, sqlmap) tidak ditemukan. Build Docker dan ketersediaan tool dalam container belum diverifikasi. Jangan menganggap tombol sukses membuka halaman sebagai bukti semua adapter siap berjalan. Riwayat scan lama tidak otomatis mendapat izin, screenshot asli, bukti lengkap atau CVE tervalidasi setelah upgrade ini.

## Kesimpulan

Fondasi kontrol akses, pelaporan jujur, isolasi scan dan penggunaan mobile lebih baik dari kondisi awal. Laporan lebih lengkap karena konteks serta kekurangan bukti terlihat, bukan karena severity dibesarkan. Untuk skala enterprise, prioritas berikutnya adalah kepatuhan egress seluruh adapter, worker terdistribusi, validasi kualitas detector dan benchmark lab; bukan mengaktifkan eksploitasi lanjutan tanpa pengujian dan persetujuan.
