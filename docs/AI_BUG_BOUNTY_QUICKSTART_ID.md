# Panduan AI, scope, dan laporan bug bounty

Perubahan tersedia di kode lokal. Restart backend melalui prosedur deploy Anda dan muat ulang browser untuk mengaktifkan kode baru. Jangan restart proses produksi saat masih ada scan penting; runner saat ini belum resumable secara durable setelah restart.

## Pilih jalur AI

Di Admin Monitor → AI Agent & Copilot:

1. Muat konfigurasi backend dan katalog provider. Jangan menganggap semua ID dalam katalog pasti dapat menjalankan chat.
2. Pilih mode:
   - **Model tunggal:** satu ID model persis, tanpa pergantian model oleh aplikasi.
   - **Combo NineRouter:** satu nama combo seperti `security`; anggota dan fallback diatur di NineRouter.
   - **Routing per tugas:** aplikasi memilih alias reasoning/reporting dan melakukan cascade. Ini perilaku kompatibel untuk konfigurasi lama `LLM_MODEL=combo`.
3. Pilih ID dari katalog atau isi ID manual. ID manual mengganti pilihan dropdown; uji sebelum dipakai.
4. Klik **Uji inference**. Baca mode, ID yang diminta, model yang dilaporkan provider, dan latensi. Pengujian tidak menyimpan konfigurasi.
5. Klik **Save & Apply** untuk menerapkan pada proses backend saat ini. Draft yang belum diterapkan tidak dipakai chat/scan. Pengaturan ini tidak ditulis ke `.env`; atur file deployment secara terpisah bila ingin persisten. Jangan kirim API key melalui chat.

Jika base URL/provider diubah dan key dikosongkan, key endpoint sebelumnya tidak diteruskan ke endpoint baru. HTTP 404/429, kuota, billing, dan availability perlu ditangani di provider. Nama `free` bukan jaminan unlimited.

## Scope program atau private

- Pilih HackerOne/Bugcrowd/Intigriti atau **Private** untuk engagement pemilik/aset sendiri tanpa program bounty.
- Isi referensi izin, in-scope/out-of-scope host, port, waktu, RPS, teknik diizinkan/dilarang. Jangan mengisi izin untuk aset pihak lain tanpa otorisasi.
- Tempel policy berbahasa Inggris bila ingin ringkasan Indonesia. Teks dikirim ke provider AI yang dikonfigurasi; hapus informasi rahasia dan pastikan program mengizinkan pembagian tersebut.
- Cocokkan draft AI dengan sumber asli, lalu isi aturan terstruktur sendiri. AI tidak mengesahkan izin atau memperluas scope.
- Form belum mendukung seluruh tipe scope: path URL sempit, CIDR, aplikasi mobile, dan repository tidak boleh dianggap sama dengan izin satu host penuh.

Full dan focused memakai profil kedalaman deep yang sama. Full memperluas discovery dalam scope, sedangkan focused memprioritaskan host/endpoint yang dimasukkan. Budget, autentikasi, tool availability, dan perilaku target tetap dapat membuat hasil berbeda; periksa coverage gap.

## Siapkan laporan yang dapat ditriase

Laporan per temuan tersedia dari jalur Bug Bounty/Reproduction yang sudah ada. Template berbahasa Inggris memuat bukti dan konteks untuk HackerOne, platform lain, atau disclosure private.

Sebelum berbagi:

1. Pastikan endpoint dan teknik masih diizinkan.
2. Lengkapi prasyarat, identitas test yang aman, langkah reproduksi, baseline/control, expected/actual, dampak terbukti, dan rekomendasi perbaikan.
3. Cocokkan setiap klaim dengan ID evidence dan request/response. Replay template bukan hasil eksekusi; redaksi dapat membuat script perlu diedit sebelum dijalankan ulang.
4. Periksa `NEEDS_REVIEW`, coverage gap, dan kegagalan tool. Satu PoC valid tidak berarti seluruh target telah diuji.
5. Periksa ulang cookie/token/PII di semua lampiran dan ikuti aturan disclosure penerima. Tidak ada auto-submit atau jaminan bounty/acceptance.

Untuk Hermes, sediakan API server dengan profil analisis-only, seluruh toolset dinonaktifkan, dan API key tersendiri melalui konfigurasi. Integrasi live belum terverifikasi tanpa endpoint tersebut.

Lihat [audit dan batasan yang masih tersisa](AI_FIRST_RELIABILITY_AUDIT_2026-09-03.md), khususnya executor validator legacy, enforcement egress seluruh adapter, dan pengujian coverage produksi.
