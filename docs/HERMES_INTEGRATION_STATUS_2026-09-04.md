# Status konfigurasi Hermes — 4 September 2026

## Perubahan yang sudah disimpan pada server Hermes

- Dashboard: `https://hermes.samrifa.com/`.
- Profil baru: `bughunter-analysis`, dibuat sebagai profil kosong, bukan clone.
- Direktori profil: `/opt/data/profiles/bughunter-analysis`.
- Deskripsi peran: analisis policy/scope, review bukti tools, rekomendasi pengujian berizin, dan penyusunan laporan berbasis bukti.
- Bundled skills tidak disertakan; dashboard melaporkan 0 skills.
- Profil `default` tidak diganti sebagai profil aktif. Tidak ada restart/stop terhadap gateway utama atau perubahan kanal Telegram/WhatsApp utama.
- Gateway profil baru tetap berhenti. Seluruh sakelar kanal profil baru masih Disabled.

Konfigurasi toolset disimpan melalui editor YAML khusus profil tersebut:

```yaml
toolsets: []
platform_toolsets:
  cli: [no_mcp]
  api_server: [no_mcp]
agent:
  disabled_toolsets:
    - web
    - browser
    - terminal
    - file
    - code_execution
    - vision
    - video
    - image_gen
    - video_gen
    - x_search
    - tts
    - stt
    - skills
    - todo
    - memory
    - context_engine
    - session_search
    - clarify
    - delegation
    - cronjob
    - homeassistant
    - spotify
    - discord
    - discord_admin
    - yuanbao
    - computer_use
mcp_servers: {}
```

Speech-to-Text masih terlihat aktif setelah penyimpanan YAML karena memiliki pengaturan terpisah; sakelarnya kemudian dinonaktifkan melalui UI. Hasil terakhir halaman Skills → Toolsets: **0 active, 26 inactive**. Ini verifikasi UI, bukan bukti pengujian runtime API; `/v1/toolsets` harus diperiksa lagi setelah server API hidup.

## Draft API yang belum disimpan

Form Channels → API server → Configure untuk `bughunter-analysis` telah disiapkan dengan:

```env
API_SERVER_ENABLED=true
API_SERVER_HOST=127.0.0.1
API_SERVER_PORT=8642
API_SERVER_MODEL_NAME=bughunter-analysis
```

`API_SERVER_KEY` belum diisi atau dibuat. Form **Save & enable belum disubmit**. Browser diserahkan kepada pengguna untuk mengisi secret acak yang kuat, menyimpannya di tempat aman, dan menyelesaikan penyimpanan sendiri. Jangan memakai password dashboard sebagai API key dan jangan membagikan key melalui chat.

Bind loopback sengaja dipertahankan. Koneksi lintas container/host memerlukan pemeriksaan topologi serta reverse proxy/private routing sebelum mengubah bind atau mempublikasikan endpoint. Alamat `https://hermes.samrifa.com/v1` belum terverifikasi sebagai API; pengujian sebelumnya mendapatkan login/dashboard HTML, bukan JSON API.

## Pekerjaan berikutnya

1. Pengguna menyelesaikan input dan penyimpanan API key pada profil baru.
2. Konfigurasikan provider/model untuk profil baru. Profil kosong belum memiliki pilihan model yang disimpan atau diuji; jangan menganggap provider/model profil utama otomatis tersedia.
3. Jalankan hanya gateway profil `bughunter-analysis` setelah autentikasi dan model siap. Jangan mengganti profil default global atau me-restart gateway utama.
4. Verifikasi health, autentikasi, `/v1/models`, dan `/v1/toolsets` dari jalur jaringan yang akan digunakan backend.
5. Hanya bila seluruh toolset API nonaktif, lakukan inference sintetis tanpa target scan atau data program bounty.
6. Tentukan base URL final, lalu simpan konfigurasi `HERMES_BASE_URL`, `HERMES_API_KEY`, dan `HERMES_MODEL=bughunter-analysis` pada backend melalui mekanisme secret yang sesuai.

Tidak ada scan, eksekusi tools Hermes, inference, atau perubahan `.env` aplikasi lokal pada tahap ini. Konektor aplikasi saat ini tetap menjadikan Hermes fallback pada mode `task_router`, bukan pemroses wajib setiap request.

Referensi: [Hermes API Server](https://hermes-agent.nousresearch.com/docs/user-guide/features/api-server/), [pengaturan toolset](https://hermes-agent.nousresearch.com/docs/user-guide/configuration#global-toolset-disable), [profiles](https://hermes-agent.nousresearch.com/docs/user-guide/profiles/).
