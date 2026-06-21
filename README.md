# 🔐 Steganography Tugas 2

> Implementasi Penyembunyian Pesan, Enkripsi, dan Navigasi Acak Menggunakan Algoritma Kriptografi dan Steganografi

## 📋 Deskripsi Proyek

Aplikasi antarmuka web interaktif (menggunakan Streamlit) untuk mendemonstrasikan cara kerja algoritma Steganografi dalam mengamankan kerahasiaan dan integritas sebuah pesan digital ke dalam citra gambar secara *real-time*.

---
## Link Video Digital Signatures

### `https://mikroskilacid-my.sharepoint.com/:v:/g/personal/teresia_hana_students_mikroskil_ac_id/IQABOQIs0pjZRLMwZz4vBTi7AdXQoBXxojuWxcZe6naDhD4?nav=eyJyZWZlcnJhbEluZm8iOnsicmVmZXJyYWxBcHAiOiJPbmVEcml2ZUZvckJ1c2luZXNzIiwicmVmZXJyYWxBcHBQbGF0Zm9ybSI6IldlYiIsInJlZmVycmFsTW9kZSI6InZpZXciLCJyZWZlcnJhbFZpZXciOiJNeUZpbGVzTGlua0NvcHkifX0&e=M7DYmR`

---

**Skema Steganografi yang Diimplementasikan:**
- **AES-256 (CBC)**: Simulasi enkripsi pesan teks menjadi ciphertext acak menggunakan algoritma Advanced Encryption Standard dengan Initialization Vector.
- **LCG PRNG**: Implementasi Linear Congruential Generator untuk menghasilkan parameter angka acak penentu rute penjelajahan.
- **Key-Dependent Routing**: Simulasi pergerakan acak (Spiral, Squared, Snake, Ray) yang bergantung pada kunci password pengguna.
- **Modified LSB**: Implementasi modifikasi Least Significant Bit yang dinamis pada saluran warna (RGB) dan kedalaman bit (1-3 bit).
- **Message Extraction**: Simulasi proses pembongkaran pesan (re-syncing parameter LCG) untuk melacak dan menyedot kembali bit yang tersembunyi berdasarkan 32-bit header.
- **Decryption & Unpadding**: Implementasi pemisahan IV dan pemutaran balik AES-CBC beserta penghapusan karakter penambal (PKCS7) untuk mengembalikan ciphertext menjadi teks asli yang dapat dibaca.
- **Quality Metrics**: Evaluasi keamanan visual menggunakan perhitungan matematika MSE (Mean Squared Error) dan PSNR (Peak Signal-to-Noise Ratio).
---

## 🗂️ Struktur File
- `app.py`: File utama untuk menjalankan dan menampilkan antarmuka web Streamlit beserta seluruh logika inti steganografinya.
- `requirements.txt`: Berisi daftar dependencies atau library tambahan yang dibutuhkan agar aplikasi dapat berjalan dengan baik.

---

## 🚀 Cara Setup & Menjalankan Aplikasi

### ⚠️ PENTING: Setup Virtual Environment (venv)

**JANGAN skip langkah ini!** Virtual environment diperlukan agar *dependencies* (pustaka tambahan) tidak berbenturan dengan *project* Python Anda yang lain.

#### Windows (Command Prompt / PowerShell)
```cmd
# 1. Clone repository
git clone https://github.com/teyetata/SteganographyTere.git
cd SteganographyTere

# 2. Buat virtual environment
python -m venv venv

# 3. Aktifkan virtual environment
# Jika menggunakan Command Prompt (CMD):
venv\Scripts\activate
# Jika menggunakan PowerShell:
.\venv\Scripts\Activate.ps1

# 4. Pastikan venv aktif (akan muncul tulisan (venv) di kiri prompt terminal)

# 5. Install dependencies
# (Pastikan menginstal library yang dibutuhkan sesuai file requirements)
pip install -r requirements.txt

# 6. Jalankan aplikasi
streamlit run app.py
