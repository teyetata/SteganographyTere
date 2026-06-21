"""
============================================================================
 APLIKASI STEGANOGRAFI "TRIPLE-A" (AES + PRNG/LCG + Modified LSB)
============================================================================

 Alur Algoritma Triple-A:
   1. ENKRIPSI   : Pesan rahasia dienkripsi dengan AES-256 (mode CBC).
                    Kunci AES diturunkan dari password pengguna (SHA-256,
                    diambil 32 byte pertama -> AES-256).
   2. PRNG (LCG) : x_(i+1) = (a * x_i + C) mod m
                    Tiga stream LCG independen dibangkitkan dari password:
                       - Stream Movement -> memilih pola pergerakan piksel
                       - Stream Channel  -> memilih saluran warna (R,G,B,...)
                       - Stream Bit      -> memilih jumlah bit LSB yang disisip
   3. ROUTING    : Pola pergerakan piksel (Spiral / Squared / Snake / Ray)
                    menentukan URUTAN koordinat piksel yang akan disisipi.
                    Karena pola pergerakan menentukan urutan piksel secara
                    keseluruhan, pola dipilih SEKALI di awal proses (hasil
                    draw pertama dari stream Movement). Saluran warna dan
                    jumlah bit tetap di-update PER LANGKAH penyisipan sesuai
                    spesifikasi tugas.
   4. EMBEDDING  : Bit ciphertext (didahului header panjang pesan 32-bit)
                    disisipkan ke LSB channel warna yang dipilih.

============================================================================
"""

import io
import math
import hashlib
import base64

import numpy as np
import streamlit as st
from PIL import Image
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
from streamlit_option_menu import option_menu

# ============================================================================
# 1. KONFIGURASI HALAMAN & TEMA CSS (PROFESSIONAL BLUE THEME)
# ============================================================================
st.set_page_config(
    page_title="Triple-A Steganography Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
/* ---------- Global Background (Navy / Ocean Blue Gradient) ---------- */
.stApp {
    background: linear-gradient(180deg, #050b1a 0%, #0a1630 45%, #0d1f3c 100%);
    color: #e6f1ff;
}

/* ---------- Sidebar ---------- */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #061024 0%, #0a1a3a 100%);
    border-right: 1px solid #1c3a66;
}
section[data-testid="stSidebar"] * { color: #cfe6ff !important; }

/* ---------- Headings ---------- */
h1, h2, h3 {
    color: #5ad1ff !important;
    text-shadow: 0 0 12px rgba(90, 209, 255, 0.35);
}

/* ---------- Cards / Containers ---------- */
div[data-testid="stMetric"] {
    background: linear-gradient(135deg, #0e2547 0%, #123164 100%);
    border: 1px solid #1f4f8a;
    border-radius: 14px;
    padding: 14px 10px;
    box-shadow: 0 0 18px rgba(0, 153, 255, 0.18);
}
div[data-testid="stMetric"] label { color: #8fc7ff !important; }
div[data-testid="stMetric"] div { color: #ffffff !important; }

/* ---------- Buttons ---------- */
.stButton > button, .stDownloadButton > button {
    background: linear-gradient(90deg, #0072ff 0%, #00c6ff 100%);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 0.6em 1.4em;
    font-weight: 600;
    letter-spacing: 0.5px;
    box-shadow: 0 0 14px rgba(0, 198, 255, 0.45);
    transition: all 0.2s ease-in-out;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    transform: translateY(-2px) scale(1.02);
    box-shadow: 0 0 22px rgba(0, 198, 255, 0.75);
}

/* ---------- Text areas / inputs ---------- */
textarea, input, .stTextInput input {
    background-color: #0c1f3f !important;
    color: #e6f1ff !important;
    border: 1px solid #1f4f8a !important;
    border-radius: 8px !important;
}

/* ---------- File uploader ---------- */
section[data-testid="stFileUploaderDropzone"] {
    background: #0c1f3f;
    border: 1.5px dashed #2f7bd8;
    border-radius: 12px;
}

/* ---------- Progress / capacity bar text ---------- */
.capacity-box {
    background: #0c1f3f;
    border-left: 4px solid #00c6ff;
    padding: 10px 16px;
    border-radius: 8px;
    margin-bottom: 10px;
}

hr { border-color: #1f4f8a; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ============================================================================
# 2. KONSTANTA & VALIDASI
# ============================================================================
MIN_DIM = 250          # resolusi minimum wajib (250x250)
MAX_RESIZE_DIM = 4096  # auto-resize jika gambar terlalu besar (>4096px)
TRIGGER_RESIZE_DIM = 5000  # batas resolusi untuk trigger auto-resize (agar UI tetap responsif)
HEADER_BITS = 32       # 32-bit header menyimpan panjang ciphertext (byte)
ALLOWED_EXT = ("png", "bmp", "jpg", "jpeg")  # JPG/JPEG ditolak karena lossy compression

CHANNEL_MAP = {
    0: ["R"], 1: ["G"], 2: ["B"],
    3: ["R", "G"], 4: ["R", "B"], 5: ["G", "B"], 6: ["R", "G", "B"],
}
CHANNEL_IDX = {"R": 0, "G": 1, "B": 2}


# ============================================================================
# 3. MODUL KRIPTOGRAFI - AES-256 (Tahap 1 Triple-A)
# ============================================================================
def derive_aes_key(password: str) -> bytes:
    """Menurunkan kunci AES-256 (32 byte) dari password via SHA-256."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return digest  # AES-256 membutuhkan key sepanjang 32 byte

def aes_encrypt(plaintext: str, password: str) -> bytes:
    """
    Enkripsi AES-256 mode CBC.
    Output = IV (16 byte) || ciphertext (PKCS7-padded)
    """
    key = derive_aes_key(password)
    iv = os.urandom(16)  # UKURAN BLOK: Wajib 16 byte mutlak untuk semua jenis AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(blob: bytes, password: str) -> str:
    """Dekripsi AES-256 CBC. blob = IV(16 byte) || ciphertext."""
    key = derive_aes_key(password)
    iv, ciphertext = blob[:16], blob[16:]  # PEMOTONGAN IV: Tetap 16 byte
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode("utf-8")

def aes_encrypt(plaintext: str, password: str) -> bytes:
    """
    Enkripsi AES-256 mode CBC.
    Output = IV (16 byte) || ciphertext (PKCS7-padded)
    IV disimpan di depan ciphertext agar proses dekripsi tidak butuh
    saluran terpisah untuk mengirim IV.
    """
    key = derive_aes_key(password)
    iv = os.urandom(16)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(blob: bytes, password: str) -> str:
    """Dekripsi AES-256 CBC. blob = IV(16 byte) || ciphertext."""
    key = derive_aes_key(password)
    iv, ciphertext = blob[:16], blob[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode("utf-8")


# ============================================================================
# 4. MODUL PRNG - Linear Congruential Generator (Tahap 2 Triple-A)
# ============================================================================
class LCG:
    """
    Linear Congruential Generator:
        x_(i+1) = (a * x_i + C) mod m
    Mengikuti aturan dari slide kuliah: nilai a dan C tidak boleh 0.
    """

    def __init__(self, a: int, c: int, x0: int, m: int):
        self.a = a if a != 0 else 1
        self.c = c if c != 0 else 1
        self.m = m
        self.state = x0 % m if m > 0 else 0

    def next(self) -> int:
        self.state = (self.a * self.state + self.c) % self.m
        return self.state


def derive_lcg_seeds(password: str, stream_salt: str, m: int) -> LCG:
    """
    Membangkitkan parameter awal LCG (a, C, x0) dari password.
    Mengikuti pola di slide: setiap karakter password diubah ke 8 bit,
    lalu di-XOR seluruhnya. Hasil XOR dipecah menjadi bit-bit untuk x0, C, a.
    `stream_salt` membuat 3 stream (movement/channel/bit) saling independen
    walau password yang dipakai sama.
    """
    combined = password + stream_salt
    xor_val = 0
    for ch in combined:
        xor_val ^= ord(ch)
    xor_val &= 0xFF  # batasi ke 8 bit seperti contoh di slide

    x0 = xor_val & 0b11            # bit 0-1 -> x0
    c = (xor_val >> 2) & 0b111     # bit 2-4 -> C
    a = (xor_val >> 5) & 0b111     # bit 5-7 -> a

    if c == 0:
        c += 1  # aturan: C tidak boleh 0
    if a == 0:
        a += 1  # aturan: a tidak boleh 0

    return LCG(a=a, c=c, x0=x0, m=m)


# ============================================================================
# 5. MODUL ROUTING - Pola Pergerakan Piksel (Tahap 3 Triple-A)
# ============================================================================
def movement_snake(h: int, w: int):
    """Pola Snake/Boustrophedon: kiri-ke-kanan, lalu kanan-ke-kiri, dst."""
    coords = []
    for y in range(h):
        row = range(w) if y % 2 == 0 else range(w - 1, -1, -1)
        for x in row:
            coords.append((y, x))
    return coords


def movement_ray(h: int, w: int):
    """Pola Ray/diagonal: menjalar antar-diagonal dari kiri-atas."""
    coords = []
    for d in range(h + w - 1):
        for y in range(max(0, d - w + 1), min(h, d + 1)):
            x = d - y
            if 0 <= x < w:
                coords.append((y, x))
    return coords


def movement_squared(h: int, w: int):
    """Pola Squared (boustrophedon per-kolom): sederhana, kolom demi kolom
    berselang-seling arah, menyerupai gerakan kotak bolak-balik."""
    coords = []
    for x in range(w):
        col = range(h) if x % 2 == 0 else range(h - 1, -1, -1)
        for y in col:
            coords.append((y, x))
    return coords


def movement_spiral(h: int, w: int):
    """Pola Spiral: dimulai dari tepi luar berputar searah jarum jam
    menuju titik pusat citra."""
    coords = []
    top, bottom, left, right = 0, h - 1, 0, w - 1
    while top <= bottom and left <= right:
        for x in range(left, right + 1):
            coords.append((top, x))
        top += 1
        for y in range(top, bottom + 1):
            coords.append((y, right))
        right -= 1
        if top <= bottom:
            for x in range(right, left - 1, -1):
                coords.append((bottom, x))
            bottom -= 1
        if left <= right:
            for y in range(bottom, top - 1, -1):
                coords.append((y, left))
            left += 1
    return coords


MOVEMENT_FUNCS = {
    0: ("Spiral", movement_spiral),
    1: ("Squared", movement_squared),
    2: ("Snake", movement_snake),
    3: ("Ray", movement_ray),
}


# ============================================================================
# ============================================================================
# 6. MODUL EMBEDDING / EXTRACTION (Tahap 4 - Modified LSB)
# ============================================================================
def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)

def bits_to_bytes(bits: str) -> bytes:
    n = len(bits) // 8
    return bytes(int(bits[i * 8:(i + 1) * 8], 2) for i in range(n))

def build_routing_context(password: str, h: int, w: int):
    lcg_move = derive_lcg_seeds(password, "MOVE", m=4)
    lcg_chan = derive_lcg_seeds(password, "CHAN", m=7)
    lcg_bit = derive_lcg_seeds(password, "BIT", m=4)

    move_choice = lcg_move.next() % 4
    move_name, move_func = MOVEMENT_FUNCS[move_choice]
    pixel_order = move_func(h, w)

    return move_name, pixel_order, lcg_chan, lcg_bit

def next_bit_count(lcg_bit: LCG) -> int:
    val = lcg_bit.next() % 4
    if val == 0:
        val = 1
    return val

# ✨ MODIFIKASI: Menambahkan parameter custom_lcg
def embed_message(cover_img: np.ndarray, secret_bits: str, password: str, mode="Otomatis", manual_chan="RGB", manual_bit=1, custom_lcg=None):
    h, w, _ = cover_img.shape
    stego_img = cover_img.copy()
    move_name, pixel_order, lcg_chan, lcg_bit = build_routing_context(password, h, w)

    # Timpa LCG bawaan jika mode "Input LCG" dipilih
    if mode == "Input LCG" and custom_lcg:
        lcg_chan = LCG(a=custom_lcg['c_a'], c=custom_lcg['c_c'], x0=custom_lcg['c_x0'], m=7)
        lcg_bit = LCG(a=custom_lcg['b_a'], c=custom_lcg['b_c'], x0=custom_lcg['b_x0'], m=4)

    bit_idx = 0
    total_bits = len(secret_bits)
    used_pixels = 0

    for (y, x) in pixel_order:
        if bit_idx >= total_bits:
            break

        if mode == "Manual Statis":
            channels = list(manual_chan)
            n_bits = manual_bit
        else:
            channel_choice = lcg_chan.next() % 7
            channels = CHANNEL_MAP[channel_choice]
            n_bits = next_bit_count(lcg_bit)

        for ch in channels:
            if bit_idx >= total_bits:
                break
            c_idx = CHANNEL_IDX[ch]
            pixel_val = int(stego_img[y, x, c_idx])

            chunk = secret_bits[bit_idx: bit_idx + n_bits]
            chunk = chunk.ljust(n_bits, "0")
            bit_idx += len(secret_bits[bit_idx: bit_idx + n_bits])

            mask = (0xFF << n_bits) & 0xFF
            cleared = pixel_val & mask
            new_val = cleared | int(chunk, 2)

            stego_img[y, x, c_idx] = np.uint8(new_val)

        used_pixels += 1

    return stego_img, move_name, used_pixels, bit_idx >= total_bits

# ✨ MODIFIKASI: Menambahkan parameter custom_lcg
def extract_message(stego_img: np.ndarray, password: str, total_bits_needed: int, mode="Otomatis", manual_chan="RGB", manual_bit=1, custom_lcg=None):
    h, w, _ = stego_img.shape
    move_name, pixel_order, lcg_chan, lcg_bit = build_routing_context(password, h, w)

    # Timpa LCG bawaan jika mode "Input LCG" dipilih
    if mode == "Input LCG" and custom_lcg:
        lcg_chan = LCG(a=custom_lcg['c_a'], c=custom_lcg['c_c'], x0=custom_lcg['c_x0'], m=7)
        lcg_bit = LCG(a=custom_lcg['b_a'], c=custom_lcg['b_c'], x0=custom_lcg['b_x0'], m=4)

    extracted_bits = ""
    for (y, x) in pixel_order:
        if len(extracted_bits) >= total_bits_needed:
            break

        if mode == "Manual Statis":
            channels = list(manual_chan)
            n_bits = manual_bit
        else:
            channel_choice = lcg_chan.next() % 7
            channels = CHANNEL_MAP[channel_choice]
            n_bits = next_bit_count(lcg_bit)

        for ch in channels:
            if len(extracted_bits) >= total_bits_needed:
                break
            c_idx = CHANNEL_IDX[ch]
            pixel_val = int(stego_img[y, x, c_idx])

            lsb_mask = (1 << n_bits) - 1
            bits_chunk = pixel_val & lsb_mask
            bits_str = format(bits_chunk, f"0{n_bits}b")
            extracted_bits += bits_str

    return extracted_bits[:total_bits_needed], move_name


def calculate_capacity(h: int, w: int) -> int:
    """
    Estimasi kapasitas KASAR (jumlah bit) jika setiap piksel rata-rata
    memakai ~1 channel x ~2 bit (estimasi konservatif untuk UI real-time).
    Kapasitas riil bervariasi tergantung hasil acak LCG.
    """
    # Memperbaiki estimasi rata-rata kapasitas yang lebih akurat
    # Secara rata-rata statistik LCG Triple-A: ~2 saluran terpilih x ~2 bit disisipkan = ~4 bit per pixel.
    # Kita gunakan 2.5 sebagai batas aman (konservatif) agar tidak terjadi overflow.
    return int(h * w * 2.5)


# ============================================================================
# 7. MODUL METRIK KUALITAS CITRA - MSE & PSNR
# ============================================================================
def compute_mse_psnr(original: np.ndarray, stego: np.ndarray):
    """
    MSE (Mean Squared Error):
        MSE = (1/(m*n)) * sum( (I(i,j) - K(i,j))^2 )
    Dihitung rata-rata di seluruh piksel & seluruh channel (R,G,B).

    PSNR (Peak Signal to Noise Ratio) dalam dB:
        PSNR = 20 * log10(MAX_I) - 10 * log10(MSE)
        MAX_I = 255 untuk citra 8-bit per channel.
    Semakin besar PSNR -> semakin mirip citra stego dengan citra asli
    (imperceptibility semakin baik).
    """
    original = original.astype(np.float64)
    stego = stego.astype(np.float64)

    mse = np.mean((original - stego) ** 2)
    if mse == 0:
        return 0.0, float("inf")  # citra identik -> PSNR tak hingga

    max_i = 255.0
    psnr = 20 * math.log10(max_i) - 10 * math.log10(mse)
    return mse, psnr


def compute_channel_metrics(original: np.ndarray, stego: np.ndarray):
    """Menghitung MSE dan PSNR spesifik untuk setiap saluran (Red, Green, Blue)."""
    metrics = {}
    channels = ['Red', 'Green', 'Blue']
    for i in range(3):
        mse, psnr = compute_mse_psnr(original[:, :, i], stego[:, :, i])
        metrics[channels[i]] = {'mse': mse, 'psnr': psnr}
    return metrics


# def build_difference_heatmap(original: np.ndarray, stego: np.ndarray):
#     """
#     Membuat peta perbedaan (difference map) antara citra asli dan stego.
#     Nilai piksel pada heatmap = total selisih absolut R+G+B pada lokasi
#     tersebut, sehingga titik yang disisipi pesan akan tampak menyala.
#     """
#     diff = np.abs(original.astype(np.int16) - stego.astype(np.int16))
#     diff_sum = diff.sum(axis=2)  # gabungkan R,G,B jadi 1 channel intensitas
    
#     # ✨ FITUR BARU: Normalisasi agar jejak LCG menyala terang
#     max_diff = diff_sum.max()
#     if max_diff > 0:
#         diff_sum = (diff_sum / max_diff) * 255  # Paksa yang redup jadi terang maksimal
        
#     return diff_sum


def plot_histogram_comparison(original: np.ndarray, stego: np.ndarray):
    """Membuat plot perbandingan histogram RGB antara gambar asli dan hasil steganografi."""
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    fig.patch.set_facecolor("#0a1630")
    colors = ('red', 'green', 'blue')
    
    # Plot Cover Image Histogram
    for i, color in enumerate(colors):
        hist_orig, _ = np.histogram(original[:, :, i], bins=256, range=(0, 256))
        axes[0].plot(hist_orig, color=color, alpha=0.75, linewidth=1.5)
    axes[0].set_title("Histogram Cover Image", color="#5ad1ff")
    axes[0].set_facecolor("#0a1630")
    axes[0].tick_params(colors="white")

    # Plot Stego Image Histogram
    for i, color in enumerate(colors):
        hist_stego, _ = np.histogram(stego[:, :, i], bins=256, range=(0, 256))
        axes[1].plot(hist_stego, color=color, alpha=0.75, linewidth=1.5)
    axes[1].set_title("Histogram Stego Image", color="#5ad1ff")
    axes[1].set_facecolor("#0a1630")
    axes[1].tick_params(colors="white")

    return fig


# ============================================================================
# 8. UTILITAS GAMBAR (VALIDASI & RESIZE)
# ============================================================================
def validate_and_load_image(uploaded_file):
    """
    Validasi format & resolusi sesuai aturan Robustness:
      - Hanya PNG / BMP yang diterima (JPG ditolak karena lossy compression
        akan merusak bit LSB).
      - Resolusi minimum 250x250.
      - Jika resolusi > 2000px pada sisi manapun -> auto-resize ke
        maksimum 1024x1024 (mempertahankan aspect ratio) agar perhitungan
        matriks tetap responsif.
    Mengembalikan (np.ndarray RGB, pesan_warning_atau_None) atau
    melempar ValueError jika validasi gagal.
    """
    ext = uploaded_file.name.split(".")[-1].lower()
    if ext not in ALLOWED_EXT:
        raise ValueError(
            f"Format '.{ext}' TIDAK DIIZINKAN. Gunakan file .PNG atau .BMP saja "
            f"(.JPG ditolak karena kompresi lossy merusak bit LSB)."
        )

    img = Image.open(uploaded_file).convert("RGB")
    w, h = img.size

    if w < MIN_DIM or h < MIN_DIM:
        raise ValueError(
            f"Resolusi citra ({w}x{h}) terlalu kecil. Minimum wajib {MIN_DIM}x{MIN_DIM} pixel."
        )

    warning_msg = None
    if w > TRIGGER_RESIZE_DIM or h > TRIGGER_RESIZE_DIM:
        img.thumbnail((MAX_RESIZE_DIM, MAX_RESIZE_DIM), Image.LANCZOS)
        warning_msg = (
            f"Resolusi asli ({w}x{h}) terlalu besar -> otomatis di-resize menjadi "
            f"{img.size[0]}x{img.size[1]} agar pemrosesan tetap cepat & stabil."
        )

    return np.array(img), warning_msg


def pil_image_to_download_bytes(img_array: np.ndarray) -> bytes:
    img = Image.fromarray(img_array.astype(np.uint8), mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

# ============================================================================
# 9. HALAMAN STREAMLIT - NATIVE TABS
# ============================================================================
# Pindahkan judul dari sidebar ke tengah halaman utama
st.markdown("<h2 style='text-align: center; color: #5ad1ff;'>🛡️ Triple-A Stego Suite</h2>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #cfe6ff;'>Algoritma: <b>AES-256 + LCG PRNG + Modified LSB</b></p>", unsafe_allow_html=True)

# Membuat Top Bar Menu yang elegan
menu = option_menu(
    menu_title=None,
    options=["How to Use", "Embedding", "Extraction"], # <--- Tambah "How to Use" di sini
    icons=["book", "lock", "unlock"], # <--- Tambah ikon "book" di sini
    menu_icon="cast",
    default_index=0, # 0 berarti "How to Use" akan terbuka pertama kali saat web dimuat
    orientation="horizontal",
    styles={
        "container": {"padding": "0!important", "background-color": "#0a1a3a", "border": "1px solid #1f4f8a", "border-radius": "10px", "margin-bottom": "20px"},
        "icon": {"color": "#5ad1ff", "font-size": "18px"},
        "nav-link": {"color": "#cfe6ff", "font-size": "16px", "text-align": "center", "margin":"0px", "--hover-color": "#123164"},
        "nav-link-selected": {"background-color": "#0072ff", "font-weight": "bold"},
    }
)

st.info("💡 Password yang sama WAJIB digunakan saat Embedding & Extraction.")

# ============================================================================
# 9.5 HALAMAN How to Use (DOKUMENTASI)
# ============================================================================
if menu == "How to Use":
    st.title("📖 How to Use Algoritma Triple-A")
    st.markdown(
        "Aplikasi ini mengamankan pesan rahasia menggunakan tiga lapis algoritma "
        "(Kriptografi, Pseudo-Random Number Generator, dan Steganografi). "
        "Berikut adalah rincian proses dari masing-masing lapisan pelindung:"
    )

    with st.expander("🔒 Lapis 1: Kriptografi AES-256 (Cipher Block Chaining)"):
        st.markdown(
            """
            Sebelum disembunyikan, pesan teks/dokumen asli dihancurkan polanya menggunakan **Advanced Encryption Standard (AES) 256-bit**.
            
            * **SHA-256 Key Derivation:** *Password* yang Anda masukkan akan di-*hash* menjadi kunci sepanjang 32 byte (256-bit).
            * **Mode CBC:** Algoritma menggunakan mode *Cipher Block Chaining* (CBC). Mode ini menggunakan *Initialization Vector* (IV) sebesar 16 byte untuk memastikan bahwa pola teks yang sama akan dienkripsi menjadi *ciphertext* yang sama sekali berbeda, sehingga tidak bisa ditebak melalui analisis frekuensi huruf.
            * Hasil dari tahap ini adalah data biner mentah (*ciphertext*) yang terlihat seperti *noise* (derau) acak.
            """
        )

    with st.expander("🎲 Lapis 2: LCG PRNG (Pembuat Rute Acak)"):
        st.markdown(
            """
            *Linear Congruential Generator* (LCG) adalah algoritma matematika PRNG dengan persamaan:
            """
        )
        st.latex(r"x_{i+1} = (a \cdot x_i + C) \pmod m")
        st.markdown(
            """
            Aplikasi ini menggunakan huruf-huruf dari *password* sebagai nilai awal (*Seed*) LCG. Mesin LCG kemudian berputar untuk menentukan tiga hal secara deterministik:
            1. **Movement (Pergerakan):** Menentukan rute piksel mana yang akan dilewati (Spiral, Zig-zag/Snake, Kolom/Squared, atau Diagonal/Ray).
            2. **Channel Hopping:** Memilih secara acak saluran warna mana yang akan disusupi pesan (hanya Merah, Kombinasi Merah & Biru, dll).
            3. **Dynamic Bit Depth:** Memilih jumlah bit yang akan disisipkan per piksel (antara 1 hingga 3 bit).
            """
        )

    with st.expander("🖼️ Lapis 3: Modified LSB (Penyisipan Pesan)"):
        st.markdown(
            """
            *Least Significant Bit* (LSB) adalah teknik mengganti bit paling belakang pada matriks warna piksel gambar dengan bit dari *ciphertext*.
            
            * Pada steganografi klasik, bit selalu diubah secara berurutan dan teratur.
            * Pada **Modified LSB**, penyisipan mengikuti rute, saluran warna, dan kedalaman bit yang diinstruksikan oleh mesin LCG PRNG.
            * Karena yang diubah hanya bit paling tidak signifikan, secara matematis (terbukti melalui metrik **PSNR > 40 dB**), mata telanjang manusia tidak akan mampu melihat perbedaan antara *Cover Image* dan *Stego Image*.
            """
        )
        
    st.markdown("---")
    st.caption("Silakan navigasikan menu di atas ke **Embedding** untuk mulai menyembunyikan pesan, atau **Extraction** untuk membongkar pesan.")

# ============================================================================
# 9.5 HALAMAN How to Use (DOKUMENTASI)
# ============================================================================
if menu == "How to Use":
    st.title("📖 Panduan Penggunaan Aplikasi")
    st.markdown(
        "Selamat datang! Aplikasi ini memiliki dua fungsi utama: **Embedding** (untuk menyembunyikan pesan ke dalam gambar) "
        "dan **Extraction** (untuk membongkar kembali pesan dari gambar). "
        "Ikuti langkah-langkah mudah di bawah ini untuk mulai menggunakannya."
    )

    st.markdown("---")

    # PANDUAN EMBEDDING
    st.markdown("### 🔒 1. How to Use Menu EMBEDDING (Menyisipkan Pesan)")
    st.info("Gunakan menu ini jika Anda memiliki pesan rahasia yang ingin disembunyikan ke dalam sebuah gambar.")
    
    col_e1, col_e2 = st.columns([1, 1])
    with col_e1:
        st.markdown(
            """
            **Langkah-langkah:**
            1. **Pilih Menu:** Klik tombol **Embedding** di bilah navigasi atas.
            2. **Unggah Gambar:** Masukkan gambar biasa (Cover Image) berformat `.PNG` atau `.BMP`. Gambar ini akan menjadi "wadah" untuk pesan Anda.
            3. **Masukkan Pesan:** Anda bisa mengetik pesan secara manual di kotak yang disediakan, atau memilih **"Unggah File (.txt)"** jika pesan Anda berupa dokumen panjang.
            4. **Buat Password:** Ketik kata sandi rahasia. **Ingat baik-baik password ini!** Tanpa password ini, pesan tidak akan pernah bisa dibuka lagi.
            5. **Proses:** Klik tombol biru **"🚀 Proses Embedding"**.
            """
        )
    with col_e2:
        st.success(
            """
            **Apa yang Terjadi Setelahnya?**
            * Aplikasi akan menyisipkan pesan Anda ke dalam gambar tersebut tanpa mengubah tampilan visual gambar sama sekali.
            * Anda akan melihat laporan metrik (seperti PSNR dan Histogram) untuk membuktikan bahwa gambar tidak rusak.
            * Di bagian paling bawah, klik **"📥 Download Stego Image"** untuk menyimpan gambar yang sudah berisi pesan rahasia ke laptop Anda. Gambar inilah yang siap Anda kirimkan ke teman Anda!
            """
        )

    st.markdown("---")

    # PANDUAN EXTRACTION
    st.markdown("### 🔓 2. How to Use Menu EXTRACTION (Membongkar Pesan)")
    st.warning("Gunakan menu ini jika Anda menerima gambar rahasia (Stego Image) dari seseorang dan ingin membaca isinya.")

    col_x1, col_x2 = st.columns([1, 1])
    with col_x1:
        st.markdown(
            """
            **Langkah-langkah:**
            1. **Pilih Menu:** Klik tombol **Extraction** di bilah navigasi atas.
            2. **Unggah Gambar:** Masukkan gambar (Stego Image) yang sudah disisipi pesan rahasia sebelumnya.
            3. **Masukkan Password:** Ketik kata sandi yang **sama persis** dengan yang digunakan saat proses Embedding (huruf besar & kecil sangat berpengaruh!).
            4. **Proses:** Klik tombol biru **"🔍 Proses Extraction"**.
            """
        )
    with col_x2:
        st.success(
            """
            **Apa yang Terjadi Setelahnya?**
            * Aplikasi akan memindai gambar tersebut dan mencari pesan yang tersembunyi.
            * Jika gambar dan passwordnya benar, isi pesan rahasia (Plaintext) akan langsung muncul di layar Anda!
            * Anda bisa langsung membacanya, atau mengeklik tombol **"📥 Download Pesan (.txt)"** untuk menyimpan isi pesannya menjadi file dokumen.
            """
        )
        
    st.markdown("---")
    st.caption("💡 **Tips:** Selalu gunakan format gambar `.PNG` saat mengirim gambar via chat atau email, karena format `.JPG` (seperti fitur kompresi WhatsApp) akan merusak pesan yang ada di dalamnya.")

# ============================================================================
# 10. HALAMAN EMBEDDING
# ============================================================================
elif menu == "Embedding":
    st.title("🔒 Embedding — Sisipkan Pesan Rahasia")
    st.caption("Cover Image → AES-256 → LCG Routing → Modified LSB → Stego Image")

    col_upload, col_form = st.columns([1, 1])

    with col_upload:
        st.subheader("1️⃣ Unggah Cover Image")
        uploaded_file = st.file_uploader(
            "Hanya menerima file .PNG / .BMP (min. 250x250 px)",
            type=["png", "bmp"],
        )

        cover_array = None
        if uploaded_file is not None:
            try:
                cover_array, warn = validate_and_load_image(uploaded_file)
                if warn:
                    st.warning(warn)
                st.image(cover_array, caption="Cover Image (Preview)", use_container_width=True)
                h, w, _ = cover_array.shape
                st.success(f"Citra valid: {w} x {h} pixel")
            except ValueError as e:
                st.error(str(e))

    with col_form:
        st.subheader("2️⃣ Pesan & Kunci Rahasia")
        
        # Fitur Input Pesan (Ketik Teks ATAU Unggah File)
        input_method = st.radio("Pilih Metode Input:", ["📝 Ketik Manual", "📄 Unggah File (.txt)"], horizontal=True)
        
        secret_message = ""
        if input_method == "📝 Ketik Manual":
            secret_message = st.text_area(
                "Pesan Rahasia (Plaintext)", 
                value="", 
                placeholder="Ketik pesan rahasia yang ingin disembunyikan di sini... (Wajib diisi)", 
                height=120,
            )
        else:
            uploaded_secret = st.file_uploader("Unggah dokumen teks rahasia", type=["txt"])
            if uploaded_secret is not None:
                try:
                    secret_message = uploaded_secret.read().decode("utf-8")
                    st.success(f"✅ File '{uploaded_secret.name}' berhasil dibaca! ({len(secret_message)} karakter)")
                    with st.expander("👀 Preview Isi File"):
                        preview_text = secret_message[:500] + ("..." if len(secret_message) > 500 else "")
                        st.text(preview_text)
                except Exception:
                    st.error("❌ Gagal membaca file. Pastikan file berformat teks murni (.txt).")

        # ==========================================
        # BLOK UI PENGATURAN KEAMANAN (EMBEDDING)
        # ==========================================
        st.markdown("---")
        st.markdown("#### ⚙️ Konfigurasi Keamanan & Steganografi")
        
        password = st.text_input("Password / Kunci (AES + Seed LCG)", type="password", placeholder="Wajib diisi...")

        st.write("**Metode Penentuan Saluran & Bit:**")
        mode_param = st.radio(
            "Metode Parameter:", 
            ["🔄 Otomatis (Belakang Layar)", "🔢 Parameter LCG (Auto)", "🛠️ Manual Statis (Pilih Sendiri)"], 
            horizontal=True,
            label_visibility="collapsed"
        )
        
        manual_channel = "RGB"
        manual_bit = 1
        custom_lcg_params = None
        
        # JIKA MENGKLIK OPSI 2 (Parameter LCG Auto - Tampilan otomatis terisi dari password)
        if mode_param == "🔢 Parameter LCG (Auto)":
            st.markdown("""<div style="background-color: #0c1f3f; padding: 15px; border-radius: 8px; border: 1px dashed #5ad1ff; margin-bottom: 15px;">
                <b>Parameter LCG Tergenerasi (Auto dari Password)</b><br>
                <i>Nilai Xn, A, dan C di bawah ini dihitung otomatis secara real-time berdasarkan kunci Anda.</i>
                """, unsafe_allow_html=True)
            
            # Hitung nilai secara otomatis jika password sudah diinput pengguna
            if password:
                lcg_chan_demo = derive_lcg_seeds(password, "CHAN", m=7)
                lcg_bit_demo = derive_lcg_seeds(password, "BIT", m=4)
                c_x0, c_a, c_c = lcg_chan_demo.state, lcg_chan_demo.a, lcg_chan_demo.c
                b_x0, b_a, b_c = lcg_bit_demo.state, lcg_bit_demo.a, lcg_bit_demo.c
            else:
                c_x0, c_a, c_c = 0, 0, 0
                b_x0, b_a, b_c = 0, 0, 0

            c1, c2, c3 = st.columns(3)
            with c1:
                st.number_input("Xn (Channel)", value=int(c_x0), disabled=True, key="embed_auto_cx0")
                st.number_input("Xn (Bit)", value=int(b_x0), disabled=True, key="embed_auto_bx0")
            with c2:
                st.number_input("A (Channel)", value=int(c_a), disabled=True, key="embed_auto_ca")
                st.number_input("A (Bit)", value=int(b_a), disabled=True, key="embed_auto_ba")
            with c3:
                st.number_input("C (Channel)", value=int(c_c), disabled=True, key="embed_auto_cc")
                st.number_input("C (Bit)", value=int(b_c), disabled=True, key="embed_auto_bc")
            st.markdown("</div>", unsafe_allow_html=True)
            
            custom_lcg_params = {"c_x0": c_x0, "c_a": c_a, "c_c": c_c, "b_x0": b_x0, "b_a": b_a, "b_c": b_c}

        # JIKA MENGKLIK OPSI 3 (Pilih Tombol Manual)
        elif mode_param == "🛠️ Manual Statis (Pilih Sendiri)":
            st.markdown("""<div style="background-color: #0c1f3f; padding: 15px; border-radius: 8px; border: 1px dashed #5ad1ff; margin-bottom: 15px;">""", unsafe_allow_html=True)
            mc1, mc2 = st.columns([1.5, 1])
            with mc1:
                manual_channel = st.radio("Saluran Warna:", ["R", "G", "B", "RG", "RB", "GB", "RGB"], horizontal=True)
            with mc2:
                manual_bit = st.radio("Depth:", [1, 2, 3], format_func=lambda x: f"{x} Bit", horizontal=True)
            st.markdown("</div>", unsafe_allow_html=True)
        # ==========================================

        # ---- Real-time capacity counter ----
        if cover_array is not None:
            h, w, _ = cover_array.shape
            capacity_bits = calculate_capacity(h, w)
            capacity_chars = capacity_bits // 8
            used_chars = len(secret_message)
            remaining = capacity_chars - used_chars
            pct = min(used_chars / max(capacity_chars, 1), 1.0)

            st.markdown(
                f"""<div class="capacity-box">
                <b>Estimasi Kapasitas Citra:</b> ~{capacity_chars} karakter<br>
                <b>Terpakai:</b> {used_chars} karakter &nbsp;|&nbsp;
                <b>Sisa:</b> {max(remaining, 0)} karakter
                </div>""",
                unsafe_allow_html=True,
            )
            st.progress(pct)
            if remaining < 0:
                st.error("⚠️ Pesan terlalu panjang untuk kapasitas citra ini!")
        else:
            st.info("Unggah cover image terlebih dahulu untuk melihat kapasitas real-time.")

        process_btn = st.button("🚀 Proses Embedding", use_container_width=True)

    # ---- Proses Embedding ----
    if process_btn:
        if cover_array is None:
            st.error("Silakan unggah cover image yang valid terlebih dahulu.")
        elif not password:
            st.error("Password tidak boleh kosong.")
        elif not secret_message:
            st.error("Pesan rahasia tidak boleh kosong.")
        else:
            with st.spinner("Mengenkripsi pesan (AES-256) & menyisipkan via LCG routing..."):
                # Tahap 1: Enkripsi AES
                ciphertext_blob = aes_encrypt(secret_message, password)

                # Tahap: susun bitstream = header(32-bit panjang) + ciphertext bits
                cipher_bits = bytes_to_bits(ciphertext_blob)
                header_bits = format(len(cipher_bits), f"0{HEADER_BITS}b")
                full_bits = header_bits + cipher_bits

                # Pemetaan string mode ke fungsi inti steganografi
                if mode_param == "🔄 Otomatis (Belakang Layar)":
                    embed_mode = "Otomatis"
                elif mode_param == "🔢 Parameter LCG (Auto)":
                    embed_mode = "Input LCG"
                else:
                    embed_mode = "Manual Statis"

                stego_array, move_name, used_pixels, fully_embedded = embed_message(
                    cover_array, full_bits, password, 
                    mode=embed_mode, 
                    manual_chan=manual_channel, 
                    manual_bit=manual_bit,
                    custom_lcg=custom_lcg_params
                )

            if not fully_embedded:
                st.error(
                    "❌ Kapasitas citra tidak mencukupi untuk menampung seluruh pesan "
                    "terenkripsi. Gunakan citra dengan resolusi lebih besar atau "
                    "persingkat pesan."
                )
            else:
                mse, psnr = compute_mse_psnr(cover_array, stego_array)
                # diff_map = build_difference_heatmap(cover_array, stego_array)
                channel_metrics = compute_channel_metrics(cover_array, stego_array)

                st.success(f"✅ Penyisipan berhasil! Pola pergerakan terpilih: **{move_name}**")

                st.markdown("### 📊 Live Metrics Dashboard")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("MSE (Keseluruhan)", f"{mse:.6f}")
                m2.metric("PSNR (Keseluruhan)", f"{psnr:.2f} dB")
                m3.metric("Pola Pergerakan", move_name)
                m4.metric("Piksel Terpakai", f"{used_pixels}")

                st.markdown("#### Detail Metrik Per-Saluran Warna")
                col_r, col_g, col_b = st.columns(3)
                col_r.info(f"🔴 **RED** |  MSE: {channel_metrics['Red']['mse']:.6f}  |  PSNR: {channel_metrics['Red']['psnr']:.2f} dB")
                col_g.success(f"🟢 **GREEN**|  MSE: {channel_metrics['Green']['mse']:.6f}  |  PSNR: {channel_metrics['Green']['psnr']:.2f} dB")
                col_b.info(f"🔵 **BLUE** |  MSE: {channel_metrics['Blue']['mse']:.6f}  |  PSNR: {channel_metrics['Blue']['psnr']:.2f} dB")

                st.markdown("### 🖼️ Steganalysis Visualizer")
                c1, c2 = st.columns(2)
                with c1:
                    st.image(cover_array, caption="Cover Image (Original)", use_container_width=True)
                with c2:
                    st.image(stego_array, caption="Stego Image (Hasil Penyisipan)", use_container_width=True)

                # st.markdown("#### 🔥 Difference Map / Heatmap (Lokasi Piksel yang Berubah)")
                # fig, ax = plt.subplots(figsize=(6, 6))
                # fig.patch.set_facecolor("#0a1630")
                # ax.set_facecolor("#0a1630")
                # im = ax.imshow(diff_map, cmap="inferno")
                # ax.set_title("Heatmap Perubahan Piksel (LCG Routing)", color="#5ad1ff")
                # ax.axis("off")
                # cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
                # cbar.ax.yaxis.set_tick_params(color="white")
                # plt.setp(plt.getp(cbar.ax.axes, "yticklabels"), color="white")
                # st.pyplot(fig)

                st.markdown("#### 📈 Analisis Histogram RGB")
                st.caption("Jika grafiknya identik, metode steganografi berhasil menyembunyikan pesan tanpa merusak sebaran warna.")
                hist_fig = plot_histogram_comparison(cover_array, stego_array)
                st.pyplot(hist_fig)

                st.markdown("### ⬇️ Unduh Hasil")
                stego_bytes = pil_image_to_download_bytes(stego_array)
                st.download_button(
                    label="📥 Download Stego Image (PNG)",
                    data=stego_bytes,
                    file_name="stego_image_triple_a.png",
                    mime="image/png",
                    use_container_width=True,
                )

                st.info(
                    f"ℹ️ Catat informasi ini (opsional, sistem extraction sudah "
                    f"otomatis menyimpan header panjang pesan di dalam gambar): "
                    f"Total bit payload (header+ciphertext) = {len(full_bits)} bit."
                )


# ============================================================================
# 11. HALAMAN EXTRACTION
# ============================================================================
elif menu == "Extraction":
    st.title("🔓 Extraction — Ekstrak Pesan Rahasia")
    st.caption("Stego Image → LCG Routing → Modified LSB Reader → AES Decrypt → Plaintext")
    col_upload2, col_form2 = st.columns([1, 1])

    with col_upload2:
        st.subheader("1️⃣ Unggah Stego Image")
        uploaded_stego = st.file_uploader(
            "Hanya menerima file .PNG / .BMP (min. 250x250 px)",
            type=["png", "bmp"],
            key="extract_uploader",
        )
        stego_array = None
        if uploaded_stego is not None:
            try:
                stego_array, warn = validate_and_load_image(uploaded_stego)
                if warn:
                    st.warning(warn)
                st.image(stego_array, caption="Stego Image (Preview)", use_container_width=True)
            except ValueError as e:
                st.error(str(e))

    with col_form2:
        # ==========================================
        # BLOK UI PENGATURAN KEAMANAN (EXTRACTION)
        # ==========================================
        st.subheader("2️⃣ Password & Konfigurasi Pembongkaran")
        
        password_extract = st.text_input(
            "Masukkan Password yang SAMA dengan saat Embedding",
            type="password",
            key="extract_password",
            placeholder="Masukkan password..."
        )

        st.write("**Metode Parameter Saat Disisipkan:**")
        mode_param_ext = st.radio(
            "Metode Parameter:", 
            ["🔄 Otomatis (Belakang Layar)", "🔢 Parameter LCG (Auto)", "🛠️ Manual Statis (Pilih Sendiri)"], 
            horizontal=True,
            label_visibility="collapsed",
            key="ext_mode"
        )
        
        manual_channel_ext = "RGB"
        manual_bit_ext = 1
        custom_lcg_params_ext = None
        
        # JIKA MENGKLIK OPSI 2 (Parameter LCG Auto - Tampilan otomatis terisi dari password)
        if mode_param_ext == "🔢 Parameter LCG (Auto)":
            st.markdown("""<div style="background-color: #0c1f3f; padding: 15px; border-radius: 8px; border: 1px dashed #5ad1ff; margin-bottom: 15px;">
                <b>Parameter LCG Tergenerasi (Auto dari Password)</b><br>
                <i>Nilai Xn, A, dan C di bawah ini dihitung otomatis secara real-time berdasarkan kunci Anda.</i>
                """, unsafe_allow_html=True)
            
            if password_extract:
                lcg_chan_demo_ext = derive_lcg_seeds(password_extract, "CHAN", m=7)
                lcg_bit_demo_ext = derive_lcg_seeds(password_extract, "BIT", m=4)
                c_x0_ext, c_a_ext, c_c_ext = lcg_chan_demo_ext.state, lcg_chan_demo_ext.a, lcg_chan_demo_ext.c
                b_x0_ext, b_a_ext, b_c_ext = lcg_bit_demo_ext.state, lcg_bit_demo_ext.a, lcg_bit_demo_ext.c
            else:
                c_x0_ext, c_a_ext, c_c_ext = 0, 0, 0
                b_x0_ext, b_a_ext, b_c_ext = 0, 0, 0

            c1_ext, c2_ext, c3_ext = st.columns(3)
            with c1_ext:
                st.number_input("Xn (Channel)", value=int(c_x0_ext), disabled=True, key="ext_auto_cx0")
                st.number_input("Xn (Bit)", value=int(b_x0_ext), disabled=True, key="ext_auto_bx0")
            with c2_ext:
                st.number_input("A (Channel)", value=int(c_a_ext), disabled=True, key="ext_auto_ca")
                st.number_input("A (Bit)", value=int(b_a_ext), disabled=True, key="ext_auto_ba")
            with c3_ext:
                st.number_input("C (Channel)", value=int(c_c_ext), disabled=True, key="ext_auto_cc")
                st.number_input("C (Bit)", value=int(b_c_ext), disabled=True, key="ext_auto_bc")
            st.markdown("</div>", unsafe_allow_html=True)
            
            custom_lcg_params_ext = {"c_x0": c_x0_ext, "c_a": c_a_ext, "c_c": c_c_ext, "b_x0": b_x0_ext, "b_a": b_a_ext, "b_c": b_c_ext}

        # JIKA MENGKLIK OPSI 3 (Pilih Tombol Manual)
        elif mode_param_ext == "🛠️ Manual Statis (Pilih Sendiri)":
            st.markdown("""<div style="background-color: #0c1f3f; padding: 15px; border-radius: 8px; border: 1px dashed #5ad1ff; margin-bottom: 15px;">""", unsafe_allow_html=True)
            mc1_ext, mc2_ext = st.columns([1.5, 1])
            with mc1_ext:
                manual_channel_ext = st.radio("Saluran Warna:", ["R", "G", "B", "RG", "RB", "GB", "RGB"], horizontal=True, key="ext_chan")
            with mc2_ext:
                manual_bit_ext = st.radio("Depth:", [1, 2, 3], format_func=lambda x: f"{x} Bit", horizontal=True, key="ext_bit")
            st.markdown("</div>", unsafe_allow_html=True)
        # ==========================================

        extract_btn = st.button("🔍 Proses Extraction", use_container_width=True)

    # ---- Proses Extraction ----
    if extract_btn:
        if stego_array is None:
            st.error("Silakan unggah stego image yang valid terlebih dahulu.")
        elif not password_extract:
            st.error("Password tidak boleh kosong.")
        else:
            with st.spinner("Membaca header & menelusuri rute LCG yang sama..."):
                # Konversi pilihan UI ke mode string pendukung fungsi inti
                if mode_param_ext == "🔄 Otomatis (Belakang Layar)":
                    extract_mode = "Otomatis"
                elif mode_param_ext == "🔢 Parameter LCG (Auto)":
                    extract_mode = "Input LCG"
                else:
                    extract_mode = "Manual Statis"

                # Tahap 1: baca 32-bit header (panjang ciphertext dalam bit)
                header_bits, move_name = extract_message(
                    stego_array, password_extract, HEADER_BITS,
                    mode=extract_mode,
                    manual_chan=manual_channel_ext,
                    manual_bit=manual_bit_ext,
                    custom_lcg=custom_lcg_params_ext
                )
                try:
                    cipher_bit_len = int(header_bits, 2)
                except ValueError:
                    cipher_bit_len = -1

            # Validasi kewajaran panjang header agar tidak crash
            max_possible_bits = stego_array.shape[0] * stego_array.shape[1] * 3 * 3
            if cipher_bit_len <= 0 or cipher_bit_len > max_possible_bits:
                st.error(
                    "❌ Ekstraksi GAGAL: Password salah, konfigurasi parameter tidak cocok, "
                    "atau gambar bukan hasil Stego Triple-A yang valid (header panjang pesan tidak terbaca)."
                )
            else:
                with st.spinner("Mengekstrak ciphertext & mendekripsi AES-256..."):
                    total_bits_needed = HEADER_BITS + cipher_bit_len
                    full_bits, move_name = extract_message(
                        stego_array, password_extract, total_bits_needed,
                        mode=extract_mode,
                        manual_chan=manual_channel_ext,
                        manual_bit=manual_bit_ext,
                        custom_lcg=custom_lcg_params_ext
                    )
                    cipher_bits_only = full_bits[HEADER_BITS:]
                    ciphertext_blob = bits_to_bytes(cipher_bits_only)

                    try:
                        plaintext = aes_decrypt(ciphertext_blob, password_extract)
                        success = True
                    except Exception:
                        plaintext = ""
                        success = False

                if not success:
                    st.error(
                        "❌ Dekripsi AES GAGAL: Password yang dimasukkan kemungkinan salah, "
                        "atau citra telah mengalami modifikasi/kompresi data piksel."
                    )
                else:
                    st.success("✅ Ekstraksi & dekripsi berhasil!")
                    
                    # Fitur Metadata Dashboard
                    st.markdown("### 📊 Extraction Metadata")
                    em1, em2, em3 = st.columns(3)
                    em1.metric("Pola Pergerakan LCG", move_name)
                    em2.metric("Total Bit Diekstrak", f"{len(full_bits)} bit")
                    em3.metric("Ukuran Plaintext", f"{len(plaintext)} karakter")

                    # Fitur Raw Ciphertext Hex Dump
                    st.markdown("### 💻 Raw Ciphertext (Hex Dump)")
                    st.caption("Data mentah terenkripsi (AES-256) yang diangkat dari LSB sebelum didekripsi.")
                    hex_dump = " ".join([f"{b:02X}" for b in ciphertext_blob[:64]])
                    if len(ciphertext_blob) > 64:
                        hex_dump += " ... [TRUNCATED]"
                    st.code(hex_dump, language="text")

                    # Fitur Penampilan Isi Teks Rahasia
                    st.markdown("### 📜 Pesan / Isi Dokumen yang Ditemukan")
                    st.text_area("Plaintext", value=plaintext, height=250)
                    st.metric("Panjang Pesan", f"{len(plaintext)} karakter")

                    # Fitur Unduh File .TXT
                    st.download_button(
                        label="📥 Download Pesan (.txt)",
                        data=plaintext,
                        file_name="extracted_secret_message.txt",
                        mime="text/plain",
                        use_container_width=True,
                    )

st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #8fc7ff; font-size: 14px; padding-bottom: 20px;'>
        🔐 <b>Triple-A Steganography Suite</b> — AES-256 · LCG · Modified LSB Multi-Channel · PSNR/MSE Analyzer<br>
        Nama: <b>Teresia Hana Agatha Siburian (231112494)</b><br>
        Kelas: <b>IF-B</b><br>
        Tugas Kriptografi & Keamanan Informasi IF2117
    </div>
    """, 
    unsafe_allow_html=True
)