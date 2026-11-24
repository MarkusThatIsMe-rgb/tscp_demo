"""\
Checkpoint 2 - Fase 2: Build Primitive
Eksperimen avalanche effect dan collision resistance pada fungsi hash.

Eksperimen A:
- Membalik tepat satu bit pada 1.000 pesan sepanjang 32 byte.
- Mengukur Hamming distance digest SHA-256, SHA3-256, dan checksum sederhana.

Eksperimen B:
- Memvalidasi pasangan collision MD5 128 byte yang disediakan pada
  materi praktikum Minggu 6.
- Menguji pengaruh sufiks bersama dan prefiks bersama.
- Membandingkan digest MD5, SHA-256, dan SHA3-256.

Implementasi dan struktur pengujian ditulis ulang. Pasangan collision MD5
hanya digunakan sebagai data uji; program tidak mencari collision dari nol.
Kompatibel dengan Python 3.9+ dan hanya menggunakan pustaka standar.
"""

import hashlib
import random
import statistics

JUMLAH_UJI = 1_000
PANJANG_PESAN = 32
SEED_UJI = 2026


def hitung_bit_berbeda(digest_a, digest_b):
    """Menghitung Hamming distance untuk dua digest dengan panjang sama."""
    if len(digest_a) != len(digest_b):
        raise ValueError("Panjang kedua digest harus sama.")
    return sum(bin(a ^ b).count("1") for a, b in zip(digest_a, digest_b))


def balik_satu_bit(pesan, indeks_bit):
    """Mengembalikan salinan pesan dengan tepat satu bit dibalik."""
    batas = len(pesan) * 8
    if not 0 <= indeks_bit < batas:
        raise ValueError("Indeks bit berada di luar ukuran pesan.")

    hasil = bytearray(pesan)
    posisi_byte, bit_dalam_byte = divmod(indeks_bit, 8)
    hasil[posisi_byte] ^= 1 << bit_dalam_byte
    return bytes(hasil)


def checksum_sederhana(pesan):
    """Checksum 32-bit berbasis penjumlahan byte; bukan hash kriptografis."""
    nilai = sum(pesan) % (2 ** 32)
    return nilai.to_bytes(4, byteorder="big")


def jalankan_avalanche():
    print("=" * 76)
    print("EKSPERIMEN A - PENGUKURAN AVALANCHE EFFECT")
    print("=" * 76)
    print("Jumlah percobaan :", JUMLAH_UJI)
    print("Panjang pesan    :", PANJANG_PESAN, "byte")
    print("Perubahan input  : tepat satu bit pada setiap percobaan")
    print("Seed generator   :", SEED_UJI)

    rng = random.Random(SEED_UJI)
    algoritma = {
        "SHA-256": lambda data: hashlib.sha256(data).digest(),
        "SHA3-256": lambda data: hashlib.sha3_256(data).digest(),
        "Checksum32": checksum_sederhana,
    }
    catatan = {nama: [] for nama in algoritma}

    for _ in range(JUMLAH_UJI):
        pesan_awal = rng.randbytes(PANJANG_PESAN)
        bit_terpilih = rng.randrange(PANJANG_PESAN * 8)
        pesan_ubah = balik_satu_bit(pesan_awal, bit_terpilih)

        for nama, fungsi_hash in algoritma.items():
            digest_awal = fungsi_hash(pesan_awal)
            digest_ubah = fungsi_hash(pesan_ubah)
            berbeda = hitung_bit_berbeda(digest_awal, digest_ubah)
            persen = berbeda / (len(digest_awal) * 8) * 100
            catatan[nama].append(persen)

    print("\n{:<14}{:>12}{:>12}{:>12}{:>12}".format(
        "Algoritma", "Rata-rata", "Std. dev.", "Minimum", "Maksimum"))
    print("-" * 62)
    for nama, nilai in catatan.items():
        print("{:<14}{:>11.2f}%{:>11.2f}%{:>11.2f}%{:>11.2f}%".format(
            nama,
            statistics.mean(nilai),
            statistics.stdev(nilai),
            min(nilai),
            max(nilai),
        ))

    simpangan_teoretis = (256 * 0.5 * 0.5) ** 0.5
    persen_simpangan = simpangan_teoretis / 256 * 100
    print("\nAcuan teoretis untuk digest 256-bit dengan peluang perubahan 0,5:")
    print("Rata-rata bit berubah : 128 dari 256 bit (50,00%)")
    print("Simpangan baku        : {:.0f} bit ({:.3f}%)".format(
        simpangan_teoretis, persen_simpangan))
    print("Catatan: hasil empiris ini bukan bukti matematis keamanan hash.")
    return catatan


# Pasangan collision MD5 128 byte dari materi Praktikum Kriptografi Minggu 6.
# Data ini dipakai sebagai sampel untuk memvalidasi collision yang sudah diketahui.
DATA_P = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a"
    "085125e8f7cdc99fd91dbdf280373c5b"
    "960b1dd1dc417b9ce4d897f45a6555d5"
    "35739ac7f0ebfd0c3029f166d109b18f"
    "75277f7930d55ceb22e8adba79cc155c"
    "ed74cbdd5fc5d36db19b0ad835cca7e3"
)

DATA_Q = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c"
    "2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a"
    "085125e8f7cdc99fd91dbd7280373c5b"
    "960b1dd1dc417b9ce4d897f45a6555d5"
    "35739a47f0ebfd0c3029f166d109b18f"
    "75277f7930d55ceb22e8adba794c155c"
    "ed74cbdd5fc5d36db19b0a5835cca7e3"
)


def digest_hex(nama_algoritma, data):
    return hashlib.new(nama_algoritma, data).hexdigest()


def jalankan_collision():
    print("\n" + "=" * 76)
    print("EKSPERIMEN B - PENGUJIAN COLLISION RESISTANCE")
    print("=" * 76)

    if DATA_P == DATA_Q:
        raise RuntimeError("Data uji P dan Q seharusnya berbeda.")

    perbedaan = [
        (posisi, nilai_p, nilai_q, nilai_q - nilai_p)
        for posisi, (nilai_p, nilai_q) in enumerate(zip(DATA_P, DATA_Q))
        if nilai_p != nilai_q
    ]

    print("Panjang input P :", len(DATA_P), "byte")
    print("Panjang input Q :", len(DATA_Q), "byte")
    print("Input identik   :", DATA_P == DATA_Q)
    print("Jumlah byte berbeda:", len(perbedaan))
    print("\nLokasi byte yang berbeda (offset dimulai dari 0):")
    for posisi, nilai_p, nilai_q, selisih in perbedaan:
        print("  Offset {:>3}: P=0x{:02x}, Q=0x{:02x}, Q-P={:+d}".format(
            posisi, nilai_p, nilai_q, selisih))

    print("\nPerbandingan digest:")
    hasil = {}
    for nama in ("md5", "sha256", "sha3_256"):
        hash_p = digest_hex(nama, DATA_P)
        hash_q = digest_hex(nama, DATA_Q)
        hasil[nama] = (hash_p, hash_q, hash_p == hash_q)
        print("\n{}".format(nama.upper().replace("SHA256", "SHA-256").replace("SHA3_256", "SHA3-256")))
        print("  Hash P :", hash_p)
        print("  Hash Q :", hash_q)
        print("  Sama   :", hash_p == hash_q)

    print("\nUji penambahan sufiks yang sama:")
    daftar_sufiks = [
        ("kosong", b""),
        ("teks tambahan", b" Lampiran identik untuk kedua dokumen."),
        ("1000 byte X", b"X" * 1000),
    ]
    for label, sufiks in daftar_sufiks:
        sama = digest_hex("md5", DATA_P + sufiks) == digest_hex("md5", DATA_Q + sufiks)
        print("  Sufiks {:<18} ({} byte): MD5 sama = {}".format(
            label, len(sufiks), sama))

    print("\nUji penambahan prefiks yang sama:")
    daftar_prefiks = [
        ("kosong", b""),
        ("1 byte X", b"X"),
        ("header dokumen", b"Header dokumen versi 2\n"),
    ]
    for label, prefiks in daftar_prefiks:
        sama = digest_hex("md5", prefiks + DATA_P) == digest_hex("md5", prefiks + DATA_Q)
        print("  Prefiks {:<18} ({} byte): MD5 sama = {}".format(
            label, len(prefiks), sama))

    print("\nInterpretasi:")
    print("- Input P dan Q berbeda, tetapi MD5(P) = MD5(Q): collision MD5 terkonfirmasi.")
    print("- Sufiks identik mempertahankan collision pada pasangan ini.")
    print("- Prefiks yang ditambahkan mengubah kondisi awal pemrosesan; collision ini tidak bertahan.")
    print("- SHA-256 dan SHA3-256 menghasilkan digest berbeda untuk pasangan MD5 ini.")
    print("- Hasil ini tidak membuktikan SHA-256 atau SHA3-256 bebas collision.")


def main():
    jalankan_avalanche()
    jalankan_collision()


if __name__ == "__main__":
    main()
