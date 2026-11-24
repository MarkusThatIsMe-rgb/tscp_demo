
import os
import json
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import (
    x25519, ed25519
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==================================================
# 1. IDENTITY SETUP
# Simulasi identitas yang telah dipercaya oleh CA
# ==================================================

alice_identity = ed25519.Ed25519PrivateKey.generate()
bob_identity = ed25519.Ed25519PrivateKey.generate()

# Simulasi trust store: public key identitas yang dipercaya
trusted_users = {
    "Alice": alice_identity.public_key(),
    "Bob": bob_identity.public_key()
}


def raw_public_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


print("=== TOKONUSA SECURE CHAT PROTOCOL ===")
print("[1] Alice dan Bob memiliki identitas terpercaya.")


# ==================================================
# 2. EPHEMERAL KEY EXCHANGE - X25519
# ==================================================

alice_private = x25519.X25519PrivateKey.generate()
bob_private = x25519.X25519PrivateKey.generate()

alice_public = raw_public_key(alice_private.public_key())
bob_public = raw_public_key(bob_private.public_key())

nonce_a = os.urandom(16)
nonce_b = os.urandom(16)

print("[2] Alice dan Bob membuat kunci sementara X25519.")


# ==================================================
# 3. HANDSHAKE AUTHENTICATION - ED25519
# ==================================================

handshake = {
    "alice": "Alice",
    "bob": "Bob",
    "alice_ephemeral": alice_public.hex(),
    "bob_ephemeral": bob_public.hex(),
    "nonce_a": nonce_a.hex(),
    "nonce_b": nonce_b.hex(),
    "algorithm": "X25519-HKDF-SHA256-AES256GCM"
}

transcript = json.dumps(
    handshake, sort_keys=True, separators=(",", ":")
).encode()

# Kedua pihak menandatangani informasi handshake
alice_signature = alice_identity.sign(transcript)
bob_signature = bob_identity.sign(transcript)

# Alice memverifikasi identitas Bob
trusted_users["Bob"].verify(bob_signature, transcript)

# Bob memverifikasi identitas Alice
trusted_users["Alice"].verify(alice_signature, transcript)

print("[3] Tanda tangan digital berhasil diverifikasi.")


# ==================================================
# 4. SHARED SECRET - X25519
# ==================================================

alice_shared = alice_private.exchange(
    x25519.X25519PublicKey.from_public_bytes(bob_public)
)

bob_shared = bob_private.exchange(
    x25519.X25519PublicKey.from_public_bytes(alice_public)
)

assert alice_shared == bob_shared

transcript_hash = hashlib.sha256(transcript).digest()


# ==================================================
# 5. SESSION KEY DERIVATION - HKDF
# ==================================================

derived_keys = HKDF(
    algorithm=hashes.SHA256(),
    length=128,
    salt=transcript_hash,
    info=b"TokoNusa Secure Chat Protocol v1"
).derive(alice_shared)

K_AB = derived_keys[0:32]
K_BA = derived_keys[32:64]
K_finished_server = derived_keys[64:96]
K_finished_client = derived_keys[96:128]

print("[4] Shared secret berhasil dibuat.")
print("[5] HKDF berhasil menghasilkan kunci sesi.")


# ==================================================
# 6. KEY CONFIRMATION - HMAC-SHA256
# ==================================================

# Bob mengirim ServerFinished kepada Alice
server_finished = hmac.new(
    K_finished_server,
    b"ServerFinished" + transcript_hash,
    hashlib.sha256
).digest()

# Alice memverifikasi pesan Bob
expected_server = hmac.new(
    K_finished_server,
    b"ServerFinished" + transcript_hash,
    hashlib.sha256
).digest()

assert hmac.compare_digest(server_finished, expected_server)

print("[6] ServerFinished berhasil diverifikasi oleh Alice.")

# Alice mengirim ClientFinished kepada Bob
client_finished = hmac.new(
    K_finished_client,
    b"ClientFinished" + transcript_hash,
    hashlib.sha256
).digest()

# Bob memverifikasi pesan Alice
expected_client = hmac.new(
    K_finished_client,
    b"ClientFinished" + transcript_hash,
    hashlib.sha256
).digest()

assert hmac.compare_digest(client_finished, expected_client)

print("[7] ClientFinished berhasil diverifikasi oleh Bob.")
print("    SESSION ESTABLISHED!")


# ==================================================
# 7. MESSAGE ENCRYPTION - AES-256-GCM
# ==================================================

def encrypt_message(message, key, sequence):
    nonce = os.urandom(12)

    aad = (
        transcript_hash
        + sequence.to_bytes(8, "big")
    )

    ciphertext = AESGCM(key).encrypt(
        nonce,
        message.encode(),
        aad
    )

    return nonce, ciphertext, aad


def decrypt_message(nonce, ciphertext, aad, key):
    plaintext = AESGCM(key).decrypt(
        nonce,
        ciphertext,
        aad
    )

    return plaintext.decode()


# Alice mengirim pesan kepada Bob
message = "Halo Bob, ini pesan rahasia dari Alice!"

nonce, ciphertext, aad = encrypt_message(
    message, K_AB, 1
)

print("\n=== ALICE -> BOB ===")
print("Pesan asli :", message)
print("Ciphertext :", ciphertext.hex())

received_message = decrypt_message(
    nonce, ciphertext, aad, K_AB
)

print("Pesan Bob  :", received_message)


# Bob membalas Alice
reply = "Halo Alice, pesanmu berhasil saya terima!"

nonce_reply, ciphertext_reply, aad_reply = encrypt_message(
    reply, K_BA, 1
)

print("\n=== BOB -> ALICE ===")
print("Ciphertext :", ciphertext_reply.hex())

received_reply = decrypt_message(
    nonce_reply, ciphertext_reply, aad_reply, K_BA
)

print("Pesan Alice:", received_reply)


# ==================================================
# 8. SESSION CLOSE
# ==================================================

print("\n=== SESSION CLOSED ===")
print("Komunikasi TSCP berhasil disimulasikan.")
