"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""
import os
import hashlib
from argon2 import PasswordHasher
from Crypto.Cipher import AES

ph = PasswordHasher()

def store_password(pw: str) -> str:
    # FIX: argon2id, salted automatically
    return ph.hash(pw)

def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False

def login_and_migrate(stored_hash: str, pw: str) -> tuple[bool, str]:
    if stored_hash.startswith("$argon2"):
        return verify_password(stored_hash, pw), stored_hash

    if len(stored_hash) == 32:
        legacy_hash = hashlib.md5(pw.encode()).hexdigest()

        if legacy_hash == stored_hash:
            return True, store_password(pw)

    return False, stored_hash

def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # FIX: authenticated encryption (AES-GCM), random nonce, key from env/KMS
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag

def decrypt_gcm(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ct, tag)
    return data

def reset_token() -> str:
    # FIX: CSPRNG
    import secrets
    return secrets.token_urlsafe(16)

if __name__ == "__main__":
    key = bytes.fromhex(os.environ.get("ENC_KEY_HEX", os.urandom(32).hex()))
    h = store_password("password123")
    print("argon2 ok:", verify_password(h, "password123"))
    print("gcm:", encrypt_gcm(b"secret", key))
    print("token:", reset_token())

    legacy = hashlib.md5(b"password123").hexdigest()

    ok, migrated = login_and_migrate(legacy, "password123")

    print("legacy login:", ok)
    print("migrated to argon2:", migrated.startswith("$argon2"))
    print("argon2 verify:", verify_password(migrated, "password123"))
   
    print("gcm:", encrypt_gcm(b"secret", key))
    print("token:", reset_token())

    nonce, ct, tag = encrypt_gcm(b"secret message", key)

    decrypted = decrypt_gcm(nonce, ct, tag, key)
    print("decrypted:", decrypted)

    tampered = bytearray(ct)
    tampered[0] ^= 1

    try:
        decrypt_gcm(nonce, bytes(tampered), tag, key)
        print("tampered: FAIL - accepted")
    except ValueError:
        print("tampered: PASS - decryption rejected")
