import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF", 16)

G = 2

def generate_dh_keypair():
    private_key = int.from_bytes(os.urandom(32), "big") % (P - 3) + 2
    public_key  = pow(G, private_key, P)
    return private_key, public_key

def compute_shared_secret(their_public_key, my_private_key):
    return pow(their_public_key, my_private_key, P)

def derive_aes_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).digest()

def encrypt_file(file_bytes, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(bytes(16)))
    return cipher.encryptor().update(file_bytes)

def decrypt_file(encrypted_bytes, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(bytes(16)))
    return cipher.decryptor().update(encrypted_bytes)

def save_private_key(private_key, public_key, username, password, key_dir):
    os.makedirs(key_dir, exist_ok=True)

    data = json.dumps({
        "private_key": str(private_key),
        "public_key":  str(public_key)
    }).encode()

    aes_key   = hashlib.sha256(password.encode()).digest()
    encrypted = Cipher(algorithms.AES(aes_key), modes.CTR(bytes(16))).encryptor().update(data)

    with open(os.path.join(key_dir, f"{username}.key"), "wb") as f:
        f.write(encrypted)

def load_private_key(username, password, key_dir):
    key_file = os.path.join(key_dir, f"{username}.key")

    if not os.path.exists(key_file):
        raise FileNotFoundError(f"No key file found for '{username}'")

    with open(key_file, "rb") as f:
        encrypted = f.read()

    try:
        aes_key   = hashlib.sha256(password.encode()).digest()
        decrypted = Cipher(algorithms.AES(aes_key), modes.CTR(bytes(16))).decryptor().update(encrypted)
        data      = json.loads(decrypted.decode())
    except Exception:
        raise ValueError("Wrong password — cannot open key file")

    return int(data["private_key"]), int(data["public_key"])


def has_local_keys(username, key_dir):
    return os.path.exists(os.path.join(key_dir, f"{username}.key"))


def format_pubkey_short(public_key):
    s = str(public_key)
    return s if len(s) <= 12 else f"{s[:10]}...{s[-6:]}"
