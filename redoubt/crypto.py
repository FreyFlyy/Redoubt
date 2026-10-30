### crypto.py

"""
Cryptography module for Redoubt
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization


## Identity

def generate_x25519_keypair() -> X25519PrivateKey:
    """Generate a Private Key"""
    return X25519PrivateKey.generate()

def private_key_to_raw(priv: X25519PrivateKey) -> bytes:
    """Transform a X25519 Private Key in bytes"""
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

def private_key_from_raw(raw: bytes) -> X25519PrivateKey:
    """Transform a X25519 Private Key from bytes"""
    return X25519PrivateKey.from_private_bytes(raw)

def public_key_to_raw(pub: X25519PublicKey) -> bytes:
    """Transform a X25519 Public Key in bytes"""
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

def public_key_from_raw(raw: bytes) -> X25519PublicKey:
    """Transform a X25519 Public Key from bytes"""
    return X25519PublicKey.from_public_bytes(raw)

def fingerprint_of(pubkey_raw: bytes) -> str:
    """Get fingerprint of a Public Key (sha256)"""
    return hashlib.sha256(pubkey_raw).hexdigest()


## Local passphrase cipher of identity and local database (containing contacts and messages)

# Argon2id parameters (anti brute-force)
ARGON2ID_TIME_COST = 3
ARGON2ID_MEMORY_COST_KIB = 262144    # =256 MiB RAM for every try, limits mass brute force attacks and slows down the process
ARGON2ID_PARALLELISM = 4

def derive_vault_key(passphrase: str, salt: bytes) -> bytes:
    """Derive vault key from selected passphrase (inserted while creating the first local identity)"""
    kdf = Argon2id(
        salt=salt, length=32,
        iterations=ARGON2ID_TIME_COST,
        lanes=ARGON2ID_PARALLELISM,
        memory_cost=ARGON2ID_MEMORY_COST_KIB,
        ad=None, secret=None,
    )
    return kdf.derive(passphrase.encode("utf-8"))

def derive_wire_key(dh_ee: bytes, term1: bytes, term2: bytes) -> bytes:
    """Derive an authenticated transport key (Noise-KK scheme) resistant to MITM attacks via static keys"""
    ikm = dh_ee + term1 + term2
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"WE WON")
    return hkdf.derive(ikm)

def vault_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Return nonce(12) || ciphertext+tag"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)

def vault_decrypt(key: bytes, blob: bytes) -> bytes:
    """Decrypt local identity and database from derived key (see `derive_vault_key`)"""
    aesgcm = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, None)


## Handshake (X25519 + Root Key + Wire Key)

def x25519_shared_secret(my_priv: X25519PrivateKey, their_pub: X25519PublicKey) -> bytes:
    """Compute X25519 shared secret (MyPriv, TheirPub)"""
    return my_priv.exchange(their_pub)

def derive_root_key(shared_secret: bytes, nonce_a: bytes, nonce_b: bytes) -> bytes:
    """Derive the application session Root Key using HKDF-SHA256, alphabetically sorting the two nonces to derive a deterministic salt"""
    ordered = sorted([nonce_a, nonce_b])
    salt = ordered[0] + ordered[1]
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"PRIVACY IS A RIGHT")
    return hkdf.derive(shared_secret)

def initial_chain_key(root_key: bytes, fingerprint: str) -> bytearray:
    """Initialize the Chain Key for a specific conversation direction using HMAC-SHA256"""
    digest = hmac.new(root_key, b"REGAIN PRIVACY" + fingerprint.encode("utf-8"), hashlib.sha256).digest()
    return bytearray(digest)


## Symmetrical Ratchet (KDF chain, Signal-like)

def ratchet_step(chain_key):
    """Advance the symmetric KDF chain key by one step (Signal-like ratchet)"""
    ck = bytes(chain_key)   # Get clean bytes
    message_key = hmac.new(ck, b"YOU CANNOT SPY US", hashlib.sha256).digest()
    next_chain_key = bytearray(hmac.new(ck, b"WE DEMAND PRIVACY", hashlib.sha256).digest())
    return message_key, next_chain_key


## AES-256-GCM with AAD on headers

def encrypt_message(message_key: bytes, plaintext: str, aad: bytes):
    """Encrypt a plaintext message using AES-256-GCM with Additional Authenticated Data (AAD)"""
    aesgcm = AESGCM(message_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return nonce, ct

def decrypt_message(message_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> str:
    """Decrypt an AES-256-GCM ciphertext and verify its authenticity and AAD"""
    aesgcm = AESGCM(message_key)
    return aesgcm.decrypt(nonce, ciphertext, aad).decode("utf-8")
