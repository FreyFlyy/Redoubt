import os

import pytest
from cryptography.exceptions import InvalidTag

from redoubt import crypto


def test_fingerprint_is_sha256_hex():
    fp = crypto.fingerprint_of(b"\x01" * 32)
    assert len(fp) == 64
    assert fp == fp.lower()
    int(fp, 16)


def test_key_serialization_roundtrip():
    priv = crypto.generate_x25519_keypair()
    priv2 = crypto.private_key_from_raw(crypto.private_key_to_raw(priv))
    assert crypto.public_key_to_raw(priv.public_key()) == crypto.public_key_to_raw(priv2.public_key())
    pub_raw = crypto.public_key_to_raw(priv.public_key())
    assert len(pub_raw) == 32
    assert crypto.public_key_to_raw(crypto.public_key_from_raw(pub_raw)) == pub_raw


def test_x25519_shared_secret_is_symmetric():
    a, b = crypto.generate_x25519_keypair(), crypto.generate_x25519_keypair()
    assert crypto.x25519_shared_secret(a, b.public_key()) == crypto.x25519_shared_secret(b, a.public_key())


def test_vault_roundtrip_and_nonce_uniqueness(vault_key):
    pt = b"secret"
    c1, c2 = crypto.vault_encrypt(vault_key, pt), crypto.vault_encrypt(vault_key, pt)
    assert c1 != c2  # random nonce
    assert crypto.vault_decrypt(vault_key, c1) == pt


def test_vault_rejects_wrong_key_and_tampering(vault_key):
    blob = crypto.vault_encrypt(vault_key, b"secret")
    with pytest.raises(InvalidTag):
        crypto.vault_decrypt(os.urandom(32), blob)
    tampered = bytearray(blob)
    tampered[-1] ^= 1
    with pytest.raises(InvalidTag):
        crypto.vault_decrypt(vault_key, bytes(tampered))


def test_derive_vault_key_properties(fast_kdf):
    salt = os.urandom(16)
    k = crypto.derive_vault_key("correct horse", salt)
    assert len(k) == 32
    assert k == crypto.derive_vault_key("correct horse", salt)
    assert k != crypto.derive_vault_key("correct horse!", salt)
    assert k != crypto.derive_vault_key("correct horse", os.urandom(16))


def test_kdf_cost_parameters_not_weakened():
    """Regression guard: fires if someone lowers the production Argon2id cost."""
    assert crypto.ARGON2ID_MEMORY_COST_KIB >= 262144
    assert crypto.ARGON2ID_TIME_COST >= 3
    assert crypto.ARGON2ID_PARALLELISM >= 1


def test_real_argon2id_parameters_run():
    """Runs ONCE with production parameters: catches OpenSSL/cryptography builds without Argon2id."""
    assert len(crypto.derive_vault_key("passphrase", os.urandom(16))) == 32


def test_root_key_independent_of_nonce_order():
    secret = os.urandom(32)
    n1, n2 = os.urandom(16), os.urandom(16)
    assert crypto.derive_root_key(secret, n1, n2) == crypto.derive_root_key(secret, n2, n1)
    assert crypto.derive_root_key(secret, n1, n2) != crypto.derive_root_key(secret, n1, os.urandom(16))


def test_wire_key_binds_all_inputs():
    dh, t1, t2 = os.urandom(32), os.urandom(32), os.urandom(32)
    base = crypto.derive_wire_key(dh, t1, t2)
    assert len(base) == 32
    assert base == crypto.derive_wire_key(dh, t1, t2)
    assert base != crypto.derive_wire_key(os.urandom(32), t1, t2)
    assert base != crypto.derive_wire_key(dh, os.urandom(32), t2)
    assert base != crypto.derive_wire_key(dh, t1, os.urandom(32))


def test_initial_chain_key_is_direction_specific():
    root = os.urandom(32)
    a = crypto.initial_chain_key(root, "a" * 64)
    b = crypto.initial_chain_key(root, "b" * 64)
    assert isinstance(a, bytearray) and len(a) == 32
    assert a != b


def test_ratchet_step_properties():
    ck = bytearray(os.urandom(32))
    mk1, ck1 = crypto.ratchet_step(ck)
    mk1_again, ck1_again = crypto.ratchet_step(ck)
    assert (mk1, ck1) == (mk1_again, ck1_again)  # deterministic
    assert len(mk1) == 32 and len(ck1) == 32
    assert mk1 != bytes(ck1)  # message key must not equal next chain key
    mk2, _ = crypto.ratchet_step(ck1)
    assert mk2 != mk1


def test_message_aead_roundtrip_and_aad_binding():
    mk = os.urandom(32)
    aad = b"MESSAGE|id|sender|1|0"
    nonce, ct = crypto.encrypt_message(mk, "ciao àèì 🔐", aad)
    assert crypto.decrypt_message(mk, nonce, ct, aad) == "ciao àèì 🔐"
    with pytest.raises(InvalidTag):
        crypto.decrypt_message(mk, nonce, ct, b"MESSAGE|id|sender|1|1")  # header changed
    with pytest.raises(InvalidTag):
        crypto.decrypt_message(os.urandom(32), nonce, ct, aad)
