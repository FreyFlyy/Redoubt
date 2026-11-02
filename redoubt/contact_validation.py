### contact_validation.py

"""
Contact input validation for Redoubt (shared by the CLI and the UI form,
so the trust-establishing checks live in exactly one place)
"""

import ipaddress

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from . import crypto
from . import protocol as protocol_mod


def format_fingerprint(fp: str) -> str:
    """Format sha256 fingerprint into 4-char spaced blocks"""
    return " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))


def normalize_fingerprint(s: str) -> str:
    """Remove every whitespace character and lowercase (fingerprints are lowercase hex)"""
    return "".join(s.split()).lower()


def validate_new_contact(storage, ident, name, ip_input, pubkey_b64, fingerprint_input):
    """Validate the 4 fields of a new contact (Name, IP, PubKey b64, Fingerprint).

    Returns (name, ip, pubkey_b64, fingerprint) with normalized values.
    Raises ValueError with a user-presentable message on the first failed check.
    """
    name = name.strip()
    ip_input = ip_input.strip()
    pubkey_b64 = pubkey_b64.strip()
    fingerprint_input = normalize_fingerprint(fingerprint_input)

    if not name:
        raise ValueError("Name cannot be empty.")

    try:
        addr = ipaddress.ip_address(ip_input)
        if addr.version != 4 or addr.is_unspecified or addr.is_multicast:   # the listener/connector are IPv4-only (AF_INET)
            raise ValueError
        ip = str(addr)  # canonical form, so it matches the source IP seen by the listener
    except ValueError:
        raise ValueError("Not a valid peer IP address.") from None

    try:
        pubkey_raw = protocol_mod.unb64(pubkey_b64)
        if len(pubkey_raw) != 32:
            raise ValueError("wrong length")
        X25519PublicKey.from_public_bytes(pubkey_raw)
    except Exception:
        raise ValueError("Public key is not a valid X25519 key (base64 of 32 bytes).") from None

    computed_fp = crypto.fingerprint_of(pubkey_raw)
    if computed_fp != fingerprint_input:
        raise ValueError("Fingerprint does not match Public key. Always share it on a secure out-of-band channel.")

    if computed_fp == ident.fingerprint:
        raise ValueError("This is your own identity.")

    if storage.get_contact(computed_fp) is not None:
        raise ValueError("A contact with this fingerprint already exists.")

    return name, ip, pubkey_b64, computed_fp
