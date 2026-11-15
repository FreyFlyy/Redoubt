### contact_validation.py

"""
Contact input validation for Redoubt (shared by the CLI and the UI form,
so the trust-establishing checks live in exactly one place)
"""

import hmac
import ipaddress

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from . import crypto
from . import onion as onion_mod
from . import protocol as protocol_mod


## Contact ids
#
# A contact is identified by a contact id (cid). For a classic IPv4 contact the cid is the fingerprint itself (so every
# contact saved before onion support keeps working untouched); for an onion contact it is the fingerprint plus a suffix.
# This lets the SAME machine (same key, same fingerprint) be saved twice, once per transport, each with its own chat,
# session, Double Ratchet state and outbox. The suffix contains "-", which never appears in a hex fingerprint, and it is
# also safe inside Textual widget ids.

ONION_CID_SUFFIX = "-onion"
ONION_NAME_PREFIX = "(On) "


def make_contact_id(fingerprint: str, onion: bool = False) -> str:
    return fingerprint + ONION_CID_SUFFIX if onion else fingerprint


def is_onion_contact_id(cid: str) -> bool:
    return isinstance(cid, str) and cid.endswith(ONION_CID_SUFFIX)


def contact_fingerprint(cid: str) -> str:
    """The real fingerprint (hash of the public key) behind a contact id"""
    return cid[:-len(ONION_CID_SUFFIX)] if is_onion_contact_id(cid) else cid


def contact_id_for(fingerprint: str, address: str) -> str:
    """Contact id of a contact reachable at `address` (IPv4 or .onion)"""
    return make_contact_id(fingerprint, onion_mod.is_onion_address(address))


def display_name(cid: str, name: str) -> str:
    """Name shown in the UI: onion contacts get the (On) prefix (it is NOT part of the stored name)"""
    return ONION_NAME_PREFIX + name if is_onion_contact_id(cid) else name


def parse_peer_address(text: str) -> str:
    """Validate a peer address: IPv4 or v3 onion. Returns the canonical form. Raises ValueError (user-presentable)"""
    text = text.strip()
    if onion_mod.is_onion_address(text):
        return onion_mod.normalize_onion_address(text)    # its own, more specific error messages
    try:
        addr = ipaddress.ip_address(text)
        if addr.version != 4 or addr.is_unspecified or addr.is_multicast:   # the listener/connector are IPv4-only (AF_INET)
            raise ValueError
        return str(addr)    # canonical form, so it matches the source IP seen by the listener
    except ValueError:
        raise ValueError("Not a valid peer address (expected an IPv4 address or a v3 .onion address).") from None


def format_fingerprint(fp: str) -> str:
    """Format sha256 fingerprint into 4-char spaced blocks"""
    return " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))


def normalize_fingerprint(s: str) -> str:
    """Remove every whitespace character and lowercase (fingerprints are lowercase hex)"""
    return "".join(s.split()).lower()


def _fingerprint_matches(computed: str, provided: str) -> bool:
    """Constant-time fingerprint comparison to avoid timing side-channels"""
    return hmac.compare_digest(computed, provided)


def validate_new_contact(storage, ident, name, ip_input, pubkey_b64, fingerprint_input):
    """Validate the 4 fields of a new contact (Name, IP or .onion address, PubKey b64, Fingerprint).

    Returns (name, address, pubkey_b64, fingerprint) with normalized values (fingerprint = the REAL one: the contact id
    to store it under is contact_id_for(fingerprint, address)).
    Raises ValueError with a user-presentable message on the first failed check.
    """
    name = name.strip()
    ip_input = ip_input.strip()
    pubkey_b64 = pubkey_b64.strip()
    fingerprint_input = normalize_fingerprint(fingerprint_input)

    if not name:
        raise ValueError("Name cannot be empty.")
    if name.lower().startswith(ONION_NAME_PREFIX.strip().lower()):
        raise ValueError('Name cannot start with "(On)": that prefix marks onion contacts.')

    ip = parse_peer_address(ip_input)   # IPv4 or onion

    try:
        pubkey_raw = protocol_mod.unb64(pubkey_b64)
        if len(pubkey_raw) != 32:
            raise ValueError("wrong length")
        X25519PublicKey.from_public_bytes(pubkey_raw)
    except Exception:
        raise ValueError("Public key is not a valid X25519 key (base64 of 32 bytes).") from None

    computed_fp = crypto.fingerprint_of(pubkey_raw)
    if not _fingerprint_matches(computed_fp, fingerprint_input):
        raise ValueError("Fingerprint does not match Public key. Always share it on a secure out-of-band channel.")

    if computed_fp == ident.fingerprint:
        raise ValueError("This is your own identity.")

    if storage.get_contact(contact_id_for(computed_fp, ip)) is not None:
        if onion_mod.is_onion_address(ip):
            raise ValueError("An onion contact with this fingerprint already exists.")
        raise ValueError("A contact with this fingerprint already exists.")

    return name, ip, pubkey_b64, computed_fp
