### onion.py

"""
Onion helpers for Redoubt (pure functions, no Tor process involved):
- v3 onion address validation / normalization (the only version supported: v2 was removed from Tor)
- onion service key generation and derivation of the address from it
- minimal SOCKS5 client (CONNECT with the hostname resolved by Tor, never locally)
"""

import base64
import hashlib
import os
import socket
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


## Variables

ONION_SUFFIX = ".onion"
ONION_VERSION = 3
_CHECKSUM_PREFIX = b".onion checksum"
_B32_ALPHABET = set("abcdefghijklmnopqrstuvwxyz234567")
SERVICE_ID_LEN = 56     # base32 of 35 bytes (pubkey 32 + checksum 2 + version 1)
SEED_LEN = 32

# SOCKS5 (RFC 1928) + Tor extended error codes (tor-spec / socks-extensions.txt)
SOCKS_VERSION = 5
SOCKS_ERRORS = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
    0xF0: "onion service descriptor not found (service offline or address wrong)",
    0xF1: "onion service descriptor is invalid",
    0xF2: "onion service introduction timed out",
    0xF3: "onion service rendezvous failed",
    0xF4: "onion service needs client authorization",
    0xF5: "onion service client authorization is wrong",
    0xF6: "onion address is invalid",
    0xF7: "onion service introduction failed",
}
# Replies that just mean "the peer is not reachable right now" (normal: offline peer): not worth a status bar message
SOCKS_PEER_OFFLINE = frozenset({0x04, 0x05, 0x06, 0xF0, 0xF2, 0xF7})


## Exceptions

class SocksError(OSError):
    """The SOCKS5 proxy refused or failed the CONNECT (code = SOCKS reply code, None for protocol errors)"""
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code

    @property
    def peer_offline(self) -> bool:
        return self.code in SOCKS_PEER_OFFLINE


## Address helpers

def _checksum(pubkey: bytes) -> bytes:
    return hashlib.sha3_256(_CHECKSUM_PREFIX + pubkey + bytes([ONION_VERSION])).digest()[:2]


def is_onion_address(text) -> bool:
    """Cheap check used to decide HOW to treat a string (IPv4 or onion), not whether it is valid"""
    return isinstance(text, str) and text.strip().lower().endswith(ONION_SUFFIX)


def parse_onion_address(text) -> bytes:
    """Validate a v3 onion address (with or without '.onion') and return the 32-byte service public key.
    Raises ValueError with a user-presentable message"""
    if not isinstance(text, str):
        raise ValueError("Not a valid onion address.")
    s = text.strip().lower()
    if s.endswith(ONION_SUFFIX):
        s = s[:-len(ONION_SUFFIX)]
    if "." in s or ":" in s or "/" in s:
        raise ValueError("Not a valid onion address (use the bare v3 address, without subdomain, port or scheme).")
    if len(s) == 16:
        raise ValueError("Onion v2 addresses are not supported anymore (Tor removed them). Ask for a v3 address (56 characters).")
    if len(s) != SERVICE_ID_LEN:
        raise ValueError(f"Not a valid v3 onion address (expected {SERVICE_ID_LEN} characters before '.onion', got {len(s)}).")
    if not set(s) <= _B32_ALPHABET:
        raise ValueError("Not a valid v3 onion address (only a-z and 2-7 are allowed).")

    raw = base64.b32decode(s.upper())   # 35 bytes, no padding needed (56 chars = 280 bits)
    pubkey, checksum, version = raw[:32], raw[32:34], raw[34]
    if version != ONION_VERSION:
        raise ValueError("Not a v3 onion address (wrong version byte).")
    if checksum != _checksum(pubkey):
        raise ValueError("Onion address checksum is wrong (typo?).")
    return pubkey


def normalize_onion_address(text) -> str:
    """Validated, lowercase, 'xxxxxxxx.onion' form (what is stored and shown)"""
    pubkey = parse_onion_address(text)
    return address_from_pubkey(pubkey)


def address_from_pubkey(pubkey: bytes) -> str:
    """'<56 base32 chars>.onion' from the 32-byte ed25519 public key of the service"""
    if len(pubkey) != 32:
        raise ValueError("Onion service public key must be 32 bytes.")
    raw = pubkey + _checksum(pubkey) + bytes([ONION_VERSION])
    return base64.b32encode(raw).decode("ascii").lower() + ONION_SUFFIX


## Service key helpers

def generate_seed() -> bytes:
    """New random 32-byte ed25519 seed for an onion service (the ONLY secret that identifies the address)"""
    return os.urandom(SEED_LEN)


def pubkey_from_seed(seed: bytes) -> bytes:
    if len(seed) != SEED_LEN:
        raise ValueError("Onion service seed must be 32 bytes.")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def address_from_seed(seed: bytes) -> str:
    return address_from_pubkey(pubkey_from_seed(seed))


def expanded_secret_key(seed: bytes) -> bytes:
    """64-byte 'expanded' ed25519 secret key in the format Tor expects (tor-spec rend-spec-v3: hs_ed25519_secret_key,
    control-spec ADD_ONION ED25519-V3): clamped scalar || second half of SHA-512(seed)"""
    if len(seed) != SEED_LEN:
        raise ValueError("Onion service seed must be 32 bytes.")
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def add_onion_key_arg(seed: bytes) -> str:
    """Value for ADD_ONION's key argument: 'ED25519-V3:<base64 expanded key>'"""
    return "ED25519-V3:" + base64.b64encode(expanded_secret_key(seed)).decode("ascii")


## SOCKS5 client

def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SocksError("SOCKS proxy closed the connection unexpectedly")
        buf += chunk
    return bytes(buf)


def socks5_connect(proxy, hostname: str, port: int, timeout: float, handshake_timeout=None) -> socket.socket:
    """Connect to hostname:port through a SOCKS5 proxy (Tor's SocksPort), no authentication.
    The hostname is sent as a DOMAINNAME: it is resolved by Tor (for .onion it is not resolvable at all), never by this machine.
    Returns the connected socket (timeout reset to None). Raises SocksError / OSError (the socket is closed on any failure)"""
    name = hostname.encode("ascii")
    if not (0 < len(name) < 256):
        raise ValueError("hostname must be 1-255 ASCII bytes")
    if not (0 < port < 65536):
        raise ValueError("invalid port")

    sock = socket.create_connection(proxy, timeout=timeout)    # to the local proxy: fast
    try:
        sock.settimeout(handshake_timeout or timeout)
        sock.sendall(bytes([SOCKS_VERSION, 1, 0x00]))   # 1 method offered: no authentication
        reply = _recv_exact(sock, 2)
        if reply[0] != SOCKS_VERSION or reply[1] != 0x00:
            raise SocksError("SOCKS proxy does not accept unauthenticated connections")

        sock.sendall(bytes([SOCKS_VERSION, 0x01, 0x00, 0x03, len(name)]) + name + struct.pack(">H", port))

        # The CONNECT reply only arrives when Tor has built the whole circuit to the onion service (can take tens of seconds)
        sock.settimeout(timeout)
        head = _recv_exact(sock, 4)
        if head[0] != SOCKS_VERSION:
            raise SocksError("Invalid SOCKS reply")
        rep, atyp = head[1], head[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        elif atyp == 0x03:
            _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
        else:
            raise SocksError("Invalid SOCKS address type in reply")
        if rep != 0x00:
            raise SocksError(SOCKS_ERRORS.get(rep, f"SOCKS error 0x{rep:02x}"), code=rep)

        sock.settimeout(None)
        return sock
    except BaseException:
        sock.close()
        raise
