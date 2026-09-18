### protocol.py

"""
Protocol module for Redoubt
"""

import base64
import json
import secrets
import socket
import struct
import time
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


## Variables

VALID_TYPES = {"HELLO", "HELLO_ACK", "MESSAGE", "MESSAGE_ACK", "PRESENCE", "PRESENCE_ACK", "CLOSE"}
WIRE_NONCE_SIZE = 12  # nonce AES-GCM standard (96 bit)
PACKET_PADDING_BLOCK = 4096 # static padding for every message
MAX_FRAME_SIZE = WIRE_NONCE_SIZE + PACKET_PADDING_BLOCK + 16    # max frame size (4096 padded ciphertext + 12 nonce + 16 tag)
MAX_MESSAGE_BYTES = 2500  # max plaintext bytes per message (keeps padded packet within PACKET_PADDING_BLOCK, avoids a 2nd PADMÉ bracket); UI should warn/block past this
MAX_CHAIN_SKIP = 200  # max consecutive lost/dropped messages tolerated before killing the session (fast-forward DoS guard)


## Exceptions

class InvalidPacket(Exception):
    """The packet format is invalid"""
    pass


## Helpers

def b64(data: bytes) -> str:
    """Return a base64 string from raw bytes"""
    return base64.b64encode(data).decode("ascii")


def unb64(s: str) -> bytes:
    """Return raw bytes from a base64 string"""
    return base64.b64decode(s.encode("ascii"))


def new_message_id() -> str:
    """Create a new UUID4 random ID for message identification"""
    return str(uuid.uuid4())


def now_ms() -> int:
    """Returns timestamp ms"""
    return int(time.time() * 1000)


## Packet construction

def build_hello(msg_type, identity_pub_raw, fingerprint, session_nonce, name, listen_port):
    """Build HELLO/HELLO_ACK packets"""
    return {
        "type": msg_type,
        "identity_pub": b64(identity_pub_raw),
        "fingerprint": fingerprint,
        "session_nonce": b64(session_nonce),
        "name": name,
        "listen_port": listen_port,
    }

def build_presence(msg_type, sender_fp, status):
    """Build PRESENCE/PRESENCE_ACK packets"""
    return {
        "type": msg_type,
        "sender": sender_fp,
        "status": status,
        "timestamp": now_ms(),
    }

def build_message(msg_id, sender_fp, timestamp, nonce, ciphertext, chain_index):
    """Build MESSAGE packets"""
    return {
        "type": "MESSAGE",
        "id": msg_id,
        "sender": sender_fp,
        "timestamp": timestamp,
        "chain_index": chain_index,
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
    }

def build_message_ack(msg_id, sender_fp):
    """Build MESSAGE_ACK packets"""
    return {
        "type": "MESSAGE_ACK",
        "id": msg_id,
        "sender": sender_fp
    }

def build_close(sender_fp):
    """Build CLOSE packets"""
    return {
        "type": "CLOSE",
        "sender": sender_fp
    }


## Padding

def _padding_string(n: int) -> str:
    """Returns a JSON-safe string of length n to use as padding"""
    if n <= 0:
        return ""
    return secrets.token_hex((n + 1) // 2)[:n]

def add_padding(packet: dict) -> dict:
    """Add fixed padding to every message"""
    padded = dict(packet)
    padded["padding"] = ""

    base_len = len(json.dumps(padded, separators=(",", ":")).encode("utf-8"))
    target_len = PACKET_PADDING_BLOCK

    needed = target_len - base_len
    padded["padding"] = _padding_string(needed)
    return padded

def message_aad(packet: dict) -> bytes:
    """Generate AAD (Additional Authenticated Data) to ensure message integrity"""
    return f"{packet['type']}|{packet['id']}|{packet['sender']}|{packet['timestamp']}|{packet['chain_index']}".encode("utf-8")


## Validation

def _is_hex_fingerprint(s) -> bool:
    """Return if a Fingerprint is a valid SHA256"""
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s.lower())

def validate_packet(packet: dict):
    """Validates a packet before processing"""
    if not isinstance(packet, dict):
        raise InvalidPacket("Packet is not a valid JSON")

    t = packet.get("type")
    if t not in VALID_TYPES:
        raise InvalidPacket(f"Not valid packet type: {t}")

    if t in ("HELLO", "HELLO_ACK"):
        for field in ("identity_pub", "fingerprint", "session_nonce", "name", "listen_port"):
            if field not in packet:
                raise InvalidPacket(f"Missing field in {t}: {field}")
        try:    # verify base64 integrity
            unb64(packet["identity_pub"])
            unb64(packet["session_nonce"])
        except Exception:
            raise InvalidPacket(f"Invalid base64 in {t}")
        if not _is_hex_fingerprint(packet["fingerprint"]):
            raise InvalidPacket("Invalid Fingerprint (expected 64 hex SHA256 chars)")
        if not isinstance(packet["name"], str) or len(packet["name"]) > 128:
            raise InvalidPacket("Invalid name field")
        if isinstance(packet["listen_port"], bool) or not isinstance(packet["listen_port"], int) or not (0 < packet["listen_port"] < 65536):
            raise InvalidPacket("Invalid listening port")

    elif t == "MESSAGE":
        for field in ("id", "sender", "timestamp", "chain_index", "nonce", "ciphertext"):
            if field not in packet:
                raise InvalidPacket(f"Missing field in {t}: {field}")
        try:    # verify base64 integrity
            unb64(packet["nonce"])
            unb64(packet["ciphertext"])
        except Exception:
            raise InvalidPacket(f"Invalid base64 in {t}")
        if not isinstance(packet["id"], str) or len(packet["id"]) > 64:
            raise InvalidPacket("Invalid id field")
        if not _is_hex_fingerprint(packet["sender"]):
            raise InvalidPacket("Invalid sender field")
        if isinstance(packet["timestamp"], bool) or not isinstance(packet["timestamp"], int) or packet["timestamp"] < 0:
            raise InvalidPacket("Invalid timestamp field")
        if isinstance(packet["chain_index"], bool) or not isinstance(packet["chain_index"], int) or not (0 <= packet["chain_index"] < 2**31):
            raise InvalidPacket("Invalid chain_index field")

    elif t == "MESSAGE_ACK":
        for field in ("id", "sender"):
            if field not in packet:
                raise InvalidPacket(f"Missing field in {t}: {field}")
        if not isinstance(packet["id"], str) or len(packet["id"]) > 64:
            raise InvalidPacket("Invalid id field")
        if not _is_hex_fingerprint(packet["sender"]):
            raise InvalidPacket("Invalid sender field")

    elif t == "CLOSE":
        if "sender" not in packet:
            raise InvalidPacket("Missing field in CLOSE: sender")
        if not _is_hex_fingerprint(packet["sender"]):
            raise InvalidPacket("Invalid sender field")

    elif t in ("PRESENCE", "PRESENCE_ACK"):
        for field in ("sender", "status", "timestamp"):
            if field not in packet:
                raise InvalidPacket(f"Missing field in {t}: {field}")
        if not _is_hex_fingerprint(packet["sender"]):
            raise InvalidPacket("Invalid sender field")
        if packet["status"] not in ("online", "offline"):
            raise InvalidPacket(f"Presence status not valid: {packet['status']}")
        if isinstance(packet["timestamp"], bool) or not isinstance(packet["timestamp"], int) or packet["timestamp"] < 0:
            raise InvalidPacket("Invalid timestamp field")


## TCP Framing and recieving

def frame(packet: dict, wire_key: bytes) -> bytes:
    """
    Serializes a packet, encrypting in with AES-256-GCM using the wire_key and encloses it in a packet:
    [4 byte length][12 byte nonce][ciphertext+tag].
    Caller must add padding BEFORE framing
    """
    data = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    aesgcm = AESGCM(wire_key)
    nonce = secrets.token_bytes(WIRE_NONCE_SIZE)
    body = nonce + aesgcm.encrypt(nonce, data, None)
    return struct.pack(">I", len(body)) + body


def recv_exact(sock, n, timeout=None):
    """Receive exactly n bytes (no timeout by default)"""
    if timeout is not None:
        sock.settimeout(timeout)

    buf = b""
    try:
        while len(buf) < n: # receive until length
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    except TimeoutError:
        return None

    finally:
        if timeout is not None:
            sock.settimeout(None)   # reset timeout if changed

def read_packet(sock, wire_key: bytes):
    """Reads an opaque frame from the socket, decrypts it using the session wire key, and validates the resulting structure"""
    # receive length
    raw_len = recv_exact(sock, 4)
    if raw_len is None: # no length
        return (None, None)

    # Unpack packet
    length = struct.unpack(">I", raw_len)[0]
    if length > MAX_FRAME_SIZE:
        raise InvalidPacket("Packet exceeds the maximum allowed size")

    # receive body
    raw = recv_exact(sock, length, timeout=30)
    if raw is None: # no body
        return (None, None)

    if len(raw) < WIRE_NONCE_SIZE:  # naive check
        raise InvalidPacket("Frame is too short to contain a valid nonce")

    # Split and derive decryption key
    nonce, ciphertext = raw[:WIRE_NONCE_SIZE], raw[WIRE_NONCE_SIZE:]
    aesgcm = AESGCM(wire_key)

    try:
        data = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise InvalidPacket("Wire decryption failed (wrong key or manipulated packet)")

    try:
        packet = json.loads(data.decode("utf-8"))
    except Exception:
        raise InvalidPacket("invalid JSON after wire decryption")

    validate_packet(packet)

    return packet, length
