import json
import os
import socket
import struct

import pytest

from redoubt import protocol as p

FP = "a" * 64
DH = b"d" * 32     # raw ratchet public key


@pytest.fixture
def sockpair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def valid_packets():
    return [
        p.build_hello("HELLO", b"x" * 32, FP, b"n" * 16, "bob", 60717),
        p.build_hello("HELLO_ACK", b"x" * 32, FP, b"n" * 16, "bob", 60717),
        p.build_message("id-1", FP, 1, b"n" * 12, b"c" * 32, 0, DH, 0),
        p.build_message_ack("id-1", FP),
        p.build_presence("PRESENCE", FP, "online"),
        p.build_presence("PRESENCE_ACK", FP, "offline"),
        p.build_close(FP),
    ]


def test_base64_roundtrip():
    raw = os.urandom(40)
    assert p.unb64(p.b64(raw)) == raw


@pytest.mark.parametrize("packet", valid_packets(), ids=lambda x: x["type"])
def test_valid_packets_pass_validation(packet):
    p.validate_packet(packet)


def _msg(**over):
    base = p.build_message("id-1", FP, 1, b"n" * 12, b"c" * 32, 0, DH, 0)
    base.update(over)
    return base


@pytest.mark.parametrize("packet", [
    "not a dict",
    {"type": "NOPE"},
    {},
    _msg(timestamp=True),
    _msg(timestamp=-1),
    _msg(chain_index=2**31),
    _msg(chain_index=-1),
    _msg(chain_index=True),
    _msg(sender="zz" * 32),
    _msg(sender="a" * 63),
    _msg(id="x" * 65),
    _msg(nonce="***not-b64***"),
    _msg(dh="***not-b64***"),
    _msg(dh=p.b64(b"d" * 31)),          # ratchet key too short
    _msg(dh=p.b64(b"d" * 33)),          # ratchet key too long
    _msg(dh=p.b64(b"")),
    _msg(pn=-1),
    _msg(pn=2**31),
    _msg(pn=True),
    _msg(pn="3"),
    _msg(pn=1.5),
    _msg(chain_index="0"),
    _msg(chain_index=1.0),
    p.build_hello("HELLO", b"x" * 32, FP, b"n" * 16, "b" * 129, 60717),
    p.build_hello("HELLO", b"x" * 32, FP, b"n" * 16, "bob", 0),
    p.build_hello("HELLO", b"x" * 32, FP, b"n" * 16, "bob", 65536),
    p.build_hello("HELLO", b"x" * 32, FP, b"n" * 16, "bob", True),
    p.build_presence("PRESENCE", FP, "away"),
    {"type": "MESSAGE_ACK", "id": "x"},
    {"type": "CLOSE"},
])
def test_invalid_packets_rejected(packet):
    with pytest.raises(p.InvalidPacket):
        p.validate_packet(packet)


@pytest.mark.parametrize("field", ["id", "sender", "timestamp", "chain_index", "dh", "pn", "nonce", "ciphertext"])
def test_missing_message_field_rejected(field):
    pkt = _msg()
    del pkt[field]
    with pytest.raises(p.InvalidPacket):
        p.validate_packet(pkt)


@pytest.mark.parametrize("kind", ["HELLO", "HELLO_ACK"])
@pytest.mark.parametrize("field", ["identity_pub", "fingerprint", "session_nonce", "name", "listen_port"])
def test_missing_hello_field_rejected(kind, field):
    pkt = p.build_hello(kind, b"x" * 32, FP, b"n" * 16, "bob", 60717)
    del pkt[field]
    with pytest.raises(p.InvalidPacket):
        p.validate_packet(pkt)


@pytest.mark.parametrize("kind", ["PRESENCE", "PRESENCE_ACK"])
@pytest.mark.parametrize("field", ["sender", "status", "timestamp"])
def test_missing_presence_field_rejected(kind, field):
    pkt = p.build_presence(kind, FP, "online")
    del pkt[field]
    with pytest.raises(p.InvalidPacket):
        p.validate_packet(pkt)


def test_presence_timestamp_and_sender_validated():
    for bad in (dict(timestamp=-1), dict(timestamp=True), dict(timestamp="1"), dict(sender="g" * 64)):
        pkt = p.build_presence("PRESENCE", FP, "online")
        pkt.update(bad)
        with pytest.raises(p.InvalidPacket):
            p.validate_packet(pkt)


def test_build_message_encodes_ratchet_header():
    pkt = p.build_message("id-1", FP, 5, b"n" * 12, b"c" * 32, 7, DH, 3)
    assert pkt["chain_index"] == 7 and pkt["pn"] == 3
    assert p.unb64(pkt["dh"]) == DH


def test_message_aad_covers_header_fields():
    pkt = _msg()
    aad = p.message_aad(pkt)
    assert aad == f"MESSAGE|id-1|{FP}|1|0|{p.b64(DH)}|0".encode()
    assert p.message_aad(_msg(chain_index=1)) != aad
    assert p.message_aad(_msg(timestamp=2)) != aad


@pytest.mark.parametrize("over", [
    dict(id="id-2"), dict(sender="b" * 64), dict(timestamp=2), dict(chain_index=1),
    dict(dh=p.b64(b"e" * 32)), dict(pn=1),
])
def test_message_aad_binds_every_header_field(over):
    """Tampering with ANY header field (incl. the ratchet key and pn) must change the AAD -> AEAD failure"""
    assert p.message_aad(_msg(**over)) != p.message_aad(_msg())


def test_message_aad_ignores_unauthenticated_fields():
    """nonce/ciphertext/padding are not part of the AAD (they are covered by the AEAD itself)"""
    base = p.message_aad(_msg())
    assert p.message_aad(_msg(padding="zzz")) == base
    assert p.message_aad(_msg(nonce=p.b64(b"q" * 12))) == base


@pytest.mark.parametrize("packet", valid_packets(), ids=lambda x: x["type"])
def test_padding_is_exactly_one_block(packet):
    padded = p.add_padding(packet)
    assert len(json.dumps(padded, separators=(",", ":")).encode()) == p.PACKET_PADDING_BLOCK


def test_max_size_message_still_fits_padding_block():
    ct = os.urandom(p.MAX_MESSAGE_BYTES + 16)
    packet = p.build_message("a" * 36, FP, 2**41, os.urandom(12), ct, 2**31 - 1, os.urandom(32), 2**31 - 1)
    padded = p.add_padding(packet)
    assert len(json.dumps(padded, separators=(",", ":")).encode()) == p.PACKET_PADDING_BLOCK


def test_all_frames_have_identical_wire_size():
    key = os.urandom(32)
    sizes = {len(p.frame(p.add_padding(pkt), key)) for pkt in valid_packets()}
    assert len(sizes) == 1
    assert sizes.pop() == 4 + p.MAX_FRAME_SIZE


def test_frame_roundtrip(sockpair):
    a, b = sockpair
    key = os.urandom(32)
    pkt = p.add_padding(p.build_message_ack("id-9", FP))
    a.sendall(p.frame(pkt, key))
    got, length = p.read_packet(b, key)
    assert got["type"] == "MESSAGE_ACK" and got["id"] == "id-9"
    assert length == p.MAX_FRAME_SIZE


def test_wrong_wire_key_rejected(sockpair):
    a, b = sockpair
    a.sendall(p.frame(p.add_padding(p.build_close(FP)), os.urandom(32)))
    with pytest.raises(p.InvalidPacket):
        p.read_packet(b, os.urandom(32))


def test_tampered_frame_rejected(sockpair):
    a, b = sockpair
    key = os.urandom(32)
    data = bytearray(p.frame(p.add_padding(p.build_close(FP)), key))
    data[-1] ^= 1
    a.sendall(bytes(data))
    with pytest.raises(p.InvalidPacket):
        p.read_packet(b, key)


def test_oversized_frame_rejected_before_reading_body(sockpair):
    a, b = sockpair
    a.sendall(struct.pack(">I", p.MAX_FRAME_SIZE + 1))
    with pytest.raises(p.InvalidPacket):
        p.read_packet(b, os.urandom(32))


def test_too_short_frame_rejected(sockpair):
    a, b = sockpair
    a.sendall(struct.pack(">I", 5) + b"12345")
    with pytest.raises(p.InvalidPacket):
        p.read_packet(b, os.urandom(32))


def test_closed_peer_returns_none(sockpair):
    a, b = sockpair
    a.close()
    assert p.read_packet(b, os.urandom(32)) == (None, None)


def test_valid_ciphertext_with_invalid_structure_rejected(sockpair):
    a, b = sockpair
    key = os.urandom(32)
    a.sendall(p.frame({"type": "MESSAGE"}, key))  # authentic but malformed
    with pytest.raises(p.InvalidPacket):
        p.read_packet(b, key)


# ---- padding / framing: additional edge cases ----

def test_padding_is_random_and_hex():
    a, b = p.add_padding(p.build_close(FP)), p.add_padding(p.build_close(FP))
    assert a["padding"] != b["padding"]
    int(a["padding"], 16)


def test_padding_does_not_mutate_input():
    pkt = p.build_close(FP)
    p.add_padding(pkt)
    assert "padding" not in pkt


def test_padding_string_edge_sizes():
    assert p._padding_string(0) == "" and p._padding_string(-5) == ""
    for n in (1, 2, 3, 100, 1001):
        assert len(p._padding_string(n)) == n


def test_message_ids_and_timestamps():
    assert p.new_message_id() != p.new_message_id()
    assert len(p.new_message_id()) <= 64
    t1 = p.now_ms()
    assert isinstance(t1, int) and p.now_ms() >= t1


def test_recv_exact_returns_none_on_eof_and_resets_timeout(sockpair):
    a, b = sockpair
    a.sendall(b"abc")
    a.close()
    assert p.recv_exact(b, 10, timeout=1) is None       # EOF before n bytes
    assert b.gettimeout() is None                        # timeout restored


def test_recv_exact_returns_none_on_timeout(sockpair):
    _a, b = sockpair
    assert p.recv_exact(b, 4, timeout=0.2) is None
    assert b.gettimeout() is None


def test_body_timeout_returns_none(sockpair, monkeypatch):
    """Length announced, body never arrives -> (None, None) instead of hanging forever"""
    a, b = sockpair
    a.sendall(struct.pack(">I", 100))
    real = p.recv_exact
    monkeypatch.setattr(p, "recv_exact", lambda s, n, timeout=None: real(s, n, timeout=0.2 if timeout else None))
    assert p.read_packet(b, os.urandom(32)) == (None, None)


def test_non_json_after_valid_decryption_rejected(sockpair):
    a, b = sockpair
    key = os.urandom(32)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    body = nonce + AESGCM(key).encrypt(nonce, b"\xff\xfe not json", None)
    a.sendall(struct.pack(">I", len(body)) + body)
    with pytest.raises(p.InvalidPacket):
        p.read_packet(b, key)


def test_wire_nonce_is_fresh_per_frame():
    key = os.urandom(32)
    pkt = p.add_padding(p.build_close(FP))
    n1, n2 = p.frame(pkt, key)[4:16], p.frame(pkt, key)[4:16]
    assert n1 != n2


def test_message_packet_with_max_plaintext_fits_one_frame():
    """Whole-pipeline version of the size guarantee: real AEAD ciphertext of MAX_MESSAGE_BYTES, real ratchet header"""
    from redoubt import crypto
    mk = os.urandom(32)
    text = "x" * p.MAX_MESSAGE_BYTES
    nonce, ct = crypto.encrypt_message(mk, text, b"aad")
    pkt = p.build_message(p.new_message_id(), FP, p.now_ms(), nonce, ct, 2**31 - 1, os.urandom(32), 2**31 - 1)
    wire = p.frame(p.add_padding(pkt), os.urandom(32))
    assert len(wire) == 4 + p.MAX_FRAME_SIZE
