import json
import os
import socket
import struct

import pytest

from redoubt import protocol as p

FP = "a" * 64


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
        p.build_message("id-1", FP, 1, b"n" * 12, b"c" * 32, 0),
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
    base = p.build_message("id-1", FP, 1, b"n" * 12, b"c" * 32, 0)
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


def test_missing_field_rejected():
    pkt = _msg()
    del pkt["ciphertext"]
    with pytest.raises(p.InvalidPacket):
        p.validate_packet(pkt)


def test_message_aad_covers_header_fields():
    pkt = _msg()
    aad = p.message_aad(pkt)
    assert aad == f"MESSAGE|id-1|{FP}|1|0".encode()
    assert p.message_aad(_msg(chain_index=1)) != aad
    assert p.message_aad(_msg(timestamp=2)) != aad


@pytest.mark.parametrize("packet", valid_packets(), ids=lambda x: x["type"])
def test_padding_is_exactly_one_block(packet):
    padded = p.add_padding(packet)
    assert len(json.dumps(padded, separators=(",", ":")).encode()) == p.PACKET_PADDING_BLOCK


def test_max_size_message_still_fits_padding_block():
    ct = os.urandom(p.MAX_MESSAGE_BYTES + 16)
    packet = p.build_message("a" * 36, FP, 2**41, os.urandom(12), ct, 2**31 - 1)
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
