"""Onion helpers: v3 address validation, service keys, SOCKS5 client."""
import base64
import socket
import struct
import threading

import pytest

from redoubt import onion

DDG = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad"   # a real v3 address (checksum valid)


def test_real_address_is_accepted_with_or_without_suffix_and_normalized():
    assert onion.normalize_onion_address(DDG + ".onion") == DDG + ".onion"
    assert onion.normalize_onion_address("  " + DDG.upper() + "  ") == DDG + ".onion"


@pytest.mark.parametrize("bad", [
    "", "abc.onion", "expyuzz4wqqyqhjn.onion",                 # empty, short, v2
    "www." + DDG + ".onion", DDG + ".onion:60717", "http://" + DDG + ".onion",
    DDG[:-1] + "!.onion", DDG[:-3] + "aaa.onion",              # bad char / bad checksum+version
    "1" + DDG[1:] + ".onion",                                  # '1' is not base32
])
def test_invalid_addresses_are_rejected(bad):
    with pytest.raises(ValueError):
        onion.parse_onion_address(bad)


def test_non_string_is_rejected():
    with pytest.raises(ValueError):
        onion.parse_onion_address(None)


def test_checksum_typo_is_detected():
    chars = list(DDG)
    chars[10] = "b" if chars[10] != "b" else "c"
    with pytest.raises(ValueError, match="checksum"):
        onion.parse_onion_address("".join(chars))


def test_is_onion_address_is_a_cheap_classifier():
    assert onion.is_onion_address("x.onion") and onion.is_onion_address(" X.ONION ")
    assert not onion.is_onion_address("192.168.1.1") and not onion.is_onion_address(None)


def test_seed_derives_a_valid_address_that_parses_back_to_the_same_key():
    seed = onion.generate_seed()
    addr = onion.address_from_seed(seed)
    assert addr.endswith(".onion") and len(addr) == 56 + 6
    assert onion.parse_onion_address(addr) == onion.pubkey_from_seed(seed)
    assert onion.address_from_seed(seed) == addr                 # deterministic
    assert onion.address_from_seed(onion.generate_seed()) != addr


def test_expanded_key_is_clamped_and_matches_rfc8032_scalar():
    seed = bytes(range(32))
    key = onion.expanded_secret_key(seed)
    assert len(key) == 64 and key[0] & 7 == 0 and key[31] & 0x80 == 0 and key[31] & 0x40
    assert onion.add_onion_key_arg(seed) == "ED25519-V3:" + base64.b64encode(key).decode()


def test_wrong_seed_length_is_rejected():
    for fn in (onion.pubkey_from_seed, onion.expanded_secret_key):
        with pytest.raises(ValueError):
            fn(b"short")


## ---------------------------------------------------------------- SOCKS5 client against a fake proxy

def fake_socks(reply_code=0x00, greeting_ok=True, capture=None, serve=None):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)

    def run():
        c, _ = srv.accept()
        with c:
            hello = c.recv(3)
            if capture is not None:
                capture["hello"] = hello
            c.sendall(bytes([5, 0 if greeting_ok else 0xFF]))
            if not greeting_ok:
                return
            head = c.recv(5)
            name = b""
            while len(name) < head[4]:
                name += c.recv(head[4] - len(name))
            port = struct.unpack(">H", c.recv(2))[0]
            if capture is not None:
                capture.update(atyp=head[3], cmd=head[1], name=name.decode(), port=port)
            c.sendall(bytes([5, reply_code, 0, 1]) + bytes(4) + bytes(2))
            if serve:
                serve(c)
    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()


def test_socks5_sends_the_hostname_unresolved_and_returns_a_usable_socket():
    cap = {}
    srv, addr = fake_socks(capture=cap, serve=lambda c: c.sendall(b"pong"))
    s = onion.socks5_connect(addr, DDG + ".onion", 60717, timeout=5)
    try:
        assert s.recv(4) == b"pong" and s.gettimeout() is None
    finally:
        s.close(); srv.close()
    assert cap["hello"] == b"\x05\x01\x00"                      # no-auth only
    assert cap["atyp"] == 3 and cap["cmd"] == 1                 # DOMAINNAME, CONNECT: never resolved locally
    assert cap["name"] == DDG + ".onion" and cap["port"] == 60717


@pytest.mark.parametrize("code, offline", [(0xF0, True), (0xF2, True), (0x05, True), (0xF3, False), (0x01, False), (0xF6, False)])
def test_socks5_error_codes_are_reported_and_classified(code, offline):
    srv, addr = fake_socks(reply_code=code)
    try:
        with pytest.raises(onion.SocksError) as e:
            onion.socks5_connect(addr, DDG + ".onion", 60717, timeout=5)
    finally:
        srv.close()
    assert e.value.code == code and e.value.peer_offline is offline


def test_socks5_proxy_refusing_no_auth_fails():
    srv, addr = fake_socks(greeting_ok=False)
    try:
        with pytest.raises(onion.SocksError):
            onion.socks5_connect(addr, "x.onion", 1, timeout=5)
    finally:
        srv.close()


def test_socks5_proxy_unreachable_raises_oserror():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    with pytest.raises(OSError):
        onion.socks5_connect(("127.0.0.1", port), "x.onion", 1, timeout=2)


def test_socks5_rejects_bad_arguments():
    with pytest.raises(ValueError):
        onion.socks5_connect(("127.0.0.1", 1), "x" * 300, 1, timeout=1)
    with pytest.raises(ValueError):
        onion.socks5_connect(("127.0.0.1", 1), "x.onion", 0, timeout=1)
