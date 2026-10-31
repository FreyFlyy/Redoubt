"""
End-to-end test: two real NetworkManager instances talking over localhost
(authenticated wire key -> handshake -> ratchet -> MESSAGE/MESSAGE_ACK -> outbox cleanup).
"""
import socket
import threading
import time

import pytest

from redoubt import crypto, identity as idmod, network, protocol as proto, storage as st


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for(cond, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


class Peer:
    def __init__(self, tmp_path, name):
        self.name = name
        key = crypto.generate_x25519_keypair()
        self.ident = idmod.Identity(key, bytes(range(32)))
        self.storage = st.Storage(self.ident.vault_key, str(tmp_path / f"{name}.db"))
        self.received = []
        self.acked = []
        self.net = network.NetworkManager(
            self.ident, self.storage,
            on_message=lambda fp, text, ts: self.received.append((fp, text)),
            on_ack=lambda fp, mid: self.acked.append(mid),
        )
        self.port = free_port()
        self.net.start_listener(port=self.port)

    def add_contact(self, other):
        pub_b64 = proto.b64(other.ident.public_key_raw)
        self.storage.add_contact(other.ident.fingerprint, other.name, "127.0.0.1", other.port, pub_b64)

    def close(self):
        self.net.stop()
        self.storage.conn.close()


@pytest.fixture
def peers(tmp_path, fast_kdf):
    a, b = Peer(tmp_path, "alice"), Peer(tmp_path, "bob")
    a.add_contact(b)
    b.add_contact(a)
    yield a, b
    a.close()
    b.close()


def test_message_delivery_ack_and_reply(peers):
    a, b = peers
    mid = a.net.send_text(b.ident.fingerprint, "ciao bob")
    assert wait_for(lambda: b.received), "message not delivered"
    assert b.received[0] == (a.ident.fingerprint, "ciao bob")
    assert wait_for(lambda: mid in a.acked), "ACK not received"
    assert not a.storage.has_pending(b.ident.fingerprint)  # outbox cleaned after ACK
    assert b.storage.get_history(a.ident.fingerprint)[0]["text"] == "ciao bob"

    b.net.send_text(a.ident.fingerprint, "ciao alice")
    assert wait_for(lambda: a.received)
    assert a.received[0][1] == "ciao alice"


def test_many_messages_keep_ratchet_in_sync_and_ordered(peers):
    a, b = peers
    texts = [f"msg-{i}" for i in range(15)]
    for t in texts:
        a.net.send_text(b.ident.fingerprint, t)
    assert wait_for(lambda: len(b.received) == len(texts)), f"got {len(b.received)}/{len(texts)}"
    assert sorted(t for _, t in b.received) == sorted(texts)
    assert wait_for(lambda: not a.storage.has_pending(b.ident.fingerprint))


def test_unknown_peer_is_refused(tmp_path, fast_kdf):
    a, b = Peer(tmp_path, "alice"), Peer(tmp_path, "bob")
    try:
        a.add_contact(b)  # bob does NOT know alice
        a.net.send_text(b.ident.fingerprint, "hi")
        time.sleep(2.0)
        assert b.received == []
        assert b.storage.list_contacts() == []
    finally:
        a.close()
        b.close()


def test_wrong_pinned_key_never_delivers(tmp_path, fast_kdf):
    """Alice has the WRONG public key for Bob's address: nothing may be delivered."""
    a, b, mallory = Peer(tmp_path, "alice"), Peer(tmp_path, "bob"), Peer(tmp_path, "mallory")
    try:
        b.add_contact(a)
        # alice believes "bob" at bob's port has mallory's key
        a.storage.add_contact(mallory.ident.fingerprint, "bob?", "127.0.0.1", b.port,
                              proto.b64(mallory.ident.public_key_raw))
        a.net.send_text(mallory.ident.fingerprint, "secret for mallory-key")
        time.sleep(2.0)
        assert b.received == [] and mallory.received == []
    finally:
        for x in (a, b, mallory):
            x.close()
