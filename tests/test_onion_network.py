"""Onion contacts end to end: two real NetworkManagers talking through a fake Tor (a SOCKS5 proxy that forwards .onion names to loopback listeners)."""
import socket
import struct
import threading

import pytest

from redoubt import contact_validation as cv, network, onion, protocol as proto
from test_network_integration import Peer, wait_for, connect


class FakeTor:
    """SOCKS5 proxy standing in for Tor: .onion name -> local port. Unknown names get Tor's 'descriptor not found' (0xF0)"""
    def __init__(self):
        self.routes, self.requests = {}, []
        self.srv = socket.socket(); self.srv.bind(("127.0.0.1", 0)); self.srv.listen(20)
        self.addr = self.srv.getsockname()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.recv(3); c.sendall(b"\x05\x00")
            head = c.recv(5)
            name = b""
            while len(name) < head[4]:
                name += c.recv(head[4] - len(name))
            c.recv(2)
            host = name.decode()
            self.requests.append((head[3], host))
            port = self.routes.get(host)
            if port is None:
                c.sendall(bytes([5, 0xF0, 0, 1]) + bytes(6)); c.close(); return
            up = socket.create_connection(("127.0.0.1", port))
            c.sendall(bytes([5, 0, 0, 1]) + bytes(6))
            for a, b in ((c, up), (up, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()
        except OSError:
            c.close()

    @staticmethod
    def _pipe(a, b):
        try:
            while (d := a.recv(65536)):
                b.sendall(d)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self.srv.close()


def onion_addr():
    return onion.address_from_seed(onion.generate_seed())


def add_onion_contact(owner, other, address):
    pub = proto.b64(other.ident.public_key_raw)
    owner.storage.add_contact(cv.make_contact_id(other.fp, onion=True), other.name, address, network.DEFAULT_PORT, pub)


def cid_on(other):
    return cv.make_contact_id(other.fp, onion=True)


@pytest.fixture
def duo(tmp_path, fast_kdf):
    """alice and bob, both reachable through the fake Tor at their own onion addresses, each saved by the other as onion contact"""
    tor = FakeTor()
    alice, bob = Peer(tmp_path, "alice"), Peer(tmp_path, "bob")
    for p in (alice, bob):
        p.onion = onion_addr()
        tor.routes[p.onion] = p.net.start_onion_listener()
        p.net.enable_onion_dialing(tor.addr)
    add_onion_contact(alice, bob, bob.onion)
    add_onion_contact(bob, alice, alice.onion)
    yield alice, bob, tor
    for p in (alice, bob):
        p.close()
    tor.close()


def dial(a, b):
    return a.net._get_or_connect(a.storage.get_contact(cid_on(b)))


def test_onion_contact_exchanges_messages_and_everything_is_keyed_by_the_onion_contact(duo):
    alice, bob, tor = duo
    sa = dial(alice, bob)
    assert wait_for(lambda: cid_on(alice) in bob.net.sessions and bob.net.sessions[cid_on(alice)].alive)
    assert sa.contact_id == cid_on(bob) and sa.peer_fingerprint == bob.fp           # real fp kept for authentication
    assert tor.requests and tor.requests[0] == (3, bob.onion)                       # the name went to Tor unresolved
    mid = alice.net.send_text(cid_on(bob), "hello over onion")
    assert wait_for(lambda: bob.texts() == ["hello over onion"] and mid in alice.acked)
    assert bob.received[0][0] == cid_on(alice)                                      # UI callback gets the onion contact id
    assert [m["text"] for m in bob.storage.get_history(cid_on(alice))] == ["hello over onion"]
    assert bob.storage.get_history(alice.fp) == []                                  # nothing leaks into an IP chat
    bob.net.send_text(cid_on(alice), "and back")
    assert wait_for(lambda: alice.texts() == ["and back"])


def test_same_machine_as_ip_and_onion_contact_gives_two_independent_chats(duo):
    alice, bob, _ = duo
    alice.add_contact(bob); bob.add_contact(alice)                                  # now ALSO saved as classic IP contacts (same key/fp)
    assert alice.storage.get_contact(bob.fp) and alice.storage.get_contact(cid_on(bob))
    s_ip, s_on = connect(alice, bob)[0], dial(alice, bob)
    assert s_ip is not s_on and s_ip.contact_id == bob.fp and s_on.contact_id == cid_on(bob)
    assert wait_for(lambda: cid_on(alice) in bob.net.sessions and alice.fp in bob.net.sessions)
    alice.net.send_text(bob.fp, "via ip"); alice.net.send_text(cid_on(bob), "via onion")
    assert wait_for(lambda: sorted(bob.texts()) == ["via ip", "via onion"])
    assert [m["text"] for m in bob.storage.get_history(alice.fp)] == ["via ip"]
    assert [m["text"] for m in bob.storage.get_history(cid_on(alice))] == ["via onion"]
    assert {fp for fp, _ in bob.received} == {alice.fp, cid_on(alice)}
    assert s_ip.ratchet is not s_on.ratchet


def test_dialing_an_onion_contact_while_tor_is_off_fails_without_touching_the_network(duo):
    alice, bob, tor = duo
    alice.net.stop_onion()
    with pytest.raises(network.OnionUnavailable):
        dial(alice, bob)
    assert tor.requests == [] and not alice.net.onion_ready
    mid = alice.net.send_text(cid_on(bob), "queued")                                # stays in the outbox, delivered once Tor is back
    assert wait_for(lambda: any("Tor is off" in m for _, m in alice.statusbar))
    assert alice.storage.has_pending(cid_on(bob))
    alice.net.enable_onion_dialing(tor.addr)
    alice.net._flush_outbox_for(cid_on(bob))
    assert wait_for(lambda: bob.texts() == ["queued"] and mid in alice.acked)


def test_inbound_onion_from_someone_who_is_only_an_ip_contact_is_refused(tmp_path, fast_kdf):
    tor = FakeTor()
    alice, bob = Peer(tmp_path, "alice"), Peer(tmp_path, "bob")
    try:
        bob.onion = onion_addr(); tor.routes[bob.onion] = bob.net.start_onion_listener()
        alice.net.enable_onion_dialing(tor.addr)
        add_onion_contact(alice, bob, bob.onion)
        bob.add_contact(alice)                                                      # bob knows alice ONLY as an IP contact
        with pytest.raises(Exception):
            dial(alice, bob)
        assert not bob.net.sessions and wait_for(lambda: any("onion service" in m for _, m in bob.statusbar))
    finally:
        alice.close(); bob.close(); tor.close()


def test_unknown_onion_peer_is_refused(tmp_path, fast_kdf):
    tor = FakeTor()
    alice, bob, eve = Peer(tmp_path, "alice"), Peer(tmp_path, "bob"), Peer(tmp_path, "eve")
    try:
        bob.onion = onion_addr(); tor.routes[bob.onion] = bob.net.start_onion_listener()
        eve.net.enable_onion_dialing(tor.addr)
        add_onion_contact(eve, bob, bob.onion)                                      # eve dials bob, but bob never saved eve
        add_onion_contact(bob, alice, onion_addr())                                 # bob has some other onion contact
        with pytest.raises(Exception):
            dial(eve, bob)
        assert not bob.net.sessions
    finally:
        for p in (alice, bob, eve): p.close()
        tor.close()


def test_onion_listener_is_loopback_only_and_closes_with_stop_onion(tmp_path, fast_kdf):
    p = Peer(tmp_path, "p")
    try:
        port = p.net.start_onion_listener()
        assert p.net._onion_listener_sock.getsockname()[0] == "127.0.0.1" and p.net.start_onion_listener() == port
        socket.create_connection(("127.0.0.1", port), timeout=2).close()
        p.net.stop_onion()
        assert p.net.onion_local_port is None and not p.net.onion_ready
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)
    finally:
        p.close()


def test_stop_onion_ends_onion_sessions_marks_them_offline_and_keeps_ip_sessions(duo):
    alice, bob, _ = duo
    alice.add_contact(bob); bob.add_contact(alice)
    connect(alice, bob); dial(alice, bob)
    assert wait_for(lambda: len(bob.net.sessions) == 2)
    alice.net.stop_onion()
    assert wait_for(lambda: (cid_on(bob), "offline") in alice.status)
    assert cid_on(bob) not in alice.net.sessions and alice.net.sessions[bob.fp].alive
    assert wait_for(lambda: cid_on(alice) not in bob.net.sessions) and bob.net.sessions[alice.fp].alive


def test_peer_offline_is_silent_but_other_socks_errors_are_reported(duo):
    alice, bob, tor = duo
    tor.routes.pop(bob.onion)                                                       # -> 0xF0 descriptor not found: just offline
    with pytest.raises(onion.SocksError):
        dial(alice, bob)
    assert not [m for _, m in alice.statusbar if "Onion connection" in m]
    alice.net._onion_socks = ("127.0.0.1", 1)                                       # nothing there: the proxy itself is down
    with pytest.raises(OSError):
        dial(alice, bob)
    assert any("SOCKS proxy" in m for _, m in alice.statusbar)


def test_presence_skips_onion_contacts_while_tor_is_off_and_throttles_retries(duo, monkeypatch):
    alice, bob, tor = duo
    net = alice.net
    assert net._onion_due(cid_on(bob)) is True and net._onion_due(cid_on(bob)) is False   # second try inside the interval
    monkeypatch.setattr(network, "ONION_RETRY_INTERVAL", 0)
    assert net._onion_due(cid_on(bob)) is True
    net.stop_onion()
    assert net._onion_due(cid_on(bob)) is False
    alice.net.broadcast_presence("online")                                          # must not raise nor dial anything
    assert tor.requests == []


def test_presence_roundtrip_over_onion_marks_both_online(duo):
    alice, bob, _ = duo
    alice.net.broadcast_presence("online")
    assert wait_for(lambda: (cid_on(bob), "online") in alice.status and (cid_on(alice), "online") in bob.status)


def test_session_tie_break_uses_real_fingerprints_for_onion_contacts(duo):
    alice, bob, _ = duo
    # both sides dial each other at once: exactly one session must survive on each side, and it must be usable
    t = threading.Thread(target=lambda: dial(bob, alice)); t.start()
    try:
        dial(alice, bob)
    except Exception:
        pass
    t.join(15)
    assert wait_for(lambda: len(alice.net.sessions) == 1 and len(bob.net.sessions) == 1)
    alice.net.send_text(cid_on(bob), "after the race")
    assert wait_for(lambda: bob.texts() == ["after the race"])
