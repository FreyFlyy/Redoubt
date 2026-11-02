"""
End-to-end test: two real NetworkManager instances talking over localhost
(authenticated wire key -> handshake -> ratchet -> MESSAGE/MESSAGE_ACK -> outbox cleanup).
"""
import os
import random
import socket
import threading
import time

import pytest

from redoubt import crypto, identity as idmod, network, protocol as proto, ratchet as ratchet_mod, ratelimit, storage as st


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
    def __init__(self, tmp_path, name, port=None, listen=True):
        self.name = name
        key = crypto.generate_x25519_keypair()
        self.ident = idmod.Identity(key, bytes(range(32)))
        self.storage = st.Storage(self.ident.vault_key, str(tmp_path / f"{name}.db"))
        self.received = []
        self.acked = []
        self.status = []
        self.statusbar = []
        self.net = network.NetworkManager(
            self.ident, self.storage,
            on_message=lambda fp, text, ts: self.received.append((fp, text)),
            on_ack=lambda fp, mid: self.acked.append(mid),
            on_status=lambda fp, st_: self.status.append((fp, st_)),
            on_statusbar_message=lambda fp, msg: self.statusbar.append((fp, msg)),
        )
        self.port = port or free_port()
        if listen:
            self.net.start_listener(port=self.port)

    @property
    def fp(self):
        return self.ident.fingerprint

    def texts(self):
        return [t for _, t in self.received]

    def contact_of(self, other):
        return self.storage.get_contact(other.fp)

    def add_contact(self, other):
        pub_b64 = proto.b64(other.ident.public_key_raw)
        self.storage.add_contact(other.ident.fingerprint, other.name, "127.0.0.1", other.port, pub_b64)

    def close(self):
        self.net.stop()
        try:
            self.storage.conn.close()
        except Exception:
            pass


def connect(a, b, timeout=10):
    """Open a session a -> b and wait until BOTH ends have it installed and alive. Returns (a's session, b's session)"""
    sa = a.net._get_or_connect(a.contact_of(b))
    assert wait_for(lambda: (b.net.sessions.get(a.fp) is not None and b.net.sessions[a.fp].alive), timeout)
    return sa, b.net.sessions[a.fp]


def no_sessions(*peers):
    return all(not p.net.sessions for p in peers)


def drop_session(peer, other):
    """Abruptly kill the TCP connection from `peer`'s side"""
    s = peer.net.sessions[other.fp]
    try:
        s.sock.shutdown(socket.SHUT_RDWR)   # close() alone would NOT send a FIN while another thread is blocked in recv()
    except OSError:
        pass
    s.sock.close()


def send_and_wait(src, dst, text, timeout=15):
    n = len(dst.received)
    mid = src.net.send_text(dst.fp, text)
    assert wait_for(lambda: len(dst.received) > n and dst.received[-1][1] == text, timeout), f"{text!r} not delivered"
    assert wait_for(lambda: mid in src.acked, timeout), f"{text!r} not acked"
    return mid


def lose_first_transmission(session, msg_ids):
    """Make `session` silently lose the FIRST transmission of each given message id (retransmissions pass)"""
    pending = set(msg_ids)
    original = session.send

    def lossy(packet):
        if packet.get("type") == "MESSAGE" and packet["id"] in pending:
            pending.discard(packet["id"])
            return                                              # lost on the wire
        return original(packet)

    session.send = lossy


@pytest.fixture
def fast_retransmit(monkeypatch):
    monkeypatch.setattr(network, "INITIAL_RTO", 0.3)
    monkeypatch.setattr(network, "ACK_WATCHDOG_INTERVAL", 0.1)


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


## ======================================================================= Session (no network)

def _ratchet_pair():
    a, b = crypto.generate_x25519_keypair(), crypto.generate_x25519_keypair()
    ra, rb = crypto.public_key_to_raw(a.public_key()), crypto.public_key_to_raw(b.public_key())
    root = os.urandom(32)
    return ratchet_mod.DoubleRatchet.initiator(root, a, rb), ratchet_mod.DoubleRatchet.responder(root, b, ra)


def _session(fp="a" * 64):
    sa, sb = socket.socketpair()
    key = os.urandom(32)
    return network.Session(sa, fp, _ratchet_pair()[0], key), sb, key


def test_session_initial_state():
    s, other, _ = _session()
    try:
        assert s.alive and s.srtt is None and s.current_rto() == network.INITIAL_RTO
        assert not s.seen_msg_ids
    finally:
        s.sock.close(); other.close()


def test_session_rtt_first_sample_follows_jacobson():
    s, other, _ = _session()
    try:
        s.update_rtt(0.4)
        assert s.srtt == pytest.approx(0.4) and s.rttvar == pytest.approx(0.2)
        assert s.current_rto() == pytest.approx(0.4 + 4 * 0.2)
        s.update_rtt(0.8)
        rttvar = 0.75 * 0.2 + 0.25 * abs(0.4 - 0.8)
        srtt = 0.875 * 0.4 + 0.125 * 0.8
        assert s.rttvar == pytest.approx(rttvar) and s.srtt == pytest.approx(srtt)
        assert s.current_rto() == pytest.approx(srtt + 4 * rttvar)
    finally:
        s.sock.close(); other.close()


def test_session_rto_is_clamped():
    s, other, _ = _session()
    try:
        s.update_rtt(0.0001)
        assert s.current_rto() == network.RTO_MIN
        s2, other2, _ = _session()
        s2.update_rtt(10_000)
        assert s2.current_rto() == network.RTO_MAX
        s2.sock.close(); other2.close()
    finally:
        s.sock.close(); other.close()


def test_session_send_produces_a_wire_frame_readable_with_the_wire_key():
    s, other, key = _session()
    try:
        s.send(proto.add_padding(proto.build_close("c" * 64)))
        pkt, length = proto.read_packet(other, key)
        assert pkt["type"] == "CLOSE" and length == proto.MAX_FRAME_SIZE
    finally:
        s.sock.close(); other.close()


def test_session_concurrent_sends_never_interleave_frames():
    s, other, key = _session()
    n_threads, per_thread = 8, 25
    errors = []

    def writer(tid):
        try:
            for i in range(per_thread):
                s.send(proto.add_padding(proto.build_message_ack(f"{tid}-{i}", "c" * 64)))
        except Exception as e:      # pragma: no cover
            errors.append(e)

    ts = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
    for t in ts: t.start()
    seen = set()
    for _ in range(n_threads * per_thread):
        pkt, _ = proto.read_packet(other, key)
        seen.add(pkt["id"])
    for t in ts: t.join()
    s.sock.close(); other.close()
    assert not errors and len(seen) == n_threads * per_thread


def test_session_next_send_key_advances_and_destroy_blocks_it():
    s, other, _ = _session()
    try:
        (mk0, h0), (mk1, h1) = s.next_send_key(), s.next_send_key()
        assert (h0.n, h1.n) == (0, 1) and mk0 != mk1 and h0.dh == h1.dh
        s.destroy()
        assert s.ratchet._destroyed
        with pytest.raises(ratchet_mod.RatchetError):
            s.next_send_key()
        s.destroy()     # idempotent
    finally:
        s.sock.close(); other.close()


## ======================================================================= _install_session tie-break

def _mk_session(peer_fp, sock_pair=None):
    sa, sb = sock_pair or socket.socketpair()
    return network.Session(sa, peer_fp, _ratchet_pair()[0], os.urandom(32)), sb


@pytest.fixture
def two_nodes(tmp_path, fast_kdf):
    a, b = Peer(tmp_path, "alice", listen=False), Peer(tmp_path, "bob", listen=False)
    a.add_contact(b)   # _install_session refuses sessions of contacts that are no longer in storage (revoked)
    b.add_contact(a)
    yield a, b
    a.close(); b.close()


def test_tie_break_exactly_one_side_prefers_inbound(two_nodes):
    a, b = two_nodes
    assert (a.fp < b.fp) != (b.fp < a.fp)


@pytest.mark.parametrize("old_inbound", [False, True])
def test_install_session_tie_break_keeps_the_preferred_connection(two_nodes, old_inbound):
    for me, other in (two_nodes, two_nodes[::-1]):
        me_prefers_inbound = me.fp < other.fp
        old, old_peer = _mk_session(other.fp)
        new, new_peer = _mk_session(other.fp)
        assert me.net._install_session(other.fp, old, is_inbound=old_inbound) is False
        discarded = me.net._install_session(other.fp, new, is_inbound=not old_inbound)
        new_is_inbound = not old_inbound
        if new_is_inbound == me_prefers_inbound:        # new connection wins
            assert discarded is False and me.net.sessions[other.fp] is new
            assert not old.alive and old.ratchet._destroyed and new.alive
            closer = old_peer
        else:                                           # old connection stays
            assert discarded is True and me.net.sessions[other.fp] is old
            assert not new.alive and new.ratchet._destroyed and old.alive
            closer = new_peer
        # the loser is told with a CLOSE frame
        closer.settimeout(2)
        raw = closer.recv(5000)
        assert len(raw) == 4 + proto.MAX_FRAME_SIZE
        for s_ in (old, new):
            s_.sock.close()
        old_peer.close(); new_peer.close()


@pytest.mark.parametrize("peer_fp, node_prefers_inbound", [("f" * 64, True), ("0" * 64, False)])
def test_install_session_same_direction_twice_follows_the_node_preference(two_nodes, peer_fp, node_prefers_inbound):
    """CHARACTERIZATION of current behaviour: the tie-break looks only at direction, not at age. A second INBOUND
    session replaces the first one only on the node that prefers inbound; the other node keeps the old session."""
    a, _ = two_nodes
    a.net.storage.add_contact(peer_fp, "peer", "127.0.0.1", 12345, proto.b64(crypto.public_key_to_raw(crypto.generate_x25519_keypair().public_key())))
    assert (a.fp < peer_fp) == node_prefers_inbound
    s1, p1 = _mk_session(peer_fp)
    s2, p2 = _mk_session(peer_fp)
    a.net._install_session(peer_fp, s1, is_inbound=True)
    discarded = a.net._install_session(peer_fp, s2, is_inbound=True)
    if node_prefers_inbound:
        assert discarded is False and a.net.sessions[peer_fp] is s2 and not s1.alive and s2.alive
    else:
        assert discarded is True and a.net.sessions[peer_fp] is s1 and s1.alive and not s2.alive
    for x in (s1, s2):
        x.sock.close()
    p1.close(); p2.close()


def test_install_session_replaces_a_dead_session_regardless_of_preference(two_nodes):
    a, b = two_nodes
    old, op = _mk_session(b.fp)
    a.net._install_session(b.fp, old, is_inbound=False)
    old.alive = False
    new, np_ = _mk_session(b.fp)
    for direction in (True, False):
        assert a.net._install_session(b.fp, new, is_inbound=direction) is False
        assert a.net.sessions[b.fp] is new
        a.net.sessions[b.fp] = old; old.alive = False
    for x in (old, new): x.sock.close()
    op.close(); np_.close()


def test_install_session_respects_the_global_session_cap(two_nodes):
    a, b = two_nodes
    a.net._session_cap = ratelimit.GlobalSessionCap(0)
    s, sp = _mk_session(b.fp)
    assert a.net._install_session(b.fp, s, is_inbound=True) is True
    assert b.fp not in a.net.sessions and not s.alive and s.ratchet._destroyed
    s.sock.close(); sp.close()


## ======================================================================= handshake and key schedule

@pytest.fixture
def root_spy(monkeypatch):
    calls = []
    real = crypto.derive_root_key

    def spy(ikm, na, nb):
        r = real(ikm, na, nb)
        calls.append((ikm, na, nb, r))
        return r

    monkeypatch.setattr(crypto, "derive_root_key", spy)
    return calls, real


def test_both_sides_derive_the_same_root_from_ephemeral_secrets(peers, root_spy):
    a, b = peers
    calls, real = root_spy
    connect(a, b)
    assert wait_for(lambda: len(calls) == 2)
    (ikm1, na1, nb1, root1), (ikm2, na2, nb2, root2) = calls
    assert root1 == root2 and ikm1 == ikm2 and (na1, nb1) == (na2, nb2)
    assert len(ikm1) == 96                              # dh_ee || term1 || term2

    # What the OLD design used: static-static DH + public nonces. Stealing a static key gives exactly this
    static_only = crypto.x25519_shared_secret(a.ident.private_key, b.ident.public_key)
    assert real(static_only, na1, nb1) != root1
    # ... and the static-static DH is not even part of the key material
    assert static_only not in ikm1


def test_each_session_gets_a_fresh_root(peers, root_spy):
    a, b = peers
    calls, _ = root_spy
    connect(a, b)
    assert wait_for(lambda: len(calls) == 2)
    first_root = calls[0][3]
    drop_session(a, b)
    assert wait_for(lambda: no_sessions(a, b))
    connect(a, b)
    assert wait_for(lambda: len(calls) == 4)
    assert calls[2][3] == calls[3][3] and calls[2][3] != first_root
    assert calls[2][0] != calls[0][0]                   # ephemeral keys are never reused across sessions


def test_ratchets_are_seeded_consistently_by_the_handshake(peers):
    a, b = peers
    sa, sb = connect(a, b)
    ra, rb = sa.ratchet, sb.ratchet                     # a opened the connection -> initiator
    assert ra._cks is not None and ra._ckr is None      # initiator can send at once, nothing to receive yet
    assert rb._ckr is not None and rb._cks is None      # responder can receive at once, sends after a DH step
    assert ra._dhr == rb._dhs_pub and rb._dhr == ra._dhs_pub
    assert bytes(ra._rk) == bytes(rb._rk)


def test_session_ratchet_is_destroyed_when_the_connection_ends(peers):
    a, b = peers
    sa, sb = connect(a, b)
    drop_session(a, b)
    assert wait_for(lambda: no_sessions(a, b))
    for s in (sa, sb):
        assert not s.alive and s.ratchet._destroyed
        assert all(x is None or x == bytearray(32) for x in (s.ratchet._rk, s.ratchet._cks, s.ratchet._ckr))


## ======================================================================= message flows

def test_ping_pong_many_dh_steps_and_identical_histories(peers):
    a, b = peers
    expected = []
    for i in range(12):
        send_and_wait(a, b, f"a{i}"); expected.append(f"a{i}")
        send_and_wait(b, a, f"b{i}"); expected.append(f"b{i}")
    # the sender stores its own "out" row right AFTER sending, so it can lag the ACK by a scheduler tick
    assert wait_for(lambda: len(a.storage.get_history(b.fp)) == 24 and len(b.storage.get_history(a.fp)) == 24)
    ha = [m["text"] for m in a.storage.get_history(b.fp)]
    hb = [m["text"] for m in b.storage.get_history(a.fp)]
    assert sorted(ha) == sorted(hb) == sorted(expected)
    assert not a.storage.has_pending(b.fp) and not b.storage.has_pending(a.fp)
    assert len({m["id"] for m in a.storage.get_history(b.fp)}) == 24


def test_wire_headers_progress_like_a_double_ratchet(peers, monkeypatch):
    a, b = peers
    seen = []
    real = proto.build_message

    def spy(msg_id, sender_fp, ts, nonce, ct, chain_index, dh_raw, pn):
        seen.append((sender_fp, dh_raw, pn, chain_index))
        return real(msg_id, sender_fp, ts, nonce, ct, chain_index, dh_raw, pn)

    monkeypatch.setattr(proto, "build_message", spy)
    for i in range(3):
        send_and_wait(a, b, f"a{i}")
    send_and_wait(b, a, "reply")
    send_and_wait(a, b, "after-reply")
    a_hdrs = [(dh, pn, n) for fp, dh, pn, n in seen if fp == a.fp]
    b_hdrs = [(dh, pn, n) for fp, dh, pn, n in seen if fp == b.fp]
    assert [n for _, _, n in a_hdrs] == [0, 1, 2, 0]
    assert len({dh for dh, _, _ in a_hdrs[:3]}) == 1                    # same key within a burst
    assert a_hdrs[3][0] != a_hdrs[0][0] and a_hdrs[3][1] == 3           # rotated after the reply, pn = 3
    assert b_hdrs[0][0] not in {dh for dh, _, _ in a_hdrs}              # b has its own key
    assert b_hdrs[0][1] == 0


def test_responder_speaks_first_over_a_real_connection(peers):
    a, b = peers
    sa, sb = connect(a, b)                                  # a opened, b is the responder
    assert sb.ratchet._cks is None
    send_and_wait(b, a, "responder first")
    send_and_wait(a, b, "initiator answers")
    send_and_wait(b, a, "and again")
    assert a.net.sessions[b.fp] is sa and b.net.sessions[a.fp] is sb    # one connection throughout


def test_simultaneous_bidirectional_bursts_keep_both_ratchets_in_sync(peers):
    """Stress for the lock design: receive-side DH steps rewrite the SENDING chain while the other thread is sending"""
    a, b = peers
    connect(a, b)
    n = 30
    ts = [threading.Thread(target=lambda p=p, q=q, i=i: p.net.send_text(q.fp, f"{p.name}-{i}"))
          for i in range(n) for p, q in ((a, b), (b, a))]
    for t in ts: t.start()
    for t in ts: t.join()
    assert wait_for(lambda: len(a.received) == n and len(b.received) == n, 30), (len(a.received), len(b.received))
    assert sorted(b.texts()) == sorted(f"alice-{i}" for i in range(n))
    assert sorted(a.texts()) == sorted(f"bob-{i}" for i in range(n))
    assert wait_for(lambda: not a.storage.has_pending(b.fp) and not b.storage.has_pending(a.fp), 30)
    assert not any("desync" in m or "cannot decipher" in m for _, m in a.statusbar + b.statusbar)


@pytest.mark.parametrize("text", ["x" * proto.MAX_MESSAGE_BYTES, "🔐" * (proto.MAX_MESSAGE_BYTES // 4), "àèìòù ñ ç 漢字 " * 20, "a"])
def test_boundary_payloads_roundtrip(peers, text):
    a, b = peers
    assert len(text.encode()) <= proto.MAX_MESSAGE_BYTES
    send_and_wait(a, b, text)
    assert b.received[-1][1] == text


def test_replayed_packet_is_acked_but_neither_delivered_nor_stored_twice(peers):
    a, b = peers
    sa, sb = connect(a, b)
    captured = []
    orig = sa.send
    sa.send = lambda p: (captured.append(p) if p.get("type") == "MESSAGE" else None, orig(p))[1]
    mid = send_and_wait(a, b, "once")
    nr_before = sb.ratchet._nr
    acks_before = len(a.acked)
    sa.send(captured[0])                                # attacker/bug replays the exact same wire packet
    assert wait_for(lambda: len(a.acked) > acks_before)  # peer re-ACKs (lets a lost-ACK sender stop retrying)
    time.sleep(0.3)
    assert b.texts() == ["once"] and len(b.storage.get_history(a.fp)) == 1
    assert sb.ratchet._nr == nr_before                  # and no ratchet step was wasted
    assert sb.alive


def test_sender_field_mismatch_is_ignored(peers):
    a, b = peers
    sa, sb = connect(a, b)
    mk, h = sa.next_send_key()
    other_fp = "c" * 64
    pkt = proto.build_message(proto.new_message_id(), other_fp, proto.now_ms(), b"n" * 12, b"c" * 40, h.n, h.dh, h.pn)
    sa.send(proto.add_padding(pkt))
    assert wait_for(lambda: any("Sender mismatch" in m for _, m in b.statusbar))
    assert b.received == [] and sb.alive


def test_tampered_ciphertext_is_dropped_without_desynchronising(peers):
    a, b = peers
    sa, sb = connect(a, b)
    mk, h = sa.next_send_key()                                   # consumes index 0 on the sender
    nonce, ct = crypto.encrypt_message(mk, "forged", b"wrong aad")   # authenticates under the wrong AAD
    pkt = proto.build_message(proto.new_message_id(), a.fp, proto.now_ms(), nonce, ct, h.n, h.dh, h.pn)
    sa.send(proto.add_padding(pkt))
    assert wait_for(lambda: any("cannot decipher" in m for _, m in b.statusbar))
    assert b.received == [] and sb.alive and sb.ratchet._nr == 0   # nothing advanced
    send_and_wait(a, b, "genuine")                               # index 1: index 0 is skipped, not fatal
    assert b.texts() == ["genuine"] and sb.alive


def test_gap_beyond_skip_limit_kills_session_and_the_message_is_redelivered_on_a_new_one(peers):
    a, b = peers
    sa, sb = connect(a, b)
    for _ in range(ratchet_mod.R.MAX_CHAIN_SKIP + 20 if hasattr(ratchet_mod, "R") else 220):
        sa.next_send_key()                                       # sender races far ahead (lost traffic)
    mid = a.net.send_text(b.fp, "after the gap")
    assert wait_for(lambda: any("desync" in m for _, m in b.statusbar)), "receiver did not flag the desync"
    assert wait_for(lambda: no_sessions(a, b))                   # session torn down on both ends
    assert b.received == []
    # next activity re-handshakes (fresh ratchet) and the still-pending message goes out
    a.net.send_text(b.fp, "trigger")
    assert wait_for(lambda: set(b.texts()) == {"after the gap", "trigger"}, 20), b.texts()
    assert a.net.sessions[b.fp] is not sa


def test_invalid_ratchet_key_length_closes_the_session(peers):
    a, b = peers
    sa, sb = connect(a, b)
    pkt = proto.build_message(proto.new_message_id(), a.fp, proto.now_ms(), b"n" * 12, b"c" * 40, 0, b"short", 0)
    sa.send(proto.add_padding(pkt))
    assert wait_for(lambda: not sb.alive)
    assert wait_for(lambda: no_sessions(a, b))
    assert b.received == []


def test_peer_close_packet_ends_session_and_marks_offline(peers):
    a, b = peers
    sa, sb = connect(a, b)
    sa.send(proto.add_padding(proto.build_close(a.fp)))
    assert wait_for(lambda: not sb.alive)
    assert wait_for(lambda: (a.fp, "offline") in b.status)


def test_close_packet_with_wrong_sender_is_ignored(peers):
    a, b = peers
    sa, sb = connect(a, b)
    sa.send(proto.add_padding(proto.build_close("d" * 64)))
    time.sleep(0.4)
    assert sb.alive
    send_and_wait(a, b, "still connected")


def test_lost_message_is_recovered_by_retransmission_through_the_skipped_key(peers, fast_retransmit):
    """Drop the first transmission of m1; m2 arrives first; the watchdog resends m1's SAME packet."""
    a, b = peers
    a.net.start_ack_watchdog()
    sa, sb = connect(a, b)
    m1 = proto.new_message_id()
    lose_first_transmission(sa, [m1])
    a.net.send_text(b.fp, "first", msg_id=m1)
    assert wait_for(lambda: m1 in a.net.pending_acks)
    a.net.send_text(b.fp, "second")
    assert wait_for(lambda: "second" in b.texts())
    assert "first" not in b.texts()                             # genuinely out of order at this point
    assert wait_for(lambda: "first" in b.texts(), 10), "retransmission was not accepted"
    assert b.texts() == ["second", "first"]
    assert wait_for(lambda: not a.storage.has_pending(b.fp))
    assert sa.alive and sb.alive and a.net.sessions[b.fp] is sa  # the old design killed the session here
    assert sa.ratchet._ns == 2                                   # retransmit did NOT consume another ratchet step


def test_retransmitted_message_survives_a_dh_step_in_between(peers, fast_retransmit):
    a, b = peers
    a.net.start_ack_watchdog()
    sa, sb = connect(a, b)
    m1 = proto.new_message_id()
    lose_first_transmission(sa, [m1])
    a.net.send_text(b.fp, "lost-1", msg_id=m1)
    assert wait_for(lambda: m1 in a.net.pending_acks)
    send_and_wait(a, b, "chain1-later")                         # b sees index 1, skips 0
    send_and_wait(b, a, "reply")                                # b's DH step
    send_and_wait(a, b, "chain2")                               # a's DH step: pn = 2
    assert wait_for(lambda: "lost-1" in b.texts(), 10)          # old-chain message accepted after TWO DH steps


def test_unhandled_race_flush_on_a_destroyed_session_is_harmless(peers, monkeypatch):
    a, b = peers
    sa, sb = connect(a, b)
    sa.alive = False
    sa.destroy()                                                # as the read loop does when the peer disconnects
    monkeypatch.setattr(a.net, "_get_or_connect", lambda contact: sa)   # flush still holds the dead session
    errors = []
    monkeypatch.setattr(threading, "excepthook", lambda args: errors.append(args))
    a.storage.enqueue_outbox("m-race", b.fp, "stays queued")
    a.net._flush_outbox_for_locked(b.fp)                        # must not raise
    assert not errors
    assert a.storage.get_pending_ids(b.fp) == {"m-race"}        # message not lost


## ======================================================================= reconnection

def test_message_queued_while_peer_is_down_is_delivered_when_it_comes_up(tmp_path, fast_kdf):
    port = free_port()
    a = Peer(tmp_path, "alice")
    ghost = Peer(tmp_path, "bob", port=port, listen=False)       # identity exists, nothing listens yet
    a.add_contact(ghost)
    mid = a.net.send_text(ghost.fp, "are you there?")
    assert wait_for(lambda: a.storage.has_pending(ghost.fp)) and a.received == []
    time.sleep(0.5)
    assert ghost.received == [] and a.storage.has_pending(ghost.fp)
    try:
        ghost.add_contact(a)
        ghost.net.start_listener(port=port)                      # peer comes online
        a.net.broadcast_presence("online", wait=5)               # presence tick reconnects and flushes the outbox
        assert wait_for(lambda: ghost.texts() == ["are you there?"], 15)
        assert wait_for(lambda: mid in a.acked)
        assert not a.storage.has_pending(ghost.fp)
    finally:
        a.close(); ghost.close()


def test_conversation_survives_a_dropped_connection_with_a_fresh_ratchet(peers):
    a, b = peers
    send_and_wait(a, b, "before")
    old_session = a.net.sessions[b.fp]
    old_rk = bytes(old_session.ratchet._rk)
    drop_session(b, a)
    assert wait_for(lambda: no_sessions(a, b))
    send_and_wait(b, a, "after drop, b -> a")
    send_and_wait(a, b, "after drop, a -> b")
    new_session = a.net.sessions[b.fp]
    assert new_session is not old_session and bytes(new_session.ratchet._rk) != old_rk
    assert b.texts() == ["before", "after drop, a -> b"] and a.texts() == ["after drop, b -> a"]


@pytest.mark.parametrize("attempt", range(4))
def test_simultaneous_connect_converges_to_a_working_session(tmp_path, fast_kdf, fast_retransmit, attempt):
    a, b = Peer(tmp_path, "alice"), Peer(tmp_path, "bob")
    a.add_contact(b); b.add_contact(a)
    a.net.start_ack_watchdog(); b.net.start_ack_watchdog()
    try:
        barrier = threading.Barrier(2)

        def go(p, q):
            barrier.wait()
            try:
                p.net._get_or_connect(p.contact_of(q))
            except Exception:
                pass

        ts = [threading.Thread(target=go, args=(a, b)), threading.Thread(target=go, args=(b, a))]
        for t in ts: t.start()
        for t in ts: t.join()
        time.sleep(0.5)
        a.net.send_text(b.fp, "a says hi"); b.net.send_text(a.fp, "b says hi")
        assert wait_for(lambda: "a says hi" in b.texts() and "b says hi" in a.texts(), 20), (a.statusbar, b.statusbar)
        assert wait_for(lambda: not a.storage.has_pending(b.fp) and not b.storage.has_pending(a.fp), 20)
    finally:
        a.close(); b.close()


## ======================================================================= resource limits

def test_listener_connection_flood_guard_drops_excess_connections(peers):
    a, b = peers
    socks = []
    try:
        for _ in range(network.CONN_MAX_PER_IP + 3):
            s = socket.create_connection(("127.0.0.1", b.port), timeout=2)
            socks.append(s)
            time.sleep(0.02)
        time.sleep(0.5)
        closed = 0
        for s in socks:
            s.settimeout(0.3)
            try:
                if s.recv(1) == b"":
                    closed += 1
            except socket.timeout:
                pass                                             # still in handshake: accepted
            except OSError:
                closed += 1
        assert closed >= 3                                       # everything past the per-IP budget was cut
    finally:
        for s in socks:
            s.close()


def test_global_session_cap_refuses_inbound_before_handshake(peers):
    a, b = peers
    b.net._session_cap = ratelimit.GlobalSessionCap(0)
    s = socket.create_connection(("127.0.0.1", b.port), timeout=2)
    try:
        s.settimeout(2)
        assert s.recv(1) == b""                                  # closed immediately, no handshake bytes consumed
    finally:
        s.close()
    a.net.send_text(b.fp, "should not arrive")
    time.sleep(1.0)
    assert b.received == []


def test_session_byte_rate_limit_drops_excess_frames_then_recovers(tmp_path, fast_kdf, monkeypatch):
    frame_body = proto.MAX_FRAME_SIZE
    monkeypatch.setattr(network, "SESSION_MAX_BYTES_PER_WINDOW", 3 * frame_body)
    monkeypatch.setattr(network, "SESSION_WINDOW_SECONDS", 3)
    a, b = Peer(tmp_path, "alice"), Peer(tmp_path, "bob")
    a.add_contact(b); b.add_contact(a)
    try:
        sa, sb = connect(a, b)
        for _ in range(6):                                       # six frames inside one window; only three fit
            sa.send(proto.add_padding(proto.build_presence("PRESENCE", a.fp, "offline")))
        time.sleep(0.8)
        assert [s for fp, s in b.status if fp == a.fp].count("offline") == 3
        time.sleep(3.3)                                          # window slides: traffic is accepted again
        sa.send(proto.add_padding(proto.build_presence("PRESENCE", a.fp, "offline")))
        assert wait_for(lambda: [s for fp, s in b.status if fp == a.fp].count("offline") == 4)
        assert sb.alive
    finally:
        a.close(); b.close()


## ======================================================================= presence fan-out (parallel, fire-and-forget)

def _silent_server():
    """Accepts TCP and never answers: a handshake against it blocks until WIRE_KEY_EXCHANGE_TIMEOUT"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(10)
    accepted, conns = [], []

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            accepted.append(1)
            conns.append(c)

    threading.Thread(target=loop, daemon=True).start()
    return srv, srv.getsockname()[1], accepted


def _add_silent_contact(peer, port):
    ghost = idmod.Identity(crypto.generate_x25519_keypair(), bytes(range(32)))
    peer.storage.add_contact(ghost.fingerprint, "silent", "127.0.0.1", port, proto.b64(ghost.public_key_raw))
    return ghost


def test_presence_is_nonblocking_parallel_and_does_not_pile_up(peers):
    a, b = peers
    srv, sport, accepted = _silent_server()
    ghost = _add_silent_contact(a, sport)
    try:
        t0 = time.monotonic()
        a.net.broadcast_presence("online")
        a.net.broadcast_presence("online")                      # second call while the silent peer is still "in flight"
        assert time.monotonic() - t0 < 0.5                      # sequential code would block >= WIRE_KEY_EXCHANGE_TIMEOUT
        assert wait_for(lambda: (a.fp, "online") in b.status, 5)    # healthy peer not held back by the silent one
        assert len(accepted) == 1                               # no second attempt against the silent peer
        assert ghost.fingerprint in a.net._presence_inflight
    finally:
        srv.close()


def test_offline_broadcast_uses_live_sessions_only_and_is_bounded(peers):
    a, b = peers
    srv, sport, accepted = _silent_server()
    _add_silent_contact(a, sport)
    connect(a, b)
    try:
        t0 = time.monotonic()
        a.net.broadcast_presence("offline", wait=1.0)
        assert time.monotonic() - t0 < 1.5
        assert wait_for(lambda: (a.fp, "offline") in b.status, 5)
        assert accepted == []                                   # never dialled the silent contact
    finally:
        srv.close()


def test_offline_broadcast_to_unreachable_contacts_returns_immediately(peers):
    a, b = peers
    srv, sport, accepted = _silent_server()
    _add_silent_contact(a, sport)
    try:
        t0 = time.monotonic()
        a.net.broadcast_presence("offline", wait=5.0)           # no live sessions at all
        assert time.monotonic() - t0 < 0.5 and accepted == []
    finally:
        srv.close()


def test_no_online_announcement_after_shutdown_has_started(peers):
    a, b = peers
    a.net.broadcast_presence("offline", wait=0.5)               # raises the closing flag
    a.net.broadcast_presence("online", wait=1.0)
    time.sleep(0.4)
    assert (a.fp, "online") not in b.status


def test_presence_to_unreachable_contact_marks_it_offline(peers):
    a, b = peers
    a.storage.delete_contact(b.fp)
    port = free_port()                                          # nothing listens here
    ghost = idmod.Identity(crypto.generate_x25519_keypair(), bytes(range(32)))
    a.storage.add_contact(ghost.fingerprint, "gone", "127.0.0.1", port, proto.b64(ghost.public_key_raw))
    a.net.broadcast_presence("online", wait=3)
    assert wait_for(lambda: (ghost.fingerprint, "offline") in a.status, 3)


def test_presence_roundtrip_sets_peer_online_on_both_sides(peers):
    a, b = peers
    a.net.broadcast_presence("online", wait=3)
    assert wait_for(lambda: (a.fp, "online") in b.status and (b.fp, "online") in a.status, 5)
    assert a.fp in b.net.peer_presence


## ======================================================================= known defect (documented, strict xfail)

@pytest.mark.xfail(strict=True, reason="race in _flush_outbox_for_locked: pending_acks is filled AFTER session.send(), so an ACK "
                                       "that wins the race is lost and the entry stays forever (-> a redundant retransmission)")
def test_ack_that_arrives_before_pending_acks_registration_does_not_leave_an_orphan_entry(peers):
    a, b = peers
    sa, sb = connect(a, b)
    mid = proto.new_message_id()
    original = sa.send

    def send_then_wait_for_the_ack(packet):
        original(packet)
        if packet.get("type") == "MESSAGE":                       # emulate a preempted sender thread:
            assert wait_for(lambda: mid in a.acked)               # the ACK is fully processed before send() returns
    sa.send = send_then_wait_for_the_ack

    a.net.send_text(b.fp, "raced", msg_id=mid)
    assert wait_for(lambda: mid in a.acked)
    assert wait_for(lambda: len(a.storage.get_history(b.fp)) == 1)
    time.sleep(0.2)
    assert mid not in a.net.pending_acks                          # delivered AND acked: nothing may still be pending
