"""
Double Ratchet: functional behaviour, robustness against hostile/lossy input, key hygiene,
and the actual security properties (forward secrecy, post-compromise security).
Pure unit tests: no sockets, no storage.
"""
import copy
import dataclasses
import os
import random

import pytest

from redoubt import crypto, ratchet as R
from redoubt.ratchet import DoubleRatchet, Header, RatchetError


## ---------------------------------------------------------------- helpers

def pair():
    """(initiator, responder) seeded like the real handshake: shared root + each side's ephemeral key"""
    a, b = crypto.generate_x25519_keypair(), crypto.generate_x25519_keypair()
    ra, rb = crypto.public_key_to_raw(a.public_key()), crypto.public_key_to_raw(b.public_key())
    root = os.urandom(32)
    return DoubleRatchet.initiator(root, a, rb), DoubleRatchet.responder(root, b, ra)


def aad_of(h: Header) -> bytes:
    return b"hdr|" + h.dh + h.pn.to_bytes(4, "big") + h.n.to_bytes(4, "big")


def send(r, text):
    mk, h = r.prepare_send()
    nonce, ct = crypto.encrypt_message(mk, text, aad_of(h))
    return h, nonce, ct


def recv(r, pkt):
    """Full receive path as network.py does it: prepare -> AEAD verify -> commit"""
    h, nonce, ct = pkt
    mk, commit = r.prepare_receive(h)
    pt = crypto.decrypt_message(mk, nonce, ct, aad_of(h))   # raises BEFORE commit on forged data
    commit()
    return pt


def clone(r):
    c = copy.copy(r)
    c._rk = bytearray(r._rk)
    c._cks = bytearray(r._cks) if r._cks is not None else None
    c._ckr = bytearray(r._ckr) if r._ckr is not None else None
    c._skipped = copy.copy(r._skipped)
    return c


def can_decrypt(r, pkt):
    """Would a holder of state `r` decrypt a packet addressed to r's owner? (works on a clone: no side effects)"""
    try:
        recv(clone(r), pkt)
        return True
    except Exception:
        return False


def can_read_outgoing(snap, pkt):
    """Holder of a snapshot of the SENDER reads that sender's outgoing message (needs same ratchet key + chain key)"""
    h, nonce, ct = pkt
    if snap._cks is None or h.dh != snap._dhs_pub or h.n < snap._ns:
        return False
    ck = bytearray(snap._cks)
    for _ in range(h.n - snap._ns):
        _, ck = crypto.ratchet_step(ck)
    mk, _ = crypto.ratchet_step(ck)
    try:
        crypto.decrypt_message(mk, nonce, ct, aad_of(h))
        return True
    except Exception:
        return False


def state_bytes(r):
    """Every byte string that currently lives in the ratchet state"""
    parts = [bytes(r._rk), r._dhs_pub or b"", r._dhr or b""]
    if r._dhs is not None:
        parts.append(crypto.private_key_to_raw(r._dhs))
    for ck in (r._cks, r._ckr):
        if ck is not None:
            parts.append(bytes(ck))
    parts.extend(bytes(v) for v in r._skipped.values())
    return b"".join(parts)


def live_secrets(r):
    live = {bytes(r._rk)}
    for ck in (r._cks, r._ckr):
        if ck is not None:
            live.add(bytes(ck))
    live.update(bytes(v) for v in r._skipped.values())
    return live


@pytest.fixture
def secret_log(monkeypatch):
    """Records every chain key / message key / root key ever produced or consumed by the ratchet"""
    log = set()
    real_step, real_kdf = crypto.ratchet_step, R._kdf_root

    def step(ck):
        mk, nxt = real_step(ck)
        log.update({bytes(ck), bytes(mk), bytes(nxt)})
        return mk, nxt

    def kdf(rk, dh_out):
        new_rk, ck = real_kdf(rk, dh_out)
        log.update({bytes(rk), bytes(new_rk), bytes(ck)})
        return new_rk, ck

    monkeypatch.setattr(crypto, "ratchet_step", step)
    monkeypatch.setattr(R, "_kdf_root", kdf)
    return log


## ---------------------------------------------------------------- functional behaviour

def test_roundtrip_alternating_and_bursts():
    a, b = pair()
    for i in range(30):
        for _ in range(i % 4 + 1):
            assert recv(b, send(a, f"a{i}")) == f"a{i}"
        for _ in range(i % 3 + 1):
            assert recv(a, send(b, f"b{i}")) == f"b{i}"


def test_unicode_and_empty_payloads():
    a, b = pair()
    for text in ("", "ciao àèì 🔐", "x" * 2500):
        assert recv(b, send(a, text)) == text


def test_responder_can_speak_first_and_initiator_can_follow():
    a, b = pair()
    assert recv(a, send(b, "hi")) == "hi"
    assert recv(b, send(a, "yo")) == "yo"
    assert recv(a, send(b, "again")) == "again"


def test_initiator_sends_a_long_burst_before_any_reply():
    a, b = pair()
    pkts = [send(a, f"m{i}") for i in range(50)]
    assert [recv(b, p) for p in pkts] == [f"m{i}" for i in range(50)]


def test_crossing_messages_both_speak_first():
    """A and B each send before receiving the other's first message (responder-first + initiator burst)"""
    a, b = pair()
    pa0, pa1 = send(a, "a0"), send(a, "a1")
    pb0, pb1 = send(b, "b0"), send(b, "b1")
    assert recv(b, pa0) == "a0"
    assert recv(a, pb0) == "b0"
    assert recv(b, pa1) == "a1"
    assert recv(a, pb1) == "b1"
    for i in range(5):                          # and the conversation continues in sync
        assert recv(b, send(a, f"x{i}")) == f"x{i}"
        assert recv(a, send(b, f"y{i}")) == f"y{i}"


def test_independent_pairs_do_not_interoperate():
    a1, _ = pair()
    _, b2 = pair()
    with pytest.raises(Exception):
        recv(b2, send(a1, "x"))


def test_wrong_root_key_does_not_decrypt():
    ea, eb = crypto.generate_x25519_keypair(), crypto.generate_x25519_keypair()
    pa, pb = crypto.public_key_to_raw(ea.public_key()), crypto.public_key_to_raw(eb.public_key())
    a = DoubleRatchet.initiator(os.urandom(32), ea, pb)
    b = DoubleRatchet.responder(os.urandom(32), eb, pa)     # different root
    with pytest.raises(Exception):
        recv(b, send(a, "x"))


## ---------------------------------------------------------------- header semantics

def test_header_is_immutable_value_object():
    h = Header(b"k" * 32, 1, 2)
    assert h == Header(b"k" * 32, 1, 2) and hash(h) == hash(Header(b"k" * 32, 1, 2))
    with pytest.raises(dataclasses.FrozenInstanceError):
        h.n = 5


def test_header_fields_dh_is_stable_within_a_burst_and_rotates_on_turnaround():
    a, b = pair()
    burst1 = [send(a, "x")[0] for _ in range(3)]
    assert len({h.dh for h in burst1}) == 1
    assert [h.n for h in burst1] == [0, 1, 2]
    for h in burst1:
        pass
    # b receives, replies
    a2, b2 = pair()
    p = [send(a2, "x") for _ in range(3)]
    for pk in p:
        recv(b2, pk)
    rb = send(b2, "r")
    assert rb[0].dh != p[0][0].dh                 # b uses its own key
    recv(a2, rb)
    nxt = send(a2, "after")
    assert nxt[0].dh != p[0][0].dh                # a rotated its key after receiving
    assert nxt[0].pn == 3 and nxt[0].n == 0       # pn = length of the previous sending chain, n restarts


def test_pn_counts_previous_chain_for_responder_first_send():
    a, b = pair()
    h0 = send(b, "first")[0]
    assert h0.pn == 0 and h0.n == 0


def test_every_direction_change_produces_a_fresh_public_key():
    a, b = pair()
    seen = set()
    for i in range(12):
        pa = send(a, "a")
        seen.add(("a", pa[0].dh))
        recv(b, pa)
        pb = send(b, "b")
        seen.add(("b", pb[0].dh))
        recv(a, pb)
    assert len(seen) == 24              # 12 turns x 2 sides, every one a brand-new key


def test_message_keys_are_never_reused():
    """Keys produced by the SENDING side (both parties, many DH steps) are all distinct;
    and the receiver derives exactly the sender's key for each message"""
    a, b = pair()
    sent_keys = []
    for i in range(60):
        for sender, receiver in ((a, b), (b, a)):
            mk, h = sender.prepare_send()
            sent_keys.append(mk)
            nonce, ct = crypto.encrypt_message(mk, str(i), aad_of(h))
            rmk, commit = receiver.prepare_receive(h)
            assert rmk == mk
            assert crypto.decrypt_message(rmk, nonce, ct, aad_of(h)) == str(i)
            commit()
    assert len(sent_keys) == 120 and len(set(sent_keys)) == 120


## ---------------------------------------------------------------- loss, reordering, duplicates

def test_out_of_order_within_a_chain():
    a, b = pair()
    p = [send(a, f"m{i}") for i in range(6)]
    for i in (3, 0, 5, 1, 4, 2):
        assert recv(b, p[i]) == f"m{i}"


def test_loss_then_late_arrival_across_dh_steps():
    a, b = pair()
    p = [send(a, f"m{i}") for i in range(5)]
    assert recv(b, p[3]) == "m3"            # 0,1,2 skipped
    r1 = send(b, "reply")
    assert recv(a, r1) == "reply"
    p5 = send(a, "after")                    # a stepped: pn=5
    assert recv(b, p5) == "after"            # b keeps the keys of m4 of the old chain
    for i in (0, 1, 2, 4):
        assert recv(b, p[i]) == f"m{i}"


def test_late_message_from_two_chains_ago():
    a, b = pair()
    old = send(a, "old")                                   # chain 1 (never delivered)
    keep = send(a, "chain1-b")
    recv(b, keep)                                          # b skips "old"
    recv(a, send(b, "r1"))
    c2 = send(a, "chain2"); recv(b, c2)
    recv(a, send(b, "r2"))
    c3 = send(a, "chain3"); recv(b, c3)
    assert recv(b, old) == "old"


def test_skipped_key_is_single_use():
    a, b = pair()
    p0, p1 = send(a, "0"), send(a, "1")
    recv(b, p1)
    assert recv(b, p0) == "0"
    with pytest.raises(Exception):
        recv(b, p0)


def test_replay_of_consumed_message_is_rejected_and_harmless():
    a, b = pair()
    pkt = send(a, "x")
    assert recv(b, pkt) == "x"
    with pytest.raises(RatchetError):
        recv(b, pkt)
    assert recv(b, send(a, "next")) == "next"


def test_replay_of_old_chain_message_is_rejected_and_harmless():
    a, b = pair()
    old = send(a, "old"); recv(b, old)
    recv(a, send(b, "r"))
    recv(b, send(a, "new chain"))
    with pytest.raises(Exception):
        recv(b, old)                                       # old dh key: treated as bogus step, fails AEAD, no commit
    recv(a, send(b, "still works"))
    assert recv(b, send(a, "and this")) == "and this"


def test_skip_limit_per_chain(monkeypatch):
    a, b = pair()
    pkts = [send(a, str(i)) for i in range(R.MAX_CHAIN_SKIP + 5)]
    with pytest.raises(RatchetError):
        recv(b, pkts[-1])
    assert recv(b, pkts[0]) == "0"                         # state untouched by the refused jump


def test_skip_limit_boundary_is_exact():
    a, b = pair()
    pkts = [send(a, str(i)) for i in range(R.MAX_CHAIN_SKIP + 1)]
    assert recv(b, pkts[R.MAX_CHAIN_SKIP]) == str(R.MAX_CHAIN_SKIP)      # gap == MAX is allowed
    a, b = pair()
    pkts = [send(a, str(i)) for i in range(R.MAX_CHAIN_SKIP + 2)]
    with pytest.raises(RatchetError):
        recv(b, pkts[R.MAX_CHAIN_SKIP + 1])                              # gap == MAX+1 is not


def test_skip_limit_applies_to_pn_on_dh_step():
    """A forged huge `pn` in a DH-step header cannot force unbounded HMAC work"""
    a, b = pair()
    recv(b, send(a, "x"))
    recv(a, send(b, "r"))
    h, nonce, ct = send(a, "new chain")
    forged = Header(h.dh, R.MAX_CHAIN_SKIP + 50, h.n)
    with pytest.raises(RatchetError):
        b.prepare_receive(forged)


def test_skipped_key_store_cap(monkeypatch):
    monkeypatch.setattr(R, "MAX_SKIPPED_KEYS", 5)
    monkeypatch.setattr(R, "MAX_CHAIN_SKIP", 3)
    a, b = pair()
    last = None
    for turn in range(4):
        pk = [send(a, f"t{turn}-{i}") for i in range(4)]
        if turn < 1:
            recv(b, pk[3])                                  # skips 3 -> store = 3
        else:
            with pytest.raises(RatchetError):               # would exceed the cap of 5
                recv(b, pk[3])
            break
        recv(a, send(b, "r"))
    assert len(b._skipped) <= 5


def test_skipped_keys_survive_failed_attempts():
    a, b = pair()
    p = [send(a, str(i)) for i in range(4)]
    recv(b, p[3])
    assert set(n for (_, n) in b._skipped) == {0, 1, 2}
    h, nonce, ct = p[1]
    with pytest.raises(Exception):
        recv(b, (h, nonce, ct[:-1] + bytes([ct[-1] ^ 1])))  # forged copy of a skipped slot
    assert recv(b, p[1]) == "1"                              # the genuine one still decrypts


## ---------------------------------------------------------------- atomicity under attack

def test_forged_ciphertext_does_not_advance_state():
    a, b = pair()
    h, n, ct = send(a, "y")
    with pytest.raises(Exception):
        recv(b, (h, n, ct[:-1] + bytes([ct[-1] ^ 1])))
    assert b._nr == 0 and not b._skipped
    assert recv(b, (h, n, ct)) == "y"


def test_forged_header_fields_do_not_advance_state():
    a, b = pair()
    h, n, ct = send(a, "x")
    snapshot = (bytes(b._rk), bytes(b._ckr), b._nr, b._dhr, b._ns, b._pn)
    for forged in (
        Header(crypto.public_key_to_raw(crypto.generate_x25519_keypair().public_key()), 0, 0),   # unknown DH key
        Header(h.dh, h.pn, h.n + 3),                                                              # wrong index
        Header(h.dh, h.pn + 1, h.n),                                                              # wrong pn
    ):
        with pytest.raises(Exception):
            recv(b, (forged, n, ct))
        assert snapshot == (bytes(b._rk), bytes(b._ckr), b._nr, b._dhr, b._ns, b._pn)
    assert recv(b, (h, n, ct)) == "x"


def test_failed_dh_step_leaves_sending_chain_untouched():
    """A forged 'new DH key' packet must not rotate the victim's own sending chain"""
    a, b = pair()                               # a (initiator) already owns a sending chain
    mk_before, h_before = clone(a).prepare_send()
    fake = Header(crypto.public_key_to_raw(crypto.generate_x25519_keypair().public_key()), 0, 0)
    with pytest.raises(Exception):
        recv(a, (fake, b"n" * 12, b"c" * 32))
    mk_after, h_after = clone(a).prepare_send()
    assert (mk_before, h_before) == (mk_after, h_after)


@pytest.mark.parametrize("point", [
    bytes(32),                                                                                    # 0
    b"\x01" + bytes(31),                                                                          # 1
    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),            # order 8
    bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),            # order 8
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),            # p-1
])
def test_low_order_peer_keys_are_rejected(point):
    a, b = pair()
    h, n, ct = send(a, "x")
    with pytest.raises(RatchetError):
        b.prepare_receive(Header(point, 0, 0))
    eph = crypto.generate_x25519_keypair()
    with pytest.raises(RatchetError):
        DoubleRatchet.initiator(os.urandom(32), eph, point)
    with pytest.raises(RatchetError):
        DoubleRatchet.responder(os.urandom(32), eph, point)


def test_stale_index_without_stored_key_is_rejected():
    a, b = pair()
    p = [send(a, str(i)) for i in range(3)]
    for pk in p:
        recv(b, pk)
    with pytest.raises(RatchetError):
        b.prepare_receive(p[0][0])


def test_reflected_own_packet_is_rejected_and_harmless():
    """An attacker replays A's OWN outgoing packet back to A: AEAD must fail, no state change"""
    a, b = pair()
    own = send(a, "my own message")
    state = (bytes(a._rk), bytes(a._cks), a._nr, a._dhr, a._ns, a._gen)
    with pytest.raises(Exception):
        recv(a, own)
    assert state == (bytes(a._rk), bytes(a._cks), a._nr, a._dhr, a._ns, a._gen)
    assert recv(b, send(a, "still fine")) == "still fine"


def test_commit_is_single_use():
    a, b = pair()
    h, n, ct = send(a, "x")
    mk, commit = b.prepare_receive(h)
    commit()
    live = (bytes(b._rk), bytes(b._ckr))
    commit()                          # second call must be a no-op, NOT wipe the live keys
    assert (bytes(b._rk), bytes(b._ckr)) == live
    assert recv(b, send(a, "y")) == "y"


def test_stale_commit_after_a_send_is_refused_and_cannot_roll_back_the_send_chain():
    """prepare_receive(DH step) -> a send happens -> commit: would restore the OLD sending chain key and reuse a message key"""
    a, b = pair()
    recv(b, send(a, "x"))
    recv(a, send(b, "r"))
    h, n, ct = send(a, "new chain")           # b will perform a DH step on this
    mk, commit = b.prepare_receive(h)
    sent_mk, sent_h = b.prepare_send()        # concurrent send on b
    with pytest.raises(RatchetError):
        commit()
    # b's state is the post-send one: the next send must NOT reuse sent_mk
    next_mk, next_h = b.prepare_send()
    assert next_mk != sent_mk and next_h.n == sent_h.n + 1


def test_two_outstanding_prepares_only_first_commit_wins():
    a, b = pair()
    p0, p1 = send(a, "0"), send(a, "1")
    mk0, commit0 = b.prepare_receive(p0[0])
    mk1, commit1 = b.prepare_receive(p1[0])   # both computed from the same state
    commit0()
    with pytest.raises(RatchetError):
        commit1()
    assert recv(b, p1) == "1"                 # the proper path still works afterwards


def test_commit_failure_zeroes_its_temporaries():
    a, b = pair()
    recv(b, send(a, "x"))
    h, n, ct = send(a, "y")
    mk, commit = b.prepare_receive(h)
    b.prepare_send()                          # invalidates the pending commit (b is responder: starts its chain)
    with pytest.raises(RatchetError):
        commit()
    assert any(b._ckr)                        # live receive chain was NOT touched by the refused commit


## ---------------------------------------------------------------- key hygiene

def test_old_chain_keys_are_zeroed_in_place_on_send():
    a, _ = pair()
    old = a._cks
    snap = bytes(old)
    assert any(snap)
    send(a, "x")
    assert old == bytearray(32)
    assert a._cks is not old and a._cks != old


def test_old_keys_zeroed_in_place_on_receive_and_dh_step():
    a, b = pair()
    recv(b, send(a, "x"))
    old_rk, old_ckr = b._rk, b._ckr
    recv(b, send(a, "y"))
    assert old_ckr == bytearray(32)                         # advanced chain key wiped
    recv(a, send(b, "r"))
    old_rk2, old_cks2, old_ckr2 = a._rk, a._cks, a._ckr
    recv(b, send(a, "z"))                                    # b performs a DH step
    assert old_rk == bytearray(32)


def test_rejected_receive_zeroes_its_temporaries(monkeypatch):
    created = []
    real = R._kdf_root
    monkeypatch.setattr(R, "_kdf_root", lambda rk, dh: (lambda o: (created.extend(o), o)[1])(real(rk, dh)))
    a, b = pair()
    recv(b, send(a, "x"))
    recv(a, send(b, "r"))
    created.clear()
    h, n, ct = send(a, "new chain")
    forged = (h, n, ct[:-1] + bytes([ct[-1] ^ 1]))
    mk, commit = b.prepare_receive(h)               # step computed (temporaries exist)...
    assert created                                   # ...then discarded without commit: state is the old one
    assert b._dhr != h.dh


def test_destroy_zeroes_everything_and_blocks_use():
    a, b = pair()
    recv(b, send(a, "x"))
    recv(a, send(b, "r"))
    bufs = [x for x in (a._rk, a._cks, a._ckr) if x is not None]
    assert all(any(x) for x in bufs)
    a.destroy()
    assert all(x == bytearray(len(x)) for x in bufs)
    assert not a._skipped
    with pytest.raises(RatchetError):
        a.prepare_send()
    with pytest.raises(RatchetError):
        a.prepare_receive(Header(b"k" * 32, 0, 0))


def test_commit_after_destroy_does_not_resurrect_keys():
    a, b = pair()
    h, n, ct = send(a, "x")
    mk, commit = b.prepare_receive(h)
    b.destroy()
    commit()
    assert b._destroyed and b._rk == bytearray(32)
    assert b._ckr == bytearray(32)


def test_destroy_is_idempotent():
    a, _ = pair()
    a.destroy()
    a.destroy()


def test_responder_destroy_before_first_send():
    _, b = pair()
    b.destroy()                                      # _cks is None: must not crash


def test_no_dead_secret_remains_in_state(secret_log):
    """After a long conversation, NO chain key / message key / root key that has been consumed is still stored anywhere in the state"""
    rng = random.Random(7)
    a, b = pair()
    for _ in range(40):
        who = rng.choice([a, b])
        other = b if who is a else a
        for _ in range(rng.randint(1, 3)):
            recv(other, send(who, "m"))
    for r in (a, b):
        dead = secret_log - live_secrets(r)
        blob = state_bytes(r)
        assert not any(d in blob for d in dead)
        assert len(dead) > 100                       # the check is not vacuous


## ---------------------------------------------------------------- randomized network model

def run_network(seed, steps=160, snapshot_at=None):
    """Random interleaving of send / deliver (with reordering) / drop / duplicate. Returns bookkeeping"""
    rng = random.Random(seed)
    a, b = pair()
    side = {"a": a, "b": b}
    peer = {"a": "b", "b": "a"}
    inflight = {"a": [], "b": []}
    delivered, dropped, dup_attempts = set(), set(), 0
    history = {"a": {"in": [], "out": []}, "b": {"in": [], "out": []}}   # consumed packets, per owner
    snap = None
    for i in range(steps):
        if snapshot_at is not None and i == snapshot_at:
            snap = {k: clone(v) for k, v in side.items()}
            snap_hist = copy.deepcopy(history)
        who = rng.choice("ab")
        action = rng.choices(["send", "deliver", "drop", "dup"], weights=[5, 5, 1, 1])[0]
        if action == "send":
            text = f"{who}-{i}"
            pkt = send(side[who], text)
            history[who]["out"].append(pkt)
            inflight[who].append((text, pkt))
        elif action == "deliver" and inflight[who]:
            idx = 0 if rng.random() < 0.6 else rng.randrange(len(inflight[who]))
            text, pkt = inflight[who].pop(idx)
            assert recv(side[peer[who]], pkt) == text
            delivered.add(text)
            history[peer[who]]["in"].append(pkt)
        elif action == "drop" and inflight[who]:
            text, _ = inflight[who].pop(rng.randrange(len(inflight[who])))
            dropped.add(text)
        elif action == "dup" and history[peer[who]]["in"]:
            # a replay of something the receiver already consumed
            pkt = rng.choice(history[peer[who]]["in"])
            dup_attempts += 1
            with pytest.raises(Exception):
                recv(side[peer[who]], pkt)
    # drain: deliver the rest, in random order
    for who in "ab":
        rng.shuffle(inflight[who])
        for text, pkt in inflight[who]:
            assert recv(side[peer[who]], pkt) == text
            delivered.add(text)
            history[peer[who]]["in"].append(pkt)
    return side, delivered, dropped, dup_attempts, snap, (snap_hist if snap else None), history


@pytest.mark.parametrize("seed", range(40))
def test_random_network_every_delivered_message_decrypts_and_state_stays_in_sync(seed):
    side, delivered, dropped, dups, *_ = run_network(seed)
    assert not (delivered & dropped)
    # after all that chaos both sides still talk to each other
    assert recv(side["b"], send(side["a"], "final-a")) == "final-a"
    assert recv(side["a"], send(side["b"], "final-b")) == "final-b"


def test_random_network_exercises_the_interesting_paths():
    totals = dict(delivered=0, dropped=0, dups=0)
    for seed in range(40):
        _, delivered, dropped, dups, *_ = run_network(seed)
        totals["delivered"] += len(delivered); totals["dropped"] += len(dropped); totals["dups"] += dups
    assert totals["delivered"] > 500 and totals["dropped"] > 20 and totals["dups"] > 20


@pytest.mark.parametrize("seed", range(25))
def test_forward_secrecy_random_history(seed):
    """Snapshot of either side at a random moment: nothing it ALREADY consumed (received or sent) is recoverable"""
    side, _, _, _, snap, snap_hist, _ = run_network(seed, snapshot_at=random.Random(seed).randint(20, 120))
    for owner in "ab":
        attacker = snap[owner]
        for pkt in snap_hist[owner]["in"]:
            assert not can_decrypt(attacker, pkt), "past incoming message recoverable from snapshot"
        for pkt in snap_hist[owner]["out"]:
            assert not can_read_outgoing(attacker, pkt), "past outgoing message recoverable from snapshot"


## ---------------------------------------------------------------- post-compromise security

def test_known_exposure_skipped_message_keys():
    a, b = pair()
    p0, p1 = send(a, "0"), send(a, "1")
    recv(b, p1)                             # p0 skipped: its key waits in b's store
    assert can_decrypt(clone(b), p0)        # documented, bounded, inherent to out-of-order delivery


def test_pcs_exact_window_worst_case():
    """Snapshot of Bob right after a turn; Bob sends again BEFORE receiving anything new."""
    a, b = pair()
    for i in range(3):
        recv(b, send(a, f"a{i}")); recv(a, send(b, f"b{i}"))
    attacker = clone(b)

    m1 = send(b, "bob again")
    assert can_read_outgoing(attacker, m1)      # same sending chain as the snapshot: unavoidable
    recv(a, m1)
    r1 = send(a, "alice reply")                 # Alice's fresh key is DH'd against Bob's SNAPSHOT public key
    assert can_decrypt(attacker, r1)            # unavoidable too: attacker holds Bob's matching private key
    recv(b, r1)                                 # Bob steps with a key pair born AFTER the snapshot

    m2 = send(b, "bob healed")
    assert not can_read_outgoing(attacker, m2)
    recv(a, m2)
    r2 = send(a, "alice healed")
    assert not can_decrypt(attacker, r2)
    recv(b, r2)
    for i in range(6):                          # nothing afterwards, even though the attacker sees every packet
        pa, pb = send(a, f"a{i}"), send(b, f"b{i}")
        assert not can_decrypt(attacker, pa) and not can_read_outgoing(attacker, pb)
        recv(b, pa); recv(a, pb)


def test_pcs_when_victim_steps_immediately():
    a, b = pair()
    for i in range(3):
        recv(b, send(a, f"a{i}")); recv(a, send(b, f"b{i}"))
    attacker = clone(b)
    p_same = send(a, "alice")
    assert can_decrypt(attacker, p_same)        # Alice's chain was derived against Bob's snapshot key
    recv(b, p_same)
    reply = send(b, "reply")                    # Bob stepped on receipt: fresh key
    assert not can_read_outgoing(attacker, reply)


def _heal_scenario(seed, tracker_follows=True):
    """Alternating bursts after a snapshot; returns the turn numbers (1-based) in which the attacker could read something"""
    rng = random.Random(seed)
    a, b = pair()
    parties = {"a": a, "b": b}
    first = rng.choice("ab")
    for t in range(rng.randint(0, 6)):                                  # random warm-up
        s = first if t % 2 == 0 else ("b" if first == "a" else "a")
        o = "b" if s == "a" else "a"
        for _ in range(rng.randint(1, 3)):
            recv(parties[o], send(parties[s], "w"))
    victim = rng.choice("ab")
    att0 = clone(parties[victim])
    shadow = clone(parties[victim])
    readable_turns = []
    sender = rng.choice("ab")
    for turn in range(1, 11):
        recvr = "b" if sender == "a" else "a"
        compromised = False
        for _ in range(rng.randint(1, 3)):
            pkt = send(parties[sender], "t")
            if sender == victim:
                compromised |= can_read_outgoing(att0, pkt)
            else:
                try:                                                    # attacker shadows the victim's receive path
                    mk, commit = shadow.prepare_receive(pkt[0])
                    crypto.decrypt_message(mk, pkt[1], pkt[2], aad_of(pkt[0]))
                    compromised = True
                    if tracker_follows:
                        commit()
                except Exception:
                    pass
            recv(parties[recvr], pkt)
        if compromised:
            readable_turns.append(turn)
        sender = recvr
    return readable_turns


@pytest.mark.parametrize("seed", range(60))
def test_pcs_heals_within_four_turns(seed):
    readable = _heal_scenario(seed)
    assert all(t <= 4 for t in readable), f"attacker still reads in turn(s) {readable}"


def test_pcs_attacker_model_is_not_vacuous():
    """Sanity: across scenarios the attacker DOES read something right after the snapshot"""
    assert sum(1 in _heal_scenario(s) for s in range(60)) > 15


def test_pcs_harness_detects_a_ratchet_without_fresh_entropy(monkeypatch):
    """Mutation check: a ratchet whose root KDF ignores the DH output still WORKS but never heals.
    The heal property must FAIL on it, otherwise the property test proves nothing."""
    real = R._kdf_root
    monkeypatch.setattr(R, "_kdf_root", lambda rk, dh_out: real(rk, b"\x00" * 32))
    worst = max(max(_heal_scenario(seed), default=0) for seed in range(20))
    assert worst > 4, "mutated ratchet was not detected: the heal test has no teeth"
