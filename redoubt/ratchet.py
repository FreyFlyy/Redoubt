### ratchet.py

"""
Double Ratchet module for Redoubt (Signal-style: symmetric KDF chains + Diffie-Hellman ratchet)

Properties (per session, i.e. per TCP handshake):
- Forward secrecy: message keys and chain keys are deleted right after use, the root key is
  advanced through DH outputs whose private halves are discarded. A state snapshot taken at
  any time does NOT allow decrypting messages already consumed.
- Post-compromise security: every time the direction of the conversation changes a fresh DH
  key pair is generated. A snapshot becomes useless to a PASSIVE attacker after the next
  turn-around (see tests/test_ratchet.py for the exact bound).
- Out-of-order / lost messages: skipped message keys are stored (bounded) and used when the
  late message arrives.

THREADING: no internal locking. The caller must hold the session lock across the whole
prepare_receive -> decrypt -> commit sequence, and across prepare_send.
"""

from collections import OrderedDict
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto
from . import secure_memory
from .protocol import MAX_CHAIN_SKIP

MAX_SKIPPED_KEYS = 1000     # hard cap of stored skipped message keys per session
_INFO_ROOT_STEP = b"REDOUBT DOUBLE RATCHET ROOT STEP"


## Exceptions and header

class RatchetError(Exception):
    """The message cannot be processed by the ratchet (stale, too far ahead, invalid DH key...)"""


@dataclass(frozen=True)
class Header:
    dh: bytes   # sender's current ratchet public key (raw, 32 bytes)
    pn: int     # number of messages sent in the sender's PREVIOUS sending chain
    n: int      # index of this message in the current sending chain


## Helpers

def _dh(priv, pub_raw: bytes) -> bytes:
    """X25519 with rejection of invalid/low-order points"""
    try:
        out = priv.exchange(crypto.public_key_from_raw(pub_raw))
    except ValueError as e:
        raise RatchetError(f"invalid DH public key: {e}")
    if not any(out):
        raise RatchetError("degenerate DH output")
    return out

def _kdf_root(rk, dh_out: bytes):
    """Root KDF: (rk, dh_out) -> (new root key, new chain key), both bytearray"""
    out = HKDF(algorithm=hashes.SHA256(), length=64, salt=bytes(rk), info=_INFO_ROOT_STEP).derive(dh_out)
    return bytearray(out[:32]), bytearray(out[32:])

def _zero(buf):
    if buf is not None:
        secure_memory.zero_bytearray(buf)

def _skip(ck: bytearray, n: int, until: int, dh: bytes, store: dict):
    """Advance a COPY of the chain from index n to `until`, storing the skipped message keys"""
    if until - n > MAX_CHAIN_SKIP:
        raise RatchetError("too many skipped messages")
    while n < until:
        mk, nxt = crypto.ratchet_step(ck)
        _zero(ck)
        ck = nxt
        store[(dh, n)] = mk
        n += 1
    return ck, n


## Double Ratchet

class DoubleRatchet:
    def __init__(self):
        self._dhs = None            # my current ratchet private key
        self._dhs_pub = None        # ... and its raw public key
        self._dhr = None            # peer's current ratchet public key (raw)
        self._rk = None             # root key (bytearray)
        self._cks = None            # sending chain key (None = a new sending chain must be started)
        self._ckr = None            # receiving chain key
        self._ns = 0                # messages sent in the current sending chain
        self._nr = 0                # messages received in the current receiving chain
        self._pn = 0                # messages sent in the previous sending chain
        self._skipped = OrderedDict()   # (peer dh raw, n) -> message key
        self._destroyed = False
        self._gen = 0               # bumped by every state change: a commit computed on an older state is refused

    ## Initialization (the handshake ephemeral keys are the initial ratchet keys)

    @classmethod
    def initiator(cls, root_key: bytes, my_eph_priv, their_eph_pub_raw: bytes):
        """Side that opened the TCP connection"""
        r = cls()
        r._dhs = my_eph_priv
        r._dhs_pub = crypto.public_key_to_raw(my_eph_priv.public_key())
        r._dhr = their_eph_pub_raw
        r._rk, r._cks = _kdf_root(root_key, _dh(my_eph_priv, their_eph_pub_raw))
        return r

    @classmethod
    def responder(cls, root_key: bytes, my_eph_priv, their_eph_pub_raw: bytes):
        """Side that accepted the TCP connection. Can already send: its first send starts a new DH step"""
        r = cls()
        r._dhs = my_eph_priv
        r._dhs_pub = crypto.public_key_to_raw(my_eph_priv.public_key())
        r._dhr = their_eph_pub_raw
        r._rk, r._ckr = _kdf_root(root_key, _dh(my_eph_priv, their_eph_pub_raw))
        return r

    ## Sending

    def prepare_send(self):
        """Advance the sending chain. Returns (message_key, Header). The step is committed immediately"""
        if self._destroyed:
            raise RatchetError("ratchet destroyed")
        if self._cks is None:   # responder's first message: start a sending chain with a FRESH key pair
            new_priv = crypto.generate_x25519_keypair()
            new_rk, new_cks = _kdf_root(self._rk, _dh(new_priv, self._dhr))
            _zero(self._rk)
            self._rk, self._cks = new_rk, new_cks
            self._dhs = new_priv
            self._dhs_pub = crypto.public_key_to_raw(new_priv.public_key())
            self._pn, self._ns = self._ns, 0

        mk, nxt = crypto.ratchet_step(self._cks)
        _zero(self._cks)    # old chain key is gone: previous message keys cannot be recomputed
        self._cks = nxt
        self._gen += 1
        header = Header(self._dhs_pub, self._pn, self._ns)
        self._ns += 1
        return mk, header

    ## Receiving (two-phase: nothing changes until commit() is called after successful AEAD verification)

    def prepare_receive(self, h: Header):
        """Returns (message_key, commit). Call commit() ONLY after the message authenticated correctly"""
        if self._destroyed:
            raise RatchetError("ratchet destroyed")

        key = (h.dh, h.n)
        if key in self._skipped:    # late message of a previous/current chain
            mk = self._skipped[key]
            def commit_skipped():
                self._skipped.pop(key, None)
            return mk, commit_skipped

        gen = self._gen
        # Work on copies: self is untouched until commit()
        new_skipped = {}
        temps = []  # secrets created here, zeroed if anything fails
        try:
            rk = bytearray(self._rk); temps.append(rk)
            ckr = bytearray(self._ckr) if self._ckr is not None else None
            if ckr is not None: temps.append(ckr)
            nr, dhr = self._nr, self._dhr
            new_dhs, new_dhs_pub, cks, ns, pn = self._dhs, self._dhs_pub, self._cks, self._ns, self._pn
            new_cks = None
            stepped = (h.dh != dhr)

            if stepped:     # DH ratchet step
                if ckr is not None:     # keep the keys of the old chain that the peer sent but we haven't seen yet
                    ckr, nr = _skip(ckr, nr, h.pn, dhr, new_skipped)
                rk2, ckr = _kdf_root(rk, _dh(self._dhs, h.dh)); temps += [rk2, ckr]
                nr, dhr = 0, h.dh
                # immediately start a new sending chain with a fresh key pair (old private key is dropped)
                new_dhs = crypto.generate_x25519_keypair()
                new_dhs_pub = crypto.public_key_to_raw(new_dhs.public_key())
                rk3, new_cks = _kdf_root(rk2, _dh(new_dhs, h.dh)); temps += [rk3, new_cks]
                _zero(rk2); _zero(rk)   # intermediates: not needed anymore
                rk = rk3
                pn, ns = self._ns, 0
            elif ckr is None:
                raise RatchetError("no receiving chain for this key")

            if h.n < nr:
                raise RatchetError("stale or duplicate message")
            ckr, nr = _skip(ckr, nr, h.n, dhr, new_skipped)
            mk, nxt = crypto.ratchet_step(ckr)
            _zero(ckr)
            ckr, nr = nxt, nr + 1; temps.append(ckr)

            if len(self._skipped) + len(new_skipped) > MAX_SKIPPED_KEYS:
                raise RatchetError("skipped key store full")
        except Exception:
            for t in temps:
                _zero(t)
            raise

        done = []

        def commit():
            if done:                # single use: a second call must never touch live keys
                return
            done.append(True)
            if self._destroyed:     # session died meanwhile: don't resurrect key material
                for t in temps:
                    _zero(t)
                return
            if self._gen != gen:    # state moved on since prepare_receive (e.g. a send): committing would roll
                for t in temps:     # the sending chain back and REUSE a message key -> refuse
                    _zero(t)
                raise RatchetError("stale commit: ratchet state changed since prepare_receive")
            self._gen += 1
            if stepped:
                _zero(self._cks)
                self._cks = new_cks
                self._dhs, self._dhs_pub = new_dhs, new_dhs_pub
                self._pn, self._ns = pn, ns
                self._dhr = dhr
            _zero(self._rk); self._rk = rk
            _zero(self._ckr); self._ckr = ckr
            self._nr = nr
            self._skipped.update(new_skipped)
            while len(self._skipped) > MAX_SKIPPED_KEYS:
                self._skipped.popitem(last=False)   # evict oldest
        return mk, commit

    def destroy(self):
        """Best-effort zeroing of key material (Python bytes objects cannot be wiped)"""
        self._destroyed = True
        for b in (self._rk, self._cks, self._ckr):
            _zero(b)
        self._skipped.clear()
        self._dhs = None
