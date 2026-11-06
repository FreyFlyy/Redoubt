### network.py

"""
Network module for Redoubt
"""

import os
import sys
import time
import json
import struct
import socket
import threading
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import crypto
from . import protocol as proto
from . import ratchet as ratchet_mod
from . import ratelimit
from . import secure_memory
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)


## Variables

DEFAULT_PORT = 60717    # generally considered ephemeral (to blend in), also leet speak for "GOT IT"

# Timeouts
CONNECT_TIMEOUT = 10     # socket timeout for TCP connection
WIRE_KEY_EXCHANGE_TIMEOUT = 10   # socket timeout for key exchange
HANDSHAKE_TIMEOUT = 10  # socket timeout for handshake completion

# Connection limiting
CONN_MAX_PER_IP = 5     # max number of connections an IP can have on a sliding window
CONN_WINDOW_SECONDS = 10    # sliding time window to calculate max IP connections
MAX_GLOBAL_SESSIONS = 200   # max global sessions (aggregate, for all contacts)

# Traffic size limiting
SESSION_MAX_BYTES_PER_WINDOW = 1_000_000    # max bytes received from an IP on a sliding window (1MB)
SESSION_WINDOW_SECONDS = 10     # sliding time window to calculate max bytes received (10s)
# = average of 100KB/s, plenty for 10+ msg/s and prevents DoS

# Intervals
PRESENCE_INTERVAL = 15      # seconds between PRESENCE packets to all peers
ACK_WATCHDOG_INTERVAL = 1   # seconds between scans for new online peers to send "pending" messages (i.e. sent but not received)

# Adaptive RTO - keeps both ultrafast LAN environments and cross-ocean correctly tuned
RTO_MIN = 1.0       # floor: avoids pointless retries even on sub-ms LAN RTT
RTO_MAX = 60.0      # ceiling: avoids indefinite stalls on extreme links
INITIAL_RTO = 5.0   # fallback used until the first real RTT sample is collected
RTO_BACKOFF_CAP = 6 # max doubling exponent per pending message (2^6 = 64x RTO ceiling on retries)


## Exceptions

class PeerMismatch(Exception):
    """Recieved fingerprint does not match expected one"""


## Key exchange result

@dataclass
class KeyExchange:
    """Secrets of one wire-key establishment, reused to seed the Double Ratchet"""
    wire_key: bytes
    eph_priv: object        # my ephemeral X25519 private key (becomes the initial ratchet key)
    their_eph_raw: bytes    # peer ephemeral public key (raw)
    ikm: bytes              # dh_ee || term1 || term2: depends on ephemeral secrets, NOT derivable from static keys alone


## Session class

class Session:
    def __init__(self, sock, peer_fingerprint, ratchet, wire_key):
        self.sock = sock
        self.peer_fingerprint = peer_fingerprint
        self.ratchet = ratchet    # Double Ratchet state (ALWAYS access it while holding self.lock)
        self.wire_key = wire_key    # ciphers entre binary frame
        self.seen_msg_ids = set()   # set of seen message ids, to avoid double ratchet when clearing the chat with an already seen message without the other peer getting ACK (this makes them re-transmit and waste a second step, misaligning the entire chain)
        self.sent_msg_ids = set()   # messages already encrypted/sent on this session: a concurrent flush must not waste another ratchet step on them
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()  # serializes EVERY write on the socket
        self.alive = True

        # Adaptive RTO
        self.rtt_lock = threading.Lock()
        self.srtt = None
        self.rttvar = None
        self.rto = INITIAL_RTO

        # Size limiter
        self.rate_limiter = ratelimit.ByteRateLimiter(SESSION_MAX_BYTES_PER_WINDOW, SESSION_WINDOW_SECONDS)

    def destroy(self):
        """To call every time a session is discarded / not used"""
        with self.lock:     # zero every important key in RAM (best-effort)
            self.ratchet.destroy()

    def next_send_key(self):
        """Advance the sending ratchet. Returns (message_key, ratchet.Header)."""
        with self.lock:
            return self.ratchet.prepare_send()

    def update_rtt(self, sample: float):
        """Karn/Jacobson: update the RTO estimate from a genuine RTT sample (only never-retransmitted)"""
        with self.rtt_lock:
            if self.srtt is None:
                self.srtt = sample
                self.rttvar = sample / 2
            else:
                self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
                self.srtt = 0.875 * self.srtt + 0.125 * sample
            self.rto = min(RTO_MAX, max(RTO_MIN, self.srtt + 4 * self.rttvar))

    def current_rto(self) -> float:
        """Current retransmission timeout estimate for this session"""
        with self.rtt_lock:
            return self.rto

    def send(self, packet: dict):
        """
        Only point to use when writing on the socket. Includes opaque binary framing
        (JSON -> AES-256-GCM with session wire_key -> [length][nonce][ciphertext])
        Caller is responsible of adding padding before send()
        """
        data = proto.frame(packet, self.wire_key)
        with self.send_lock:
            self.sock.sendall(data)


## NetworkManager class

class NetworkManager:
    def __init__(self, identity, storage, on_message=None, on_status=None, on_statusbar_message=None, on_ack=None):
        self.identity = identity
        self.storage = storage
        self.on_message = on_message or (lambda *a, **k: None)
        self.on_status = on_status or (lambda *a, **k: None)
        self.on_statusbar_message = on_statusbar_message or (lambda *a, **k: None)
        self.on_ack = on_ack or (lambda *a, **k: None)

        self.sessions: dict[str, Session] = {}
        self.sessions_lock = threading.Lock()

        self._listener_sock = None
        self._stop = threading.Event()
        self.listen_port = None  # set by start_listener()

        self.peer_presence = {}

        # Presence fan-out (fire-and-forget): contacts with a presence attempt still running, shutdown flag
        self._presence_inflight: set = set()
        self._presence_inflight_lock = threading.Lock()
        self._closing = threading.Event()

        # Outbox flushing
        self._flush_locks: dict = {}
        self._flush_locks_guard = threading.Lock()

        # Pending messages
        self.pending_acks: dict = {}
        self.pending_acks_lock = threading.Lock()

        # Limiting guards
        self._conn_flood_guard = ratelimit.ConnectionFloodGuard(CONN_MAX_PER_IP, CONN_WINDOW_SECONDS)
        self._session_cap = ratelimit.GlobalSessionCap(MAX_GLOBAL_SESSIONS)


    ## Get & connect

    def _get_or_connect(self, contact_row) -> Session:
        """Connect to a contact and return the session"""
        # Get contact info
        fp, _name, ip, port, pubkey_b64 = contact_row

        # Get session if already existing
        with self.sessions_lock:
            existing = self.sessions.get(fp)
            if existing and existing.alive:
                return existing

        # Get contact raw PubKey
        candidate_static_pub_raw = None
        try:
            candidate_static_pub_raw = proto.unb64(pubkey_b64)
        except Exception:
            candidate_static_pub_raw = None
            logger.warning(f"Contact PubKey not valid base64 ({fp[:16]}...)")

        # Try connecting to contact IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        try:
            sock.connect((ip, port))
        except Exception as e:
            sock.close()
            if isinstance(e, ConnectionRefusedError):   # refused = peer offline (normal); type check, not str(): Windows messages are localized
                pass    # do nothing
            else:
                self.on_statusbar_message(fp, f"Connection to {ip}:{port} failed: {e}")
            raise
        sock.settimeout(None)

        # Try handshake
        try:
            their_fp, _their_name, ratchet, _their_listen_port, wire_key = self._do_handshake_outbound(sock, candidate_static_pub_raw)
        except Exception:
            sock.close()
            raise
        if their_fp != fp:  # Fingerprint mismatch
            sock.close()
            raise PeerMismatch(f"Expected {fp[:16]}..., got {their_fp[:16]}...")

        # Define and install session
        session = Session(sock, fp, ratchet, wire_key)
        discarded = self._install_session(fp, session, is_inbound=False)
        if discarded:   # new session was discarded (old still alive)
            with self.sessions_lock:    # get old session
                existing = self.sessions.get(fp)
            if existing is not None and existing.alive:
                return existing
            # if no other session is alive, raise exception
            raise RuntimeError(f"Session for {fp[:16]}... discarded (tie-break or contact revoked), and no other session can be found")

        self._flush_if_online(fp)   # flush outbox if online
        threading.Thread(target=self._read_loop, args=(session, ip), daemon=True).start()

        return session


    ## Listen

    def start_listener(self, port=DEFAULT_PORT):
        """Start socket listener on a specific port and thread"""
        self.listen_port = port
        self._listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sys.platform == "win32":
            # On Windows SO_REUSEADDR lets ANOTHER process bind the same port (traffic hijack); exclusive bind is the safe equivalent
            self._listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            self._listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener_sock.bind(("0.0.0.0", port))
        self._listener_sock.listen(20)
        self._listener_sock.settimeout(1.0)

        t = threading.Thread(target=self._listen_loop, daemon=True)
        t.start()
        return t

    def _listen_loop(self):
        """Loop for socket connection listening"""
        while not self._stop.is_set():   # not stopped
            if self._listener_sock is None:
                break
            try:    # try accepting any connection
                conn, addr = self._listener_sock.accept()
            except TimeoutError:  # no connection tried. Not a problem, restart
                continue
            except (ConnectionAbortedError, ConnectionResetError):  # peer gone before accept(): not fatal (common on Windows, ECONNABORTED on Linux)
                continue
            except OSError:
                logger.exception("OS error in _listen_loop: conn, addr = self._listener_sock.accept()")
                break

            # Per-IP connection flood protection
            if not self._conn_flood_guard.allow(addr[0]):
                logger.warning(f"Connection flood protection: too many tried connections from {addr[0]}, new connection dropped")
                try:    # close connection
                    conn.close()
                except OSError:
                    pass
                continue

            # Global session flood protection
            with self.sessions_lock:
                current = len(self.sessions)
            if not self._session_cap.allow(current):
                logger.warning(f"Global session cap ({MAX_GLOBAL_SESSIONS}) reached, inbound from {addr[0]} dropped pre-handshake")
                try:
                    conn.close()
                except OSError:
                    pass
                continue

            threading.Thread(target=self._handle_inbound, args=(conn, addr), daemon=True).start()


    ## Wire key

    def _establish_wire_key_candidates(self, sock, candidate_pubkeys_raw: list[bytes]):
        """
        Like _establish_wire_key, but it calculates a KeyExchange for all possible contacts
        (e.g. in the case of duplicated IPs with LANs). Returns (fingerprint, KeyExchange)
        pairs: decrypting with one of these only proves someone KNOWN completed the
        handshake, not WHICH known contact. Callers must bind the fingerprint that
        actually wins to whatever identity the HELLO payload later claims.
        """
        if not candidate_pubkeys_raw:
            raise PeerMismatch("Cannot establish authenticated wire key: no peer PubKey available")

        # Generate and send ephemeral PubKey
        eph_priv = crypto.generate_x25519_keypair()
        eph_pub_raw = crypto.public_key_to_raw(eph_priv.public_key())
        sock.sendall(eph_pub_raw)

        # Get peer PubKey
        their_eph_raw = proto.recv_exact(sock, 32, timeout=WIRE_KEY_EXCHANGE_TIMEOUT)
        if their_eph_raw is None:
            raise proto.InvalidPacket("Wire key exchange timeout")
        their_eph_pub = crypto.public_key_from_raw(their_eph_raw)

        # Calculate eph-eph and static-eph shared secrets
        dh_ee = crypto.x25519_shared_secret(eph_priv, their_eph_pub)
        dh_se = crypto.x25519_shared_secret(self.identity.private_key, their_eph_pub)

        candidates = []
        for cand_raw in candidate_pubkeys_raw:
            try:
                peer_static_pub = crypto.public_key_from_raw(cand_raw)
            except Exception:
                logger.exception("Can't derive candidate PubKey from raw bytes")
                continue
            # Compute last shared secret
            dh_es = crypto.x25519_shared_secret(eph_priv, peer_static_pub)

            wire_key = crypto.derive_wire_key(dh_ee, dh_es, dh_se)
            candidates.append((crypto.fingerprint_of(cand_raw), KeyExchange(wire_key, eph_priv, their_eph_raw, dh_ee + dh_es + dh_se)))

        return candidates

    def _read_packet_multi_key(self, sock, candidates: list[tuple[str, KeyExchange]]):
        """
        Like proto.read_packet but tries more (fingerprint, wire_key) candidates on the
        same frame. Returns (packet, KeyExchange, authenticated_fp): authenticated_fp is the
        fingerprint of the SPECIFIC candidate whose static key produced the decrypting
        wire key. This is the cryptographically proven identity of the sender, callers
        MUST check it against whatever identity the packet itself later claims, never
        trust the packet's own fields alone.
        """
        raw_len = proto.recv_exact(sock, 4)
        if raw_len is None: # no lenght
            return None

        length = struct.unpack(">I", raw_len)[0]
        if length > proto.MAX_FRAME_SIZE:
            raise proto.InvalidPacket("Packet exceeds the maximum allowed size")

        raw = proto.recv_exact(sock, length, timeout=HANDSHAKE_TIMEOUT)
        if raw is None:
            return None
        if len(raw) < proto.WIRE_NONCE_SIZE:
            raise proto.InvalidPacket("Frame is too short")

        nonce, ciphertext = raw[:proto.WIRE_NONCE_SIZE], raw[proto.WIRE_NONCE_SIZE:]

        for fp, kx in candidates:
            wk = kx.wire_key
            try:    # try decrypting with a candidate wire key
                data = AESGCM(wk).decrypt(nonce, ciphertext, None)
                packet = json.loads(data.decode("utf-8"))
                proto.validate_packet(packet)
            except Exception:
                continue  # wrong candidate, not an error, no logging
            return packet, kx, fp   # found

        raise proto.InvalidPacket("No candidate key could decrypt HELLO (unknown sender or IP not recognized)")

    def _establish_wire_key(self, sock, candidate_static_pub_raw: bytes, is_initiator: bool):
        """
        Establishes an authenticated wire key and returns a KeyExchange (wire key + ephemeral secrets for the ratchet).
        Requires both peers have eachother's Public Keys.
        Otherwise will raise PeerMismatch
        """

        if candidate_static_pub_raw is None:    # no key passed
            raise PeerMismatch("Cannot establish authenticated wire key: no peer PubKey available")

        # Generate ephemeral X25519 keypair
        eph_priv = crypto.generate_x25519_keypair()
        eph_pub_raw = crypto.public_key_to_raw(eph_priv.public_key())

        # Send raw PubKey
        sock.sendall(eph_pub_raw)

        # Receive peer ephemeral key
        their_eph_raw = proto.recv_exact(sock, 32, timeout=WIRE_KEY_EXCHANGE_TIMEOUT)

        if their_eph_raw is None:   # timeout, 32 bytes not received
            raise proto.InvalidPacket("wire key exchange timeout")

        their_eph_pub = crypto.public_key_from_raw(their_eph_raw)

        # Calculation of 1st shared secret (MyEphPriv × TheirEphPub)
        dh_ee = crypto.x25519_shared_secret(eph_priv, their_eph_pub)

        # Calculation of 2nd shared secret (MyStaticPriv × TheirEphPub)
        dh_se = crypto.x25519_shared_secret(self.identity.private_key, their_eph_pub)

        # Get TheirPubKey
        peer_static_pub = crypto.public_key_from_raw(candidate_static_pub_raw)

        # Calculation of 3rd shared secret (MyEphPriv × TheirStaticPub)
        dh_es = crypto.x25519_shared_secret(eph_priv, peer_static_pub)

        # Deterministic ordering
        if is_initiator:
            term1 = dh_se
            term2 = dh_es
        else:
            term1 = dh_es
            term2 = dh_se

        # Get final wire key
        wire_key = crypto.derive_wire_key(dh_ee, term1, term2)

        return KeyExchange(wire_key, eph_priv, their_eph_raw, dh_ee + term1 + term2)


    ## Handshake

    def _do_handshake_outbound(self, sock, candidate_static_pub_raw: bytes):
        """Prepare and initiate handshake"""
        # Establish wire key
        kx = self._establish_wire_key(sock, candidate_static_pub_raw, is_initiator=True)
        wire_key = kx.wire_key

        nonce_mine = os.urandom(16)

        # Build hello
        hello = proto.build_hello(
            "HELLO",
            self.identity.public_key_raw,
            self.identity.fingerprint,
            nonce_mine,
            self.identity.name_short_fp,
            self.listen_port,
        )

        sock.sendall(proto.frame(proto.add_padding(hello), wire_key))

        # Try to receive HELLO_ACK
        sock.settimeout(HANDSHAKE_TIMEOUT)
        try:
            ack, _ = proto.read_packet(sock, wire_key)
        finally:
            sock.settimeout(None)

        if ack is None:
            raise proto.InvalidPacket(
                "Failed Handshake: HELLO_ACK missing"
            )
        elif ack["type"] != "HELLO_ACK":
            raise proto.InvalidPacket(
                "Failed Handshake: peer did not HELLO_ACK"
            )

        # Check contact exists
        if self.storage.get_contact(ack["fingerprint"]) is None:
            raise PeerMismatch(
                f"Peer is not in the contact list: {ack["fingerprint"][:16]}..."
            )

        return self._finalize_handshake(ack, nonce_mine, kx, is_initiator=True) + (wire_key,)

    def _do_handshake_inbound(self, sock, addr):
        """Prepare to receive handshake"""
        candidates = self.storage.get_contact_by_ip(addr[0])
        candidate_pubkeys = []
        for row in candidates:
            try:
                candidate_pubkeys.append(proto.unb64(row[4]))
            except Exception:
                logger.exception(f"Stored public key for {addr[0]} is invalid")

        # Establish every possible candidate wire key
        candidates = self._establish_wire_key_candidates(sock, candidate_pubkeys)

        sock.settimeout(HANDSHAKE_TIMEOUT)
        try:
            result = self._read_packet_multi_key(sock, candidates)
        finally:
            sock.settimeout(None)

        if result is None:
            raise proto.InvalidPacket("Failed Handshake: HELLO missing")
        hello, kx, authenticated_fp = result
        wire_key = kx.wire_key

        if hello["type"] != "HELLO":
            raise proto.InvalidPacket("Failed Handshake: peer did not HELLO")

        # FP Cross-check (claimed vs "won" candidate)
        if hello["fingerprint"] != authenticated_fp:
            raise PeerMismatch(
                f"HELLO claims fingerprint {hello['fingerprint'][:16]}... but the wire "
                f"key was authenticated by {authenticated_fp[:16]}..., refusing"
            )

        if self.storage.get_contact(hello["fingerprint"]) is None:
            raise PeerMismatch(f"Peer is not in the contact list: {hello['fingerprint'][:16]}...")

        # Build and send HELLO_ACK
        nonce_mine = os.urandom(16)
        ack = proto.build_hello(
            "HELLO_ACK", self.identity.public_key_raw, self.identity.fingerprint,
            nonce_mine, self.identity.name_short_fp, self.listen_port,
        )
        sock.sendall(proto.frame(proto.add_padding(ack), wire_key))

        return self._finalize_handshake(hello, nonce_mine, kx, is_initiator=False) + (wire_key,)

    def _finalize_handshake(self, their_packet, my_nonce, kx: KeyExchange, is_initiator: bool):
        """Finalize handshake: derive the root key and build the Double Ratchet"""

        their_pub_raw = proto.unb64(their_packet["identity_pub"])
        their_fp = their_packet["fingerprint"]

        # Fingerprint/PubKey check
        if crypto.fingerprint_of(their_pub_raw) != their_fp:
            raise proto.InvalidPacket(
                f"Fingerprint/pubkey mismatch for {their_fp[:16]}"
            )

        # Check contact exists
        if self.storage.get_contact(their_fp) is None:
            raise PeerMismatch("Fingerprint was not found in contacts")

        # Order nonces deterministically
        their_nonce = proto.unb64(their_packet["session_nonce"])
        nonce_a, nonce_b = sorted(
            [my_nonce, their_nonce]
        )

        # Root key from the SAME secrets as the wire key (ephemeral-ephemeral + both static-ephemeral DHs):
        # a stolen static identity key alone is NOT enough to recompute it (the ephemeral private keys are not stored)
        root = crypto.derive_root_key(kx.ikm, nonce_a, nonce_b)

        if is_initiator:
            ratchet = ratchet_mod.DoubleRatchet.initiator(root, kx.eph_priv, kx.their_eph_raw)
        else:
            ratchet = ratchet_mod.DoubleRatchet.responder(root, kx.eph_priv, kx.their_eph_raw)

        return (their_fp, their_packet.get("name", their_fp[:16]), ratchet, their_packet["listen_port"])

    def _flush_if_online(self, contact_fingerprint: str):
        """To only use when we know a peer is online (flushes "pending messages" outbox)"""
        if self.storage.has_pending(contact_fingerprint):
            threading.Thread(target=self._flush_outbox_for, args=(contact_fingerprint,), daemon=True).start()


    ## Presence

    def send_presence(self, contact, status, connect=True):
        """
        Send presence to a specific contact (fire-and-forget: no reply is awaited).
        connect=False only uses an already-live session: nothing is opened, nothing can block on a handshake
        """
        try:
            if connect:
                session = self._get_or_connect(contact)
            else:
                with self.sessions_lock:
                    session = self.sessions.get(contact[0])
                if session is None or not session.alive:
                    return

            # Create packet and send
            packet = proto.build_presence(
                "PRESENCE",
                self.identity.fingerprint,
                status
            )

            session.send(proto.add_padding(packet))

        except Exception:   # if can't connect, mark offline
            if connect:
                self.on_status(contact[0], "offline")

    def _presence_task(self, contact, status, connect, owns_inflight=True):
        """Worker of broadcast_presence (one thread per contact)"""
        try:
            if status == "online" and self._closing.is_set():
                return  # never announce "online" after shutdown began
            self.send_presence(contact, status, connect=connect)
        finally:
            if owns_inflight:   # an offline send may run alongside an already in-flight online attempt
                with self._presence_inflight_lock:
                    self._presence_inflight.discard(contact[0])

    def broadcast_presence(self, status, wait=None):
        """
        Send presence to all contacts in PARALLEL, one thread per contact, treating packets as fire-and-forget
        (like UDP: a slow/unreachable peer never delays the others nor the caller).
        - "online": may open new sessions. A contact whose previous attempt is still running is skipped (no thread pile-up)
        - "offline": only uses already-live sessions (a new handshake just to say goodbye is useless)
        wait=None returns immediately; wait=<seconds> joins workers up to that GLOBAL deadline (shutdown use)
        """
        connect = (status != "offline")
        if not connect:
            self._closing.set()

        workers = []
        for contact in self.storage.list_contacts():
            fp = contact[0]
            with self._presence_inflight_lock:
                already_inflight = fp in self._presence_inflight
                if already_inflight and connect:
                    continue    # only "online" dials: never pile up a second attempt
                if not already_inflight:
                    self._presence_inflight.add(fp)
            # "offline" must still reach live peers even if an "online" broadcast is in flight for them
            t = threading.Thread(target=self._presence_task,
                                 args=(contact, status, connect, not already_inflight), daemon=True)
            t.start()
            workers.append(t)

        if wait is not None:
            deadline = time.monotonic() + wait
            for t in workers:
                t.join(max(0.0, deadline - time.monotonic()))

    def _presence_loop(self):
        """Loop to regularly send presence packets to all peers"""
        time.sleep(1) # wait for listener at first broadcast

        try:    # send inital presence to all contacts
            self.broadcast_presence("online")
        except Exception:
            logger.exception("Initial broadcast_presence failed")

        while not self._stop.is_set():  # if network is still up
            time.sleep(PRESENCE_INTERVAL)   # wait some time before another presence
            try:    # send periodical preence to all contacts
                self.broadcast_presence("online")
            except Exception:
                logger.exception("Periodical broadcast_presence failed")

    def start_presence_worker(self):
        """Start worker to regularly send presence packets to all peers"""
        t = threading.Thread(
            target=self._presence_loop,
            daemon=True
        )
        t.start()
        return t

    def _handle_presence(self, session, packet, reply=True):
        """Handle presence response to inform the peer of our presence by acknowledging its PRESENCE packet"""

        if packet["sender"] != session.peer_fingerprint:    # session fingerprint doesn't match sender's fingerprint
            self.on_statusbar_message(packet["sender"], f"Presence mismatch: expected {session.peer_fingerprint[:16]}")
            return

        fp = session.peer_fingerprint

        # Save presence
        self.peer_presence[fp] = time.time()
        self.on_status(fp, packet["status"])

        if packet["status"] == "online":    # if online, send all pending messages
            self._flush_if_online(fp)

            if reply:   # if reply=True (i.e a PRESENCE packet), send back a PRESENCE_ACK
                try:
                    ack = proto.build_presence("PRESENCE_ACK", self.identity.fingerprint, "online")
                    session.send(proto.add_padding(ack))
                except OSError:
                    logger.exception("OS error in _handle_presence: session.send(proto.add_padding(ack))")


    ## Session management

    def _install_session(self, fp: str, new_session: "Session", is_inbound: bool) -> bool:
        """
        Register new_session as the current session for fp.
        If a live session already exists for fp, a deterministic tie-break is required:
        the peer with the lexicographically greater fingerprint always keeps its OUTBOUND
        connection, while the peer with the lexicographically smaller
        fingerprint always keeps its INBOUND connection.
        Returns True if the NEW session was discarded (the caller must not start
        its read_loop, as the session has already been closed).
        """
        # Calculate my preference
        i_prefer_inbound = self.identity.fingerprint < fp
        new_is_preferred = (is_inbound == i_prefer_inbound)

        with self.sessions_lock:
            # Get old session
            old = self.sessions.get(fp)
            old_is_alive = old is not None and old is not new_session and old.alive
            # If the contact was revoked while the handshake was running: never install (pairs with drop_contact())
            if self.storage.get_contact(fp) is None:
                to_close = new_session
                new_was_discarded = True
                logger.warning(f"Contact {fp[:16]}... no longer in contacts (revoked?), discarding new session")
            # If alive and don't need another session
            elif old_is_alive and not new_is_preferred:
                to_close = new_session
                new_was_discarded = True
            # If not alive and doesn't allow anymore sessions (cap)
            elif not old_is_alive and fp not in self.sessions and not self._session_cap.allow(len(self.sessions)):
                to_close = new_session
                new_was_discarded = True
                logger.warning(f"Global session cap ({MAX_GLOBAL_SESSIONS}) reached, discarding session for {fp[:16]}...")
            else:
                self.sessions[fp] = new_session
                to_close = old if old_is_alive else None
                new_was_discarded = False

        if to_close is not None:    # if we need to close some session
            to_close.alive = False
            to_close.destroy()
            try:    # send close-old-session request packet
                to_close.send(proto.add_padding(proto.build_close(self.identity.fingerprint)))
            except OSError:
                logger.exception("OS error in _install_session: to_close.send(proto.frame(proto.build_close(self.identity.fingerprint)))")
            try:    # close session
                to_close.sock.close()
            except OSError:
                logger.exception("OS error in _install_session: to_close.sock.close()")

        return new_was_discarded


    ## Contact revocation

    def drop_contact(self, contact_fingerprint: str):
        """
        Forget a contact at runtime: kill its live session, wipe its Double Ratchet and discard its in-RAM state.
        Meant to be called by the UI AFTER the contact was deleted from storage (delete -> drop -> delete again):
        once the row is gone no handshake can succeed anymore (see _install_session), and the second delete
        removes whatever in-flight threads stored between the first delete and this call.
        Safe to call from any thread. Never blocks for long (socket timeout capped at 1s).
        """
        fp = contact_fingerprint

        with self.sessions_lock:
            session = self.sessions.pop(fp, None)

        if session is not None:
            session.alive = False
            session.destroy()   # zero ratchet key material (best-effort)
            try:    # best-effort goodbye, short timeout: we may be on the UI thread
                session.sock.settimeout(1.0)
                session.send(proto.add_padding(proto.build_close(self.identity.fingerprint)))
            except OSError:
                logger.warning(f"Could not send CLOSE to revoked contact {fp[:16]}...")
            try:    # also unblocks the session's _read_loop thread, which then exits by itself
                session.sock.close()
            except OSError:
                logger.warning(f"OS error closing socket of revoked contact {fp[:16]}...")

        with self.pending_acks_lock:    # no more retransmissions for this contact
            for mid in [m for m, e in self.pending_acks.items() if e["contact_fingerprint"] == fp]:
                del self.pending_acks[mid]

        with self._flush_locks_guard:
            self._flush_locks.pop(fp, None)

        self.peer_presence.pop(fp, None)


    ## Read & inbound

    def _handle_inbound(self, sock, addr):
        """Handle inbound traffic and sessions"""
        try:    # try getting inbound handshake
            their_fp, _their_name, ratchet, _their_listen_port, wire_key = self._do_handshake_inbound(sock, addr)
        except (proto.InvalidPacket, OSError) as e:
            self.on_statusbar_message("?", f"Failed handshake from {addr[0]}: {e}")
            sock.close()
            return
        except Exception as e:
            logger.exception(f"Unexpected error during inbound handshake from {addr[0]}: {e}")
            self.on_statusbar_message("?", f"Unexpected error handling {addr[0]}: {e}")
            try:
                sock.close()
            except OSError:
                pass
            return

        # Get contact from fingerprint
        contact = self.storage.get_contact(their_fp)
        if contact is None:
            self.on_statusbar_message(their_fp, "Tried handshake but not in contact list")

        # Install session (new if neeeded)
        session = Session(sock, their_fp, ratchet, wire_key)
        discarded = self._install_session(their_fp, session, is_inbound=True)
        if discarded:   # old session is mantained
            return
        # Set as online, send pending messages and read
        self.on_status(their_fp, "online")
        self._flush_if_online(their_fp)
        self._read_loop(session, addr[0])

    def _handle_incoming_message(self, session: Session, packet: dict, peer_ip: str):
        """Handle incoming packets, specifically messages"""
        if packet["sender"] != session.peer_fingerprint:
            self.on_statusbar_message(packet["sender"], f"Sender mismatch: expected {session.peer_fingerprint[:16]}")
            return

        msg_id = packet["id"]

        if self.storage.message_exists(msg_id) or msg_id in session.seen_msg_ids:   # if already seen but retransmitted (e.g. lost MESSAGE_ACK)
            try:    # ack but don't re-read
                session.send(proto.add_padding(proto.build_message_ack(msg_id, self.identity.fingerprint)))
            except OSError:
                logger.exception("OS error in _handle_incoming_message: session.send(proto.add_padding(proto.build_message_ack(msg_id, self.identity.fingerprint)))")
            return

        header = ratchet_mod.Header(proto.unb64(packet["dh"]), packet["pn"], packet["chain_index"])
        aad = proto.message_aad(packet)

        # prepare -> decrypt -> commit under the session lock: the receive step can also change the SENDING chain
        # (DH step), so it must not interleave with next_send_key()
        with session.lock:
            if not session.alive:
                return
            try:    # candidate step(s), not yet committed
                mk, commit = session.ratchet.prepare_receive(header)
            except ratchet_mod.RatchetError as e:
                self.on_statusbar_message(session.peer_fingerprint, "chain desync beyond recovery, session closed")
                logger.warning(f"Ratchet error from {session.peer_fingerprint[:16]}...: {e} (chain_index {packet['chain_index']}), killing session")
                session.alive = False   # force a clean reconnect/re-handshake instead of stalling forever
                return

            try:    # try decrypting
                plaintext = crypto.decrypt_message(mk, proto.unb64(packet["nonce"]), proto.unb64(packet["ciphertext"]), aad)
            except Exception:   # unable, could be corrupted or modified: ratchet state is untouched
                self.on_statusbar_message(session.peer_fingerprint, "cannot decipher message, dropped")
                logger.exception(f"Cannot decipher message from {session.peer_fingerprint[:16]}..., dropped")
                return

            try:
                commit()    # decrypted successfully: NOW advance the ratchet for real
            except ratchet_mod.RatchetError as e:   # cannot happen while the session lock is held; fail closed anyway
                logger.error(f"Ratchet commit refused for {session.peer_fingerprint[:16]}...: {e}, killing session")
                session.alive = False
                return

        session.seen_msg_ids.add(msg_id)    # only mark seen once actually decrypted, so a failed attempt can be retried

        # Store message and put in UI the recieval
        self.storage.store_message(msg_id, session.peer_fingerprint, "in", packet["timestamp"], plaintext, peer_ip, unreceived=1)
        self.on_message(session.peer_fingerprint, plaintext, packet["timestamp"])

        try:    # send message ACK
            session.send(proto.add_padding(proto.build_message_ack(msg_id, self.identity.fingerprint)))
        except OSError:
            logger.exception("OS error in _handle_incoming_message: session.send(proto.add_padding(proto.build_message_ack(msg_id, self.identity.fingerprint)))")

    def _read_loop(self, session: Session, peer_ip: str):
        """Reading loop for a session"""
        while session.alive and not self._stop.is_set():    # alive session
            try:    # read any packet
                packet, frame_len = proto.read_packet(session.sock, session.wire_key)
            except proto.InvalidPacket:
                break  # drop invalid packet, break reading loop
            except OSError:
                logger.exception("OS error in _read_loop: packet = proto.read_packet(session.sock)")
                break

            if packet is None:  # no packet even without timeout, break loop
                break

            # Rate limit exceeded (bytes/timeframe)
            if not session.rate_limiter.allow(frame_len):
                logger.warning(f"Rate limit exceeded by {session.peer_fingerprint[:16]}..., packet type {packet['type']} dropped")
                continue

            if packet["type"] == "MESSAGE": # message, handle with function
                self._handle_incoming_message(session, packet, peer_ip)
            elif packet["type"] == "MESSAGE_ACK":   # ack to message, pop from pending and delete from outbox
                if packet["sender"] != session.peer_fingerprint:    # corrupted or MITM
                    continue
                self.on_statusbar_message(session.peer_fingerprint, f"ack:{packet['id']}")
                with self.pending_acks_lock:
                    entry = self.pending_acks.pop(packet["id"], None)
                if entry is not None and entry["retries"] == 0:    # Karn: only sample RTT from sends that were never retransmitted (unambiguous timing)
                    session.update_rtt(time.time() - entry["sent_at"])
                self.storage.delete_outbox(packet["id"])
                self.on_ack(session.peer_fingerprint, packet["id"])
            elif packet["type"] == "CLOSE": # close session
                if packet["sender"] != session.peer_fingerprint:    # corrupted or MITM
                    continue
                break
            elif packet["type"] == "PRESENCE":  # presence, reply with PRESENCE_ACK
                self._handle_presence(session, packet, reply=True)
            elif packet["type"] == "PRESENCE_ACK":  # presence ack, set online
                self._handle_presence(session, packet, reply=False)

        # If session isn't alive, end all sessions with peer and set peer as offline
        session.alive = False
        session.destroy()
        with self.sessions_lock:
            if self.sessions.get(session.peer_fingerprint) is session:
                del self.sessions[session.peer_fingerprint]
        self.on_status(session.peer_fingerprint, "offline")

        try:
            session.sock.close()
        except OSError:
            logger.exception("OS error in _read_loop: session.sock.close()")


    # Send & outbound (TODO)

    def send_text(self, contact_fingerprint: str, text: str, msg_id: str | None = None) -> str:
        """
        Sends text to a peer enqueuing the message in outbox and attempts delivery on a dedicated thread
        If the peer is offline, the message remains pending and will be retried by the background worker.
        """
        if msg_id is None:  # generate new message id if not present
            msg_id = proto.new_message_id()
        self.storage.enqueue_outbox(msg_id, contact_fingerprint, text)
        threading.Thread(target=self._flush_outbox_for, args=(contact_fingerprint,), daemon=True).start()
        return msg_id

    def _get_flush_lock(self, contact_fingerprint: str) -> threading.Lock:
        """Get lock to flush outbox"""
        with self._flush_locks_guard:
            lock = self._flush_locks.get(contact_fingerprint)
            if lock is None:
                lock = threading.Lock()
                self._flush_locks[contact_fingerprint] = lock
            return lock

    def _flush_outbox_for(self, contact_fingerprint: str):
        """Flush outbox with an acquired lock"""
        lock = self._get_flush_lock(contact_fingerprint)
        acquired = lock.acquire(timeout=CONNECT_TIMEOUT + 10)
        if not acquired:
            self.on_statusbar_message(contact_fingerprint, "Failed to flush outbox, lock is too busy. The worker will retry later")
            return
        try:
            self._flush_outbox_for_locked(contact_fingerprint)
        finally:
            lock.release()

    def _flush_outbox_for_locked(self, contact_fingerprint: str):
        """Flush outbox for a specific contact"""
        contact = self.storage.get_contact(contact_fingerprint)
        if contact is None:
            self.on_statusbar_message(contact_fingerprint, "Flushing failed: unknown contact")
            logger.warning(f"Flushing for unknown contact: {contact_fingerprint[:16]}...")
            return

        try:    # connect first
            session = self._get_or_connect(contact)
        except Exception as e:
            self.on_statusbar_message(contact[0], f"Failed connection: {e}")
            return

        for msg_id, text in self.storage.pending_for(contact_fingerprint):   # for every pending message
            # Already sent on this live session: leave any retry to the ACK watchdog, which reuses the original
            # key/chain_index. Checking this also closes the race with a fast ACK that clears pending_acks
            # while the outbox row is not deleted yet (without it the message would be re-encrypted).
            if msg_id in session.sent_msg_ids:
                continue
            with self.pending_acks_lock:
                existing = self.pending_acks.get(msg_id)
            if existing is not None and existing["session"] is session and existing["session"].alive:
                continue

            # Get ts and send key
            timestamp = proto.now_ms()
            try:
                mk, header = session.next_send_key()
            except ratchet_mod.RatchetError:    # session destroyed under us (peer closed / shutdown): message stays in the outbox
                session.alive = False
                break
            # Construct packet
            partial = {"type": "MESSAGE", "id": msg_id, "sender": self.identity.fingerprint, "timestamp": timestamp,
                       "chain_index": header.n, "dh": proto.b64(header.dh), "pn": header.pn}
            aad = proto.message_aad(partial)
            nonce, ct = crypto.encrypt_message(mk, text, aad)
            packet = proto.build_message(msg_id, self.identity.fingerprint, timestamp, nonce, ct, header.n, header.dh, header.pn)
            packet = proto.add_padding(packet)
            try:    # try to send packet and store
                session.sent_msg_ids.add(msg_id)    # set before send so no concurrent flush can encrypt it again
                session.send(packet)
                self.storage.store_message(msg_id, contact_fingerprint, "out", timestamp, text)

                with self.pending_acks_lock:    # append to pending acks before confirm
                    self.pending_acks[msg_id] = {
                        "contact_fingerprint": contact_fingerprint,
                        "packet": packet,
                        "sent_at": time.time(),
                        "session": session,
                        "retries": 0,
                    }

            except OSError as e:
                session.sent_msg_ids.discard(msg_id)    # not sent after all: a future session may retry it
                self.on_statusbar_message(contact_fingerprint, f"OS Error: sending message failed: {e}")
                logger.warning(f"OS Error: sending message to {contact_fingerprint[:16]}... failed: {e}")
                self.storage.bump_attempts(msg_id)
                session.alive = False
                break


    ## ACK watchdog

    def _requeue_unacked(self, msg_id: str, contact_fingerprint: str):
        """To use when session dies when waiting for an ACK. Re-appends it to pending_acks"""
        with self.pending_acks_lock:
            self.pending_acks.pop(msg_id, None)
        self.on_statusbar_message(contact_fingerprint, "connection lost waiting for message ack: message back in pending_acks")

    def _ack_watchdog_loop(self):
        """Loop for message ack watchdog. Uses each session's adaptive RTO"""
        while not self._stop.is_set():  # if not stopped
            now = time.time()
            with self.pending_acks_lock:    # define "due" packets as ones without acks sent more than this session's backed-off RTO ago
                due = [
                    (mid, dict(entry)) for mid, entry in self.pending_acks.items()
                    if now - entry["sent_at"] >= entry["session"].current_rto() * (2 ** min(entry["retries"], RTO_BACKOFF_CAP))
                ]

            for mid, entry in due:  # for every message to send again
                session = entry["session"]
                if not session.alive:   # session dies
                    self._requeue_unacked(mid, entry["contact_fingerprint"])
                    continue
                try:    # send SAME EXACT packet (same nonce, same key, same chain_index...) to avoid wasting ratchet steps and possibly misaligning the chains
                    session.send(entry["packet"])
                    with self.pending_acks_lock:
                        if mid in self.pending_acks:    # edit last sent timestamp and retries
                            self.pending_acks[mid]["sent_at"] = time.time()
                            self.pending_acks[mid]["retries"] += 1
                    self.on_statusbar_message(entry["contact_fingerprint"], f"message not confirmed (rto={session.current_rto():.2f}s), re-sent (try {entry['retries'] + 1})")
                except OSError as e:
                    logger.warning(f"OS Error: retry for message {mid} failed: {e}")
                    session.alive = False
                    self._requeue_unacked(mid, entry["contact_fingerprint"])

            time.sleep(ACK_WATCHDOG_INTERVAL)   # wait before re-scanning

    def start_ack_watchdog(self):
        """Watchdog for resending non-ACKed messages"""
        t = threading.Thread(target=self._ack_watchdog_loop, daemon=True)
        t.start()
        return t

    def stop(self):
        """Stop all network activity"""
        self._stop.set()
        if self._listener_sock: # close sock
            try:
                self._listener_sock.close()
            except OSError:
                logger.exception("OS Error: self._listener_sock.close()")
                pass

        with self.sessions_lock:    # kill and destroy all sessions
            for s in self.sessions.values():
                s.alive = False
                s.destroy()
                try:
                    s.sock.close()
                except OSError:
                    logger.exception("OS Error: s.sock.close()")
