# Architecture

Internals referenced from the main [README](./README.md#threat-model): layers, identity, trust model, protocol, message cryptography, storage, rate limiting, operational parameters, secure memory. Verified line by line against `app.py`, `crypto.py`, `identity.py`, `network.py`, `protocol.py`, `ratelimit.py`, `secure_memory.py`, `storage.py`, `ui.py`. Describes only actually implemented behavior, not planned design (that belongs in the README's [Roadmap](./README.md#roadmap)).

---

## Layered architecture

```
┌─────────────────────────────────────────┐
│  UI (Textual)                             │  ui.py
├─────────────────────────────────────────┤
│  Application layer: contacts, outbox,    │  network.py, app.py
│  presence, retry/ACK                      │
├─────────────────────────────────────────┤
│  Message layer: symmetric ratchet,       │  crypto.py, protocol.py
│  AES-256-GCM per message + AAD            │
├─────────────────────────────────────────┤
│  Wire layer: opaque framing, authenticated│  protocol.py, network.py
│  wire key (Noise-KK), fixed padding       │
├─────────────────────────────────────────┤
│  Transport: raw TCP                       │
└─────────────────────────────────────────┘
      │
┌─────────────────────────────────────────┐
│  Persistence: SQLCipher (whole file) +   │  storage.py
│  per-field encryption (vault key)         │
└─────────────────────────────────────────┘
```

Wire key, root key and chain key are derived with distinct HKDF/HMAC `info` labels (domain separation): compromising one derivation does not compromise the others.

**Known exception:** the vault key does not follow this rule. The same key derived from Argon2id encrypts both `identity.enc` (custom AES-GCM) and the entire database (passed raw to SQLCipher via `PRAGMA key`). No dedicated sub-key for the two uses: a weakness in either encryption scheme exposes the other as well.

---

## Identity

- Permanent X25519 keypair per installation, generated on first run.
- Fingerprint = SHA-256 of the raw public key, hex, 64 characters.
- Private key encrypted at rest with a local **vault passphrase** (never transmitted over the network), derived via Argon2id (256 MiB, 3 iterations, 4 lanes).
- The same vault key unlocks both the identity and the database (see [Storage](#storage)) — one secret to remember, two encrypted files (not two independent keys, see exception above).

---

## Trust model (contacts)

Adding a contact: name, IP, base64 pubkey, claimed fingerprint — automatic verification that `SHA-256(pubkey) == fingerprint` before saving, with an explicit manual confirmation from the terminal.

There is no separate "verified/unverified" state per contact: a contact is either present in the list (added after a successful fingerprint verification) or absent. Connections, in both directions, require the peer to already be a saved contact:

| Direction | Behavior |
|---|---|
| Outbound | Authenticated handshake against the static key saved for that contact. If the peer responds with a fingerprint different from the expected one, the connection is dropped (`PeerMismatch`) |
| Inbound | The sender's IP must match at least one saved contact's IP, otherwise the handshake fails immediately. If several contacts share the same IP, every matching static key is tried against the incoming HELLO (`_establish_wire_key_candidates`); the fingerprint claimed inside the HELLO payload is then checked against the fingerprint of the specific candidate whose key actually decrypted it (`_read_packet_multi_key` → `_do_handshake_inbound`). A mismatch is a `PeerMismatch`, session never created. |

Revocation: `--remove-contact` requires the pubkey as proof of possession (not just the name), then deletes the contact along with its history and outbox.

---

## Protocol

Packet types: `HELLO`, `HELLO_ACK`, `MESSAGE`, `MESSAGE_ACK`, `PRESENCE`, `PRESENCE_ACK`, `CLOSE`.

### Framing

```
[4-byte big-endian length] [AES-GCM nonce, 12 bytes] [ciphertext + tag]
```

The packet's JSON (type included) is never visible in plaintext on the wire: encrypted with the session wire key before touching the socket.

### Padding

Fixed 4096-byte block for every packet, regardless of type: each frame (nonce + ciphertext + tag) is padded up to that size before transport encryption. A message at the `MAX_MESSAGE_BYTES` limit (2500 bytes) comfortably stays under the threshold once encrypted and base64-encoded.

### Wire key

Always authenticated (Noise-KK-style): two cross static-ephemeral DHs plus one ephemeral-ephemeral DH, requiring both sides to possess/know the other's static key (see [Trust model](#trust-model-contacts)). If the candidate for the static key is not available, the handshake always fails (fail-closed), there is no unauthenticated fallback mode in this version.

When more than one static key is tried as a candidate (shared-IP case), a successful decrypt only proves the sender holds *one of the candidates'* private keys, not which one. The fingerprint the sender claims inside the HELLO/HELLO_ACK payload is therefore cross-checked against the fingerprint of the specific candidate that won the match, before the session is created. This binding is what actually authenticates the sender's identity in the shared-IP case; the decrypt succeeding on its own is not enough.

---

## Message cryptography

- **Root key**: HKDF over static-static X25519 DH + session nonces exchanged in HELLO/HELLO_ACK.
- **Symmetric ratchet** (KDF chain): one chain per direction, one-way advancement (HMAC-SHA256), a message key derived for every single message.
- **AES-256-GCM per message, with AAD binding type/id/sender/timestamp/chain_index**: tampering with the headers fails authentication even with an intact ciphertext.
- **Retries based on an ACK watchdog with adaptive RTO (Karn/Jacobson style)**: they always retransmit the **same** already-encrypted packet, never a fresh encryption: a retry must not consume an extra ratchet step.
- **Known limit**: purely symmetric ratchet over a static DH. Whoever steals the identity key can recompute the root of any past session recorded on the wire. Solved in V2 (Double Ratchet).

---

## Storage

SQLite via SQLCipher (`sqlcipher3-binary`): the entire `.db` file (schema, indexes, WAL included) is AES ciphertext until the vault key is supplied (`PRAGMA key` in `Storage.__init__`, explicitly verified with a check query before proceeding). On top of that, per-field encryption (`crypto.vault_encrypt`) on sensitive content (contact name/IP/pubkey, message text).

Columns that stay in plaintext **inside** the unlocked database (fingerprint, timestamp, direction, unread): needed for SQLite indexing/querying without decrypting every row. Not an external-facing weakness, the file is still encrypted at the SQLCipher level.

---

## Rate limiting

Sliding window, two distinct uses:

- `ByteRateLimiter`: byte budget per already-established session (anti flood/spam), weighted by bytes exchanged.
- `ConnectionFloodGuard`: limit on new TCP connections per source IP before the handshake.
- `GlobalSessionCap`: global cap on the number of concurrently active sessions (all contacts), independent of the number of distinct IPs used.

---

## Operational parameters (network.py)

| Parameter | Value | Meaning |
|---|---|---|
| `DEFAULT_PORT` | 60717 | Default listening port |
| `CONNECT_TIMEOUT` | 10s | Outbound TCP connection timeout |
| `HANDSHAKE_TIMEOUT` / `WIRE_KEY_EXCHANGE_TIMEOUT` | 10s | Timeout to complete the handshake and ephemeral key exchange |
| `PRESENCE_INTERVAL` | 15s | Cadence of the online/offline presence broadcast to every contact |
| `CONN_MAX_PER_IP` / `CONN_WINDOW_SECONDS` | 5 / 10s | Limit on inbound connections per source IP |
| `MAX_GLOBAL_SESSIONS` | 200 | Global cap on concurrently active sessions |
| `SESSION_MAX_BYTES_PER_WINDOW` / `SESSION_WINDOW_SECONDS` | 1MB / 10s | Byte budget per already-established session |
| `RTO_MIN` / `RTO_MAX` / `INITIAL_RTO` | 1s / 60s / 5s | Bounds of the adaptive retransmission timeout |
| `MAX_CHAIN_SKIP` | 200 | Maximum ratchet gap tolerated before closing the session |

---

## Secure memory

`secure_memory.py`: best-effort mlock() + explicit zeroization for the vault key (`Identity`'s internal buffer) and chain keys, via `SecureBuffer`. Core dumps disabled (`RLIMIT_CORE=0`) as the very first instruction in `main()`.

**Stated limit**: the protection only covers `Identity`'s internal buffer. Every consumer that needs the plaintext key (chiefly `Storage`, for every row encrypt/decrypt) receives and retains an ordinary `bytes` copy, not mlocked and never zeroed, for the entire lifetime of the process. `secure_memory.py` therefore only reduces the exposure window of the "master" copy, it does not eliminate plaintext copies living in ordinary RAM. It protects against offline forensics (stolen powered-off disk, accidental core dumps), not against an attacker with access to the running process. See the [README](./README.md#what-v1-does-not-protect-against-by-design-not-by-oversight) for the same limit stated as a threat-model item.