# Architecture

Internals referenced from the main [README](./README.md#security-model): layers, identity, trust model, protocol, message cryptography, storage, rate limiting, operational parameters and secure memory.

Describes implemented behavior, not planned design (that belongs in the README's [Roadmap](./README.md#roadmap)).

---

## Layered architecture

```text
┌─────────────────────────────────────────┐
│  UI (Textual)                           │  ui.py
├─────────────────────────────────────────┤
│  Application layer: contacts, outbox,   │  network.py, app.py
│  presence, retry/ACK                    │
├─────────────────────────────────────────┤
│  Message layer: Double Ratchet,         │  ratchet.py, crypto.py,
│  AES-256-GCM per message + AAD          │  protocol.py
├─────────────────────────────────────────┤
│  Wire layer: opaque framing,            │  protocol.py, network.py
│  authenticated wire key, fixed padding  │
├─────────────────────────────────────────┤
│  Transport: raw TCP                     │
└─────────────────────────────────────────┘
     │
┌─────────────────────────────────────────┐
│  Persistence: SQLCipher (whole file) +  │  storage.py
│  per-field encryption (vault key)       │
└─────────────────────────────────────────┘
```

The wire encryption and message encryption are independent cryptographic layers:

- **Wire layer:** protects packets in transit between connected peers.
- **Message layer:** provides per-message encryption, forward secrecy and post-compromise security through the Double Ratchet.
- **Persistence layer:** protects locally stored data at rest.

Wire keys, root keys and chain keys use distinct HKDF/HMAC `info` labels (domain separation), preventing direct cross-protocol key reuse between derivation contexts.

**Known exception:** the vault key does not follow this rule. The same key derived from Argon2id encrypts both `identity.enc` (custom AES-GCM) and the entire database (passed raw to SQLCipher via `PRAGMA key`). No dedicated sub-key exists for the two uses: a weakness in either encryption scheme exposes the other as well.

---

## Identity

- Permanent X25519 keypair per installation, generated on first run.
- Fingerprint = SHA-256 of the raw public key, hex, 64 characters.
- Private key encrypted at rest with a local **vault passphrase** (never transmitted over the network), derived via Argon2id (256 MiB, 3 iterations, 4 lanes).
- The same vault key unlocks both the identity and the database (see [Storage](#storage)): one secret to remember, two encrypted files (not two independent keys, see exception above).

---

## Trust model (contacts)

Adding a contact: name, IP, base64 public key and claimed fingerprint. Automatic verification that `SHA-256(pubkey) == fingerprint` before saving, with explicit manual confirmation from the terminal.

There is no separate "verified/unverified" state per contact: a contact is either present in the list (added after a successful fingerprint verification) or absent.

Connections, in both directions, require the peer to already be a saved contact:

| Direction | Behavior |
|---|---|
| Outbound | Authenticated handshake against the static key saved for that contact. If the peer responds with a fingerprint different from the expected one, the connection is dropped (`PeerMismatch`). |
| Inbound | The sender's IP must match at least one saved contact's IP, otherwise the handshake fails immediately. If several contacts share the same IP, every matching static key is tried against the incoming HELLO (`_establish_wire_key_candidates`); the fingerprint claimed inside the HELLO payload is then checked against the fingerprint of the specific candidate whose key actually decrypted it (`_read_packet_multi_key` → `_do_handshake_inbound`). A mismatch is a `PeerMismatch`, and no session is created. |

Revocation: `--remove-contact` requires the public key as proof of possession (not just the name), then deletes the contact along with its history and outbox.

---

## Protocol

Packet types: `HELLO`, `HELLO_ACK`, `MESSAGE`, `MESSAGE_ACK`, `PRESENCE`, `PRESENCE_ACK`, `CLOSE`.

### Framing

```text
[4-byte big-endian length] [AES-GCM nonce, 12 bytes] [ciphertext + tag]
```

The packet's JSON (type included) is never visible in plaintext on the wire: it is encrypted with the session wire key before touching the socket.

### Padding

Fixed 4096-byte block for every packet, regardless of type: each frame (nonce + ciphertext + tag) is padded up to that size before transport encryption.

A message at the `MAX_MESSAGE_BYTES` limit (2500 bytes) comfortably stays under the threshold once encrypted and base64-encoded.

### Wire key

Always authenticated (Noise-KK-style): two cross static-ephemeral DHs plus one ephemeral-ephemeral DH, requiring both sides to possess and know the other's static key (see [Trust model](#trust-model-contacts)).

If the candidate for the static key is not available, the handshake always fails (fail-closed). There is no unauthenticated fallback mode in this version.

When more than one static key is tried as a candidate (shared-IP case), a successful decrypt only proves the sender holds one of the candidates' private keys, not which one.

The fingerprint the sender claims inside the HELLO/HELLO_ACK payload is therefore cross-checked against the fingerprint of the specific candidate that won the match, before the session is created.

This binding is what actually authenticates the sender's identity in the shared-IP case; successful decryption alone is not sufficient.

---

## Message cryptography

### Session establishment

Each session initializes its message ratchet using an ephemeral Diffie-Hellman key exchange.

The root key is derived from three DH contributions:

- `DH-EE`: ephemeral-to-ephemeral.
- `DH-SE`: static-to-ephemeral.
- `DH-ES`: ephemeral-to-static.

The three contributions are combined and passed through the root key derivation function.

The previous static-static-only root derivation has been removed. Session root keys therefore depend on ephemeral secrets rather than solely on permanent identity keys.

The resulting root key initializes the Double Ratchet.

### Double Ratchet

Each session maintains an independent Double Ratchet state, implemented in `ratchet.py`.

It combines two mechanisms:

**Symmetric-key ratchet**

- A separate sending chain and receiving chain are maintained.
- Each chain advances independently using a one-way HMAC-SHA256-based KDF.
- Every message receives an independently derived message key.
- Previous chain keys are explicitly zeroized when no longer needed.

**Diffie-Hellman ratchet**

- Fresh DH key material is introduced during ratchet transitions.
- DH outputs are mixed into the root key derivation.
- Root key evolution establishes new sending and receiving chains.
- Previously consumed DH private keys are discarded when no longer needed.

**Skipped message keys**

- Temporarily stores message keys required to decrypt out-of-order messages.
- Skipped keys are bounded by `MAX_CHAIN_SKIP = 200`.
- An additional global storage limit of 1000 skipped keys prevents unbounded accumulation.

### Message encryption

- **AES-256-GCM per message**, using a unique derived message key.
- **AAD authentication:** binds message metadata, including type, ID, sender, timestamp, chain index and DH ratchet metadata (`dh`, `pn`).
- Ratchet metadata is validated before being accepted.
- Invalid or forged packets do not advance ratchet state.

### Two-phase message reception

The ratchet uses a two-phase receive API:

1. `prepare_receive()`: validates and prepares message decryption without committing ratchet state.
2. `commit()`: advances the ratchet state after successful processing.

Commits are one-time operations and reject stale state transitions.

This prevents invalid packets or stale receive operations from advancing or corrupting the ratchet state.

### Security properties

**Forward Secrecy (FS)**

Previously consumed message keys cannot be recovered from subsequent ratchet state. Compromise of the current ratchet state does not automatically expose messages whose keys have already been consumed and discarded.

**Post-Compromise Security (PCS)**

Fresh DH ratchet material can restore confidentiality after a temporary compromise, provided the attacker no longer controls the endpoint or its current state.

**Message Key Isolation**

Compromise of an individual message key does not reveal previous or subsequent message keys derived from the same chain.

**Identity Key Compromise Resistance**

Stealing a static identity key alone is insufficient to reconstruct previously established session root keys because those keys depend on ephemeral DH secrets.

### Session lifecycle and limitations

Each TCP handshake establishes a new session and initializes a fresh Double Ratchet.

Ratchet state is not persistently maintained across separate TCP sessions.

Unconfirmed outbox messages are re-encrypted using the new session ratchet after reconnection. Within an established session, retransmissions reuse the already-encrypted packet rather than consuming additional ratchet steps.

The ratchet protects message traffic, not historical messages stored in the local database. Database confidentiality continues to depend on the vault key.

A compromise of the complete live ratchet state can expose the current communication window until fresh DH material is introduced.

Double Ratchet does not prevent an attacker possessing a compromised identity key from impersonating that identity.

The implementation does not provide post-quantum security.

---

## Storage

SQLite via SQLCipher: the entire `.db` file (schema, indexes and WAL included) is encrypted until the vault key is supplied (`PRAGMA key` in `Storage.__init__`, explicitly verified with a check query before proceeding).

On top of that, per-field encryption (`crypto.vault_encrypt`) protects sensitive content (contact name, IP, public key and message text).

Columns that stay in plaintext **inside** the unlocked database (fingerprint, timestamp, direction, unread): needed for SQLite indexing and querying without decrypting every row.

This is not an external-facing plaintext exposure: the entire database file remains encrypted at the SQLCipher level.

**Known limitation:** the vault key is shared between identity encryption and database encryption. Compromise of this key exposes both.

The Double Ratchet does not protect messages already stored in the database against vault key compromise.

---

## Rate limiting

Sliding window, three distinct uses:

- `ByteRateLimiter`: byte budget per already-established session (anti-flood/spam), weighted by bytes exchanged.
- `ConnectionFloodGuard`: limit on new TCP connections per source IP before the handshake.
- `GlobalSessionCap`: global cap on the number of concurrently active sessions (all contacts), independent of the number of distinct IPs used.

---

## Operational parameters (network.py)

| Parameter | Value | Meaning |
|---|---:|---|
| `DEFAULT_PORT` | 60717 | Default listening port |
| `CONNECT_TIMEOUT` | 10s | Outbound TCP connection timeout |
| `HANDSHAKE_TIMEOUT` / `WIRE_KEY_EXCHANGE_TIMEOUT` | 10s | Timeout to complete the handshake and ephemeral key exchange |
| `PRESENCE_INTERVAL` | 15s | Cadence of online/offline presence broadcast to every contact |
| `CONN_MAX_PER_IP` / `CONN_WINDOW_SECONDS` | 5 / 10s | Limit on inbound connections per source IP |
| `MAX_GLOBAL_SESSIONS` | 200 | Global cap on concurrently active sessions |
| `SESSION_MAX_BYTES_PER_WINDOW` / `SESSION_WINDOW_SECONDS` | 1 MB / 10s | Byte budget per established session |
| `RTO_MIN` / `RTO_MAX` / `INITIAL_RTO` / `RTO_BACKOFF_CAP` | 1s / 60s / 5s / 6 | Bounds of the adaptive retransmission timeout |
| `MAX_CHAIN_SKIP` | 200 | Maximum tolerated ratchet gap before closing the session |
| `MAX_SKIPPED_KEYS` | 1000 | Global skipped-message-key storage limit |

---

## Secure memory

`secure_memory.py`: best-effort `mlock()` and explicit zeroization through `SecureBuffer`.

The protection covers the vault key's internal identity buffer and ratchet chain keys. Core dumps are disabled (`RLIMIT_CORE=0`) as the first instruction in `main()`.

**Stated limits:**

- Python immutable `bytes` objects cannot be reliably zeroized.
- Derived message keys (`mk`) and other sensitive values represented as ordinary `bytes` may remain in process memory until released by the runtime.
- Consumers receiving plaintext key copies may retain them outside the protected buffers.
- `mlock()` is best-effort and does not guarantee protection against a privileged attacker with access to the running process.

Secure memory reduces exposure to offline forensics and accidental core dumps. It does not provide protection against a compromised live process.
