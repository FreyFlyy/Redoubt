# Redoubt

[![Version](https://img.shields.io/badge/version-1.0.0-green?style=flat)](https://github.com/FreyFlyy/Redoubt/releases/tag/v1.0.0)
[![AUR](https://img.shields.io/badge/Arch-AUR-1793D1?style=flat&logo=arch-linux&logoColor=white)](#)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://kernel.org)

Terminal-based P2P messenger, end-to-end encrypted, LAN/Tailscale. No server, no broker: two instances talk directly over TCP.

**Version:** V1. protects against passive network observers and active MITM against contacts already known (fingerprint exchanged out-of-band). Does not protect against theft of the identity key, nor against an attacker with access to the running process (see [Known limits](#what-v1-does-not-protect-against-by-design-not-by-oversight)).

Internals — identity, wire protocol, message cryptography, storage, secure memory — are documented separately in [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Threat model

### What V1 protects against

| Threat | Protection |
|---|---|
| Passive network observer (sniffing) | Opaque framing: every packet (type, sender, timestamp, content) is encrypted before touching the socket and padded to a fixed size |
| Active attacker (MITM) against a contact already present in the local contact list | Authenticated wire key (Noise-KK-style scheme): requires the peer's static key, known in advance because the contact was added with an out-of-band fingerprint verification. A MITM without that private key cannot complete the handshake |
| Theft of a powered-off device (disk, swap, hibernation) | Identity encrypted with a vault passphrase (Argon2id); entire database file encrypted (SQLCipher) + additional per-field encryption on sensitive content |
| Packet-size analysis | Every packet is padded to a fixed 4096-byte block before encryption: type and real content length are not distinguishable from the size on the wire |
| Compromised/suspicious contact | Explicit revocation (`--remove-contact`), requires proof of possession of the matching public key, not just the saved name |

### What V1 does NOT protect against (by design, not by oversight)

- **Theft of the static identity key**: whoever obtains it can recompute the root key of any past session whose traffic was recorded. This requires a real Double Ratchet (X3DH + persistent DH ratchet) — **not implemented**, scope of V2.
- **Runtime compromise of the process**: no self-healing/post-compromise security. On top of that, the vault key is not confined to the mlocked buffer alone: `Identity.vault_key` returns an ordinary `bytes` copy on every access, and `Storage` keeps a persistent copy of it for the entire lifetime of the process, never zeroed. `secure_memory.py` (mlock + zero) therefore only protects `Identity`'s internal buffer, not the copies that circulate elsewhere — this is a **best-effort** protection against offline forensics (powered-off disk, accidental core dumps), not against an attacker with access to the running process's RAM.
- **Sender attribution in shared-IP scenarios (NAT/LAN)**: when several contacts are saved under the same IP, the inbound handshake tries multiple candidate static keys until one successfully decrypts the HELLO packet, but it does not verify that the fingerprint claimed in the payload matches the candidate that actually produced the winning wire key. A successfully authenticated contact (one that genuinely holds a known private key) can therefore claim to be a different contact sharing the same IP. Cryptographic authentication of the *real sender* still holds (nobody can forge a handshake without a known private key), but the session can end up associated with the wrong fingerprint, misrouting outgoing messages meant for that contact. Accepted risk in V1, to be fixed by binding the claimed fingerprint to the winning candidate.
- **MITM against contacts not yet added**: if the sender's IP does not match any saved contact, the handshake always fails (no candidate key available) — this version has no "unauthenticated ephemeral wire key" fallback mode: reception from an unknown IP is rejected, not downgraded.
- **Residual network metadata**: packet count, timing, and participants' IPs remain visible to a network observer. Padding hides size, not cadence.
- **An attacker with access to the running process** (root, ptrace, cold-boot on powered RAM): no application-level defense is possible against this, in any version.

---

# How to start

Install from AUR:

***NOTE: currently, the AUR is blocking all new registrations. No official redoubt package is available. Come back for updates***

```bash
# paru
paru -S redoubt

# yay
yay -S redoubt
```

First start (will ask for a passphrase and will generate a local identity):

```bash
redoubt
```

Display the identity card:

```bash
redoubt --show-card
```

Add a contact:

```bash
redoubt --add-contact
```

Remove a contact:

```bash
redoubt --remove-contact
```

List contacts:

```bash
redoubt --list-contacts
```

---

## Roadmap

- **V2**: full Double Ratchet (X3DH + persistent DH ratchet, self-healing/post-compromise security); binding the fingerprint claimed in the HELLO payload to the candidate that actually authenticated the wire key (closes the limit described in [Trust model](./ARCHITECTURE.md#trust-model-contacts)); optional Tor/onion support with contacts kept separate from LAN ones.
- **V3**: critical components (memory, storage) rewritten in a memory-safe language with explicit control over key lifetime in RAM, to actually close the limit described in [Secure memory](./ARCHITECTURE.md#secure-memory) instead of just reducing its surface; timing obfuscation with dummy packets.

---

## Main dependencies

- `cryptography` — X25519, HKDF, AES-GCM, Argon2id
- `sqlcipher3-binary` — file-level encrypted SQLite
- `textual` — terminal interface

## Operational requirements

- Python ≥ 3.12
- Strong vault passphrase (≥8 characters, the app warns if shorter, does not block, only warns)
- **Out-of-band** fingerprint verification (in person or over a secure channel) before adding a contact: it is the only real trust anchor, no cryptography replaces it

## Author and Maintainer

Francesco Scolz
- GitHub: [FreyFlyy](https://github.com/FreyFlyy)
- LinkedIn: [Francesco Scolz](https://www.linkedin.com/in/francesco-scolz)
- Hugging Face: [FreyFlyy](https://huggingface.co/FreyFlyy)