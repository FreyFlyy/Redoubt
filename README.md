# Redoubt

[![Version](https://img.shields.io/badge/version-1.0.0-green?style=flat)](https://github.com/FreyFlyy/Redoubt/releases/tag/v1.0.0)
[![AUR](https://img.shields.io/badge/Arch-AUR-1793D1?style=flat&logo=arch-linux&logoColor=white)](#)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://kernel.org)


A peer-to-peer messaging application with end-to-end message encryption and a hardened client runtime.

**Redoubt** is designed to protect against both **passive** and **active man-in-the-middle (MITM) attackers** by mutually verifying each other's contacts. It does **not** protect against theft of the identity private key or compromise of the running process. See [Known Limitations](#known-limitations) and the roadmap.

To communicate, users **must add each other to their contacts** and verify
each other's fingerprints **out of band**. Unverified contacts cannot exchange messages.

---

## What V1 Protects

| Threat | Protection |
|---|---|
| Passive network interception | Packet contents, packet type, sender information, and timestamps are encrypted at the wire layer |
| Active MITM against a mutually verified contact | Authenticated wire key using a Noise-KK-style static-key handshake |
| Offline theft of the encrypted database | Identity protected by an Argon2id-derived vault key; database encrypted with SQLCipher |
| Offline theft of the encrypted identity key | Identity private key is encrypted at rest with the vault key |
| Packet-type inspection | Packet type is encrypted inside the wire payload |
| Packet-size analysis | Fixed-size padding to 4096 bytes |
| Unauthorized contact impersonation | Mutual public-key fingerprint verification; unverified contacts cannot communicate |
| Packet drop | ACK-based delivery confirmation and retransmission of the same encrypted packet |

---

### V1 Security Boundaries

Redoubt V1 does **not** currently provide:

- Full post-compromise security
- Protection against a compromised running process
- Protection against theft of the identity private key
- Traffic-timing obfuscation
- Anonymity from network observers

Network observers can still observe:

- Source and destination IP addresses
- Packet timing
- Number of packets
- Connection duration
- Traffic volume

Padding hides packet-size distinctions but does not provide traffic-analysis resistance.

See [Known Limitations](#known-limitations) for the detailed limitations.

---

## Known Limitations

### 1. Identity key compromise

V1 uses a permanent X25519 identity key.

An attacker who obtains the private identity key can reconstruct the root key of recorded sessions because the message ratchet is ultimately derived from a static-static X25519 exchange.

V1 therefore does **not** provide full forward secrecy against later compromise of the identity key.

A persistent DH ratchet and X3DH-style session establishment are planned for V2.

### 2. Runtime compromise

An attacker with access to the running process may be able to access sensitive material in memory.

V1 provides best-effort protections such as memory locking, explicit zeroization, and core-dump disabling, but these do not protect against a privileged attacker with live process access.

### 3. Network metadata

Redoubt does not hide all traffic metadata.

An observer may still see:

* Source and destination IP addresses
* Number of packets
* Packet timing
* Connection duration
* Traffic volume

Padding hides packet-size distinctions but does not provide traffic-analysis or timing resistance.

### 4. Compromised host

An attacker with privileged access to a running system may bypass application-level protections.

No application-level Python mechanism can guarantee protection against a fully compromised host.

---

# Architecture

```text
┌─────────────────────────────────────────┐
│ UI (Textual)                            │
│ ui.py                                   │
├─────────────────────────────────────────┤
│ Application layer                       │
│ Contacts, outbox, presence, retry/ACK   │
│ network.py, app.py                      │
├─────────────────────────────────────────┤
│ Message layer                           │
│ Symmetric ratchet, AES-256-GCM, AAD     │
│ crypto.py, protocol.py                  │
├─────────────────────────────────────────┤
│ Wire layer                              │
│ Encrypted framing, wire key, padding    │
│ protocol.py, network.py                 │
├─────────────────────────────────────────┤
│ Transport                               │
│ Raw TCP                                 │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Persistence                             │
│ SQLCipher + field-level encryption      │
│ storage.py                              │
└─────────────────────────────────────────┘
```

Each cryptographic layer derives its own key material using separate HKDF `info` values for domain separation.

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
python -m redoubt.app --add-contact
```

Remove a contact:

```bash
python -m redoubt.app --remove-contact
```

List contacts:

```bash
python -m redoubt.app --list-contacts
```

---

# Roadmap

## V2 - Post-Compromise Security

Planned:

* X3DH-style session establishment
* Full Double Ratchet
* Tor transport (optional)

*(Tor contacts will use a separate identity/keypair from LAN contacts to avoid implicitly binding the two identities together.)*

## V3 - Native Security-Critical Components

Planned:

* Rust implementation of security-critical memory handling
* Rust implementation of security-critical storage components
* FFI integration with the Python app
* Traffic timing obfuscation with dummy traffic (optional)

## Author and Maintainer

Francesco Scolz

## Contacts
- GitHub: [FreyFlyy](https://github.com/FreyFlyy)
- LinkedIn: [Francesco Scolz](https://www.linkedin.com/in/francesco-scolz)
- Hugging Face: [FreyFlyy](https://huggingface.co/FreyFlyy)