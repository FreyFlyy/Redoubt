# Redoubt

[![Version](https://img.shields.io/badge/version-0.0.1-green?style=flat)](https://github.com/FreyFlyy/Redoubt/releases/tag/v0.0.1)
[![AUR](https://img.shields.io/badge/Arch-AUR-1793D1?style=flat&logo=arch-linux&logoColor=white)](#)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://kernel.org)
[![License](https://img.shields.io/github/license/FreyFlyy/Redoubt)](LICENSE)

A peer-to-peer messaging app with end-to-end message encryption and hardened client runtime

**Version V0.0.1 / V1**. Protects against passive network observers and **active MITM against contacts** already known (fingerprint exchanged out-of-band). **Does not** protect against theft of the identity key, nor against an attacker with access to the running process (see [Known limits](#what-v1-does-not-protect-against-by-design-not-by-oversight)).

Internals (identity, wire protocol, message cryptography, storage, secure memory) are documented separately in [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Threat model

### What V0.0.1 / V1 protects against

| Threat | Protection |
|---|---|
| Passive network observer (sniffing) | Opaque framing: every packet (type, sender, timestamp, content) is encrypted before touching the socket and padded to a fixed size |
| Active attacker (MITM) against a contact already present in the local contact list | Authenticated wire key (Noise-KK-style scheme): requires the peer's static key, known in advance because the contact was added with an out-of-band fingerprint verification. A MITM without that private key cannot complete the handshake |
| Theft of a powered-off device (disk, swap, hibernation) | Identity encrypted with a vault passphrase (Argon2id); entire database file encrypted (SQLCipher) + additional per-field encryption on sensitive content |
| Packet-size analysis | Every packet is padded to a fixed 4096-byte block before encryption: type and real content length are not distinguishable from the size on the wire |
| Compromised/suspicious contact | Explicit revocation (`--remove-contact`), requires proof of possession of the matching public key, not just the saved name |

### What V0.0.1 / V1 does NOT protect against (by design, not by oversight)

- **Theft of the static identity key**: whoever obtains it can recompute the root key of any past session whose traffic was recorded. This requires a real Double Ratchet (X3DH + persistent DH ratchet)
- **Runtime compromise of the process**: no self-healing/post-compromise security. On top of that, the vault key is not confined to the mlocked buffer alone: `Identity.vault_key` returns an ordinary `bytes` copy on every access, and `Storage` keeps a persistent copy of it for the entire lifetime of the process, never zeroed. `secure_memory.py` (mlock + zero) therefore only protects `Identity`'s internal buffer, not the copies that circulate elsewhere. This is a **best-effort** protection against offline forensics (powered-off disk, accidental core dumps), not against an attacker with access to the running process's RAM.
- **Residual network metadata**: packet count, timing, and participants' IPs remain visible to a network observer. Padding hides size, not cadence.
- **An attacker with access to the running process** (root, ptrace, cold-boot on powered RAM): no application-level defense is possible against this, in any version.

---

# How to start (Arch-Based distros)

Manual install:

> **NOTE:** Currently, AUR is blocking all new registrations. No official Redoubt package is available (**v0.0.1 is experimental**). When new registrations reopen, the project will jump to **v1.0.0**. Come back for updates.

```bash
# Move into temp folder
mkdir -p /tmp/redoubt
cd /tmp/redoubt

# Create PKGBUILD (copy and paste)
cat > PKGBUILD <<'EOF'
# Maintainer: Redoubt Developer francesco.scolz@gmail.com
### MANUAL EXPERIMENTAL INSTALL, WAIT AUR PKG FOR v1.0.0

pkgname=redoubt
pkgver=0.0.1
pkgrel=1
pkgdesc="A peer-to-peer messaging app with end-to-end message encryption and hardened client runtime"
arch=('any')
url="https://github.com/FreyFlyy/Redoubt"
license=('AGPL-3.0-only')

depends=(
    'python'
    'python-cryptography'
    'python-sqlcipher3'
    'python-textual'
    'python-rich'
)

makedepends=(
    'python-build'
    'python-installer'
    'python-setuptools'
    'python-wheel'
)

source=(
    "$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz"
)

sha256sums=('9552773e993bbc37a2ead4d4e137a444727d25fa32c5052736cd8af7081ee866')

build() {
    cd "$srcdir/Redoubt-$pkgver"
    python -m build --wheel --no-isolation
}

package() {
    cd "$srcdir/Redoubt-$pkgver"
    python -m installer --destdir="$pkgdir" dist/*.whl
}
EOF

# Install depedencies

# paru
paru -S --needed \
    python \
    python-cryptography \
    python-sqlcipher3 \
    python-textual \
    python-rich \
    python-build \
    python-installer \
    python-setuptools \
    python-wheel
# yay
yay -S --needed \
    python \
    python-cryptography \
    python-sqlcipher3 \
    python-textual \
    python-rich \
    python-build \
    python-installer \
    python-setuptools \
    python-wheel

# Make package
makepkg

# Install package
sudo pacman -U redoubt-0.0.1-1-any.pkg.tar.zst

# Remove temp files
cd /tmp
rm -rf /tmp/redoubt
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

- `cryptography`: X25519, HKDF, AES-GCM, Argon2id
- `sqlcipher3-binary`: file-level encrypted SQLite
- `textual`: terminal interface

## Operational requirements

- Python ≥ 3.12
- Strong vault passphrase (≥8 characters)
- **Out-of-band** fingerprint verification (in person or over a secure channel) before adding a contact: it is the only real trust anchor, no cryptography replaces it

## Author and Maintainer

Francesco Scolz
- GitHub: [FreyFlyy](https://github.com/FreyFlyy)
- LinkedIn: [Francesco Scolz](https://www.linkedin.com/in/francesco-scolz)
- Hugging Face: [FreyFlyy](https://huggingface.co/FreyFlyy)
