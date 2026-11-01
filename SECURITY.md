# Security Policy

Redoubt is an experimental, unaudited peer-to-peer messenger. Vulnerability reports are welcome and appreciated.

For what the project does and does not protect against, read the [Security model](./README.md#security-model) and [ARCHITECTURE.md](./ARCHITECTURE.md) first.

---

## Supported versions

Only the latest release receives security fixes (currently v1.0.1)

---

## Reporting a vulnerability

**Do not open a public issue or pull request for a security problem.**

Use one of these private channels:

1. **GitHub private vulnerability reporting (preferred):**
   [Report a vulnerability](https://github.com/FreyFlyy/Redoubt/security/advisories/new)
2. **Email:** `francesco.scolz@gmail.com` with the subject `[Redoubt security]`

Please include:
- Affected version (`redoubt --version` or AppImage filename) and platform
- Description of the issue and its impact
- Steps to reproduce, or a proof of concept
- Relevant logs or packet captures (remove your own keys and messages)
- Whether you plan to disclose publicly, and when

---

## What to expect

Redoubt is maintained by one person, so these are targets, not guarantees.

| Step | Target |
|---|---|
| Acknowledgement of your report | within 7 days |
| Initial assessment (accepted / declined / need more info) | within 14 days |
| Fix or mitigation for confirmed issues | depends on severity; critical issues first |
| Public disclosure | coordinated with you, **90 days** after the report by default, earlier once a fix is released |

If you do not receive an acknowledgement within 7 days, please resend.

---

## Scope

### In scope

- Handshake, wire-key derivation and authentication (`protocol.py`, `network.py`, `crypto.py`)
- Message encryption, ratchet and AAD handling
- Packet parsing: crashes, memory exhaustion, resource exhaustion, bypass of the rate limiters
- Identity and vault handling, key derivation (`identity.py`)
- Encrypted storage and leakage of data that should be encrypted (`storage.py`)
- Bypass of contact authentication, fingerprint verification or contact revocation
- Supply chain issues in the build and release pipeline (workflows, packaging, released AppImage)

### Out of scope

These are documented limitations of the current version, not vulnerabilities:

- Attacker with access to the running process, root, ptrace or cold-boot on powered RAM
- Lack of post-compromise security and of per-message forward secrecy (planned for V2)
- Network metadata: IP addresses, timing, packet counts
- Plaintext copies of the vault key in ordinary process memory (see [Secure memory](./ARCHITECTURE.md#secure-memory))
- Reuse of the vault key for `identity.enc` and the SQLCipher database (documented in ARCHITECTURE.md)
- Compromised endpoint, malicious OS or malicious AppImage obtained from an unofficial source
- Social engineering, or skipping the out-of-band fingerprint verification
- Vulnerabilities in third-party dependencies that are not exploitable through Redoubt (report them upstream)

A report that goes beyond a documented limitation (for example, a way to exploit one remotely or without the preconditions stated in the threat model) **is** in scope.

---

## Disclosure and credit

- Reports are handled confidentially until a fix is available or the disclosure deadline passes.
- Confirmed issues are published as a GitHub Security Advisory, with a CVE requested when appropriate.
- Reporters are credited in the advisory unless they ask to stay anonymous.
- There is no bug bounty.

---

## Safe harbor

Good-faith security research on your own installations, accounts and test peers is welcome. I will not pursue legal action for research that:

- stays within the scope above,
- avoids accessing, modifying or destroying other people's data,
- does not degrade a service or network you do not own,
- and is reported privately and given reasonable time to be fixed.

Do not test against other people's Redoubt instances without their explicit consent.

---

## Verifying releases

Release artifacts are published on the [Releases page](https://github.com/FreyFlyy/Redoubt/releases) together with a `SHA256SUMS` file. Verify before running:

```bash
sha256sum -c SHA256SUMS
```

Only trust AppImages downloaded from this repository's official releases.
