# Redoubt 2.0.0

## Improvements

- **Double Ratchet Protocol:** Implemented a Double Ratchet mechanism combining symmetric-key ratcheting and Diffie-Hellman key exchanges to provide Forward Secrecy and Post-Compromise Security within individual sessions (NOT X3DH as previously suggested by the README.md's roadmap, but still enough for the use case).
- **Ephemeral Key Exchange:** Session root keys are now derived from ephemeral Diffie-Hellman secrets rather than static identity keys, preventing identity key compromise from exposing previously established session traffic.
- **Message Key Isolation:** Each message uses an independently derived encryption key. Compromise of an individual message key does not expose previous or subsequent messages.
- **Automatic Recovery:** The ratchet periodically introduces fresh DH material, allowing sessions to recover confidentiality after a temporary state compromise.
- **Protocol Authentication:** New DH ratchet metadata is authenticated as part of the message's Additional Authenticated Data (AAD), protecting protocol state against tampering.
- **Secure Message Processing:** Introduced a two-phase message reception process (`prepare_receive` → `commit`) to prevent invalid or forged packets from advancing ratchet state.
- **Session Synchronization:** Improved handling of out-of-order messages through bounded skipped message keys.

## Security

- Replaced the previous static-key-based session root derivation with an ephemeral key exchange combining `DH-EE`, `DH-SE` and `DH-ES`.
- Introduced bounded skipped-key storage to limit memory consumption and exposure.
- Improved ratchet state management, including one-time commits and protection against stale state transitions.
- Invalid ratchet operations and malformed key exchange metadata are rejected without advancing cryptographic state.

## Compatibility

- **Breaking protocol change:** Message packet structure has changed to accommodate Double Ratchet metadata (`dh`, `pn`).
- Version 2.0.0 clients are not wire-compatible with version 1.0.1 clients.
- Existing identity keys and locally stored message history are not inherently invalidated by the protocol upgrade.
