# Redoubt 2.1.0

## Improvements

- **Settings menu:** New top-left `☰ Settings` menu (also `F2`) with `About`, `Show card`, `Contact list` and `Add contact`.
- **Contact management in the UI:** Add contacts through a validated form, browse saved contacts with name, IP, public key and fingerprint, and revoke them from the contact list.
- **Revocation with confirmation:** Revoking a contact deletes its messages and outbox, closes any live session, wipes the Double Ratchet state, drops pending ACKs/presence, and prevents in-flight handshakes from installing a new session.
- **Shared contact validation:** `contact_validation.py` centralizes name/IP/public-key/fingerprint checks for both the UI form and the CLI.
- **Legacy CLI retained:** `--add-contact`, `--list-contacts` and `--remove-contact` are still available and documented.
- **About screen:** Shows author, version and license.
- **Test coverage:** Added tests for the settings menu, theme cycling, settings persistence and revoked-contact session handling.

## Security

- Revocation is enforced at runtime: `_install_session` refuses sessions for contacts no longer present in storage, and `drop_contact()` removes live session/ratchet state and pending retransmissions.
- Contact validation (fingerprint must match the public key, own identity rejected, duplicate contacts rejected) is now shared between CLI and UI, avoiding divergent checks.
- Wire protocol and message cryptography are unchanged.

## Fixes

- Restored the missing `packaging/redoubt.desktop`, so AppImage builds ship a valid desktop entry again (v2.0.0 packaging regression).
- Corrected the desktop entry `Version` field (it is the Desktop Entry specification version `1.0`, not the Redoubt version).
- Documentation updates: settings menu, legacy CLI contact commands, module table, revocation behavior and AppImage output path.

## Compatibility

- Version **2.1.0** clients **ARE** compatible with version **2.0.0** clients (but not **1.x.x**): the wire protocol and message cryptography are unchanged.
- Existing identity keys, contacts and locally stored history remain valid.
- The legacy CLI contact commands remain available.
