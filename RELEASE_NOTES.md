# Redoubt v2.3.0

## Improvements

### Tor / onion network support (opt-in, off by default)

- Added communication via Tor v3 onion services (`.onion` addresses), without opening inbound ports and without using the system Tor service.
- The feature is **off by default**: while off, Redoubt never looks for, installs, or starts Tor.
- New `redoubt/onion.py`: v3 onion address validation/normalization, onion service key generation and address derivation, minimal SOCKS5 client (name resolved by Tor, never locally), Tor extended error codes.
- New `redoubt/tor_manager.py`: private Tor instance (dedicated `~/.redoubt/tor` DataDirectory, random SOCKS/Control ports, client only, never the system Tor service). The onion service private key is created by Redoubt and passed to Tor via `ADD_ONION` (`ED25519-V3`), so it is never written to disk by Tor. The Tor process is bound to Redoubt's lifecycle (`__OwningControllerProcess`): it terminates with Redoubt, even on crash.
- New `redoubt/onion_service.py`: orchestrates turning the feature on/off (`tor` lookup, encrypted vault key storage, loopback listener `127.0.0.1`, Tor startup, service publication with address verification, bootstrap wait).
- `redoubt/network.py`: outbound connections to IPv4 contacts (direct TCP) or `.onion` contacts via Tor's SOCKS proxy; dedicated loopback listener; longer onion timeouts; separate onion flood guard; `OnionUnavailable` exception when Tor is off.
- `redoubt/contact_validation.py` and `redoubt/storage.py`: contacts are identified by a contact id (fingerprint for IPv4, fingerprint + `-onion` for onion), allowing the same person to be saved once per transport with separate chats, Double Ratchet sessions, and outboxes. Onion contacts are shown with the `(On)` prefix.
- `redoubt/app.py` and `redoubt/ui.py`: new "Use Tor/Onion network" setting in Settings; identity card shows the onion address once created; adding a contact accepts an IPv4 address or a v3 `.onion` address; contact removal handles the same fingerprint saved as both IP and onion contact.

### Tests

- Added `tests/test_onion.py`, `tests/test_onion_contacts_and_service.py`, `tests/test_onion_network.py`, `tests/test_onion_ui.py`, `tests/test_tor_manager.py`; updated `tests/test_app.py`.

## Security

No known vulnerability fixes. New security considerations for the optional Tor/onion support:

- Tor hides *where* you are, not *that* you use Tor, nor traffic timing.
- Anyone who knows your `.onion` address can open connections to it (they cannot authenticate without a contact key, but can consume CPU: inbound onion connections share one rate-limit bucket).
- The onion service key lives in the encrypted database, but the Tor process is only as trustworthy as the `tor` package on your system.
- IP contacts still connect directly and reveal your IP even with Tor on.

## Compatibility

**Full backward compatibility with 2.1.X versions**

- IPv4 contacts saved in v2.2.1 keep working unchanged (contact id remains the fingerprint).
- Database schema gains a `secrets` table for the encrypted onion service key.
- Onion support requires Tor >= 0.3.5.0 (first stable series with v3 onion services via `ADD_ONION` `ED25519-V3`).
