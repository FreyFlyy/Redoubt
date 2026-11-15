# Redoubt 2.3.0-rc.1

## Improvements

- **Onion contacts**: contacts can have a v3 `.onion` address instead of an IP, shown with an `(On)` prefix. The same key can be saved as IP contact and as onion contact (separate chats).
- **Settings > Use Tor/Onion network** (off by default): guided Tor installation, onion address creation/check, private Tor instance, listener behind your onion service. Nothing runs and Tor is not required while it is off.

## Compatibility

- No change to existing contacts, messages or identity; a new `secrets` table is created on first open (older versions ignore it).
- New modules: `onion.py`, `onion_service.py`, `tor_manager.py`. No new Python dependencies.
