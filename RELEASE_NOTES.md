# Unreleased (planned 2.3.0): optional Tor/onion network

- **Onion contacts**: contacts can have a v3 `.onion` address instead of an IP, shown with an `(On)` prefix. The same key can be saved as IP contact and as onion contact (separate chats).
- **Settings > Use Tor/Onion network** (off by default): guided Tor installation, onion address creation/check, private Tor instance, listener behind your onion service. Nothing runs and Tor is not required while it is off.
- **Compatibility**: no change to existing contacts, messages or identity; a new `secrets` table is created on first open (older versions ignore it).
- New modules: `onion.py`, `onion_service.py`, `tor_manager.py`. No new Python dependencies.

---

# Redoubt 2.2.1

## Security

- **Hardened the update check request**: `update_check.py` now validates the URL scheme before calling `urllib.request.urlopen()`, rejecting anything other than `http`/`https` (e.g. `file:` or custom schemes). This addresses Bandit B310 while preserving TLS certificate verification. The endpoint remains a hardcoded HTTPS GitHub URL.

## Improvements

- Added `CONTRIBUTING.md` with development setup and contribution guidelines.
- Added `RELEASE_WORKFLOW.md` documenting versioning, the release procedure, artifact building (Linux AppImage / Windows ZIP), testing requirements, and release quality criteria.
- Documented the `migration.py` module in the README module overview.
- Updated the README roadmap: Tor/onion networking moved to v2.3.0; post-quantum cryptography remains a v3.0.0 goal.

## Compatibility & migration

- **Fully backward compatible** with `2.X.X` versions.
- No storage or migration format changes since 2.2.0; existing vaults continue to work without manual steps.
