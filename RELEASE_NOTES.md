# Redoubt 2.2.1

## Security

- **Hardened the update check request**: `update_check.py` now validates the URL scheme before calling `urllib.request.urlopen()`, rejecting anything other than `http`/`https` (e.g. `file:` or custom schemes). This addresses Bandit B310 while preserving TLS certificate verification. The endpoint remains a hardcoded HTTPS GitHub URL.

## Improvements

- Added `CONTRIBUTING.md` with development setup and contribution guidelines.
- Added `RELEASE_WORKFLOW.md` documenting versioning, the release procedure, artifact building (Linux AppImage / Windows ZIP), testing requirements, and release quality criteria.
- Documented the `migration.py` module in the README module overview.
- Updated `SECURITY.md` to remove the vault key reuse limitation, which was resolved in 2.2.0.
- Made README AppImage CLI examples version-agnostic instead of pinned to `2.2.0`.
- Updated the README roadmap: Tor/onion networking moved to v2.3.0; post-quantum cryptography remains a v3.0.0 goal.

## Compatibility & migration

- **Fully backward compatible** with `2.X.X` versions.
- No storage or migration format changes since 2.2.0; existing vaults continue to work without manual steps.
