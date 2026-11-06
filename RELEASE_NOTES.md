# Redoubt 2.2.0

## Security

- **Fixed critical key reuse vulnerability**: The master vault key (derived from the passphrase via Argon2id) is **no longer used directly** for encryption. Instead, two independent subkeys are derived via HKDF-SHA256 with distinct `info` labels:
  - **Identity subkey** (`VAULT_KEY_IDENTITY_LABEL`) → encrypts `identity.enc` using AES-256-GCM
  - **Database subkey** (`VAULT_KEY_DATABASE_LABEL`) → passed to SQLCipher as `PRAGMA key` for `redoubt.db`
  - Previously, the same master key protected both files; a weakness in either encryption scheme exposed the other. Now the encryption keys are cryptographically separated.
- **Strengthened Argon2id KDF**: Increased `time_cost` from **3 to 4 iterations** (memory cost remains 256 MiB, parallelism 4), further slowing brute-force attacks against the vault passphrase.
- **Constant-time fingerprint comparison**: Added `hmac.compare_digest()` for fingerprint verification during contact validation, eliminating timing side-channels.
- **Automatic transparent migration with backups**: On first unlock after upgrading, existing `identity.enc` and `redoubt.db` are **automatically migrated** to the new key-separated format. Before any modification, timestamped backups are created in `~/.redoubt/backups/` (including WAL/SHM files for the database). Migration requires user confirmation in interactive mode.

## Updates

- Added dedicated `migration.py` module handling all legacy format detection and migration logic (pre-v2.1.1 single-key format, v2.1.1 legacy time_cost=3 format, and partial migrations).
- Migration is atomic: both `identity.enc` and `redoubt.db` are migrated together on first successful unlock with the correct passphrase.
- Updated `ARCHITECTURE.md` to document the new vault key separation architecture and added a "Post-Quantum Readiness (Store-Now-Decrypt-Later)" section acknowledging the current lack of PQC and planning migration for v3.0.0.
- Updated `README.md` roadmap to reflect post-quantum cryptography as a v3.0.0 goal.

## Compatibility & migration

- **Fully backward compatible**: Existing installations migrate transparently on first run after upgrade (asks for y/N confirmation). No manual steps required.
- Migration handles all known legacy formats:
  1. Pre-v2.1.1 (single master key for both files, time_cost=3 or 4)
  2. v2.1.1 with legacy Argon2id `time_cost=3` but already separated keys
  3. v2.1.1 with current `time_cost=4` but single key (partial migration)
- Backups are created in `~/.redoubt/backups/` with timestamps (e.g., `identity.enc.20261106_185731.bak`, `redoubt.db.20261106_185731.bak` plus `-wal`/`-shm`).
- If migration is cancelled or fails, original files remain untouched and backups are available for manual recovery.
- Non-interactive environments (tests, CI, piped input) auto-confirm migration.
- After migration, subsequent launches use the fast path (no re-migration overhead).
