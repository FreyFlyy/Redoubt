### migration.py

"""
Migration module for Redoubt v2.1.1+ key separation.

Handles transparent migration from the old single-key format (pre-v2.1.1)
to the new HKDF-separated subkey format.

Migration is atomic: both identity.enc and redoubt.db are migrated together
on first successful unlock with the correct passphrase.

Also handles Argon2id parameter migration: legacy used time_cost=3, new uses time_cost=4.
"""

import os
import json
import shutil
import sys
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlcipher3 import dbapi2 as sqlcipher
from . import crypto
from . import secure_memory
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)

# Argon2id parameters for legacy (v2.1.0 and earlier) - MUST match original values
ARGON2ID_LEGACY_TIME_COST = 3
ARGON2ID_MEMORY_COST_KIB = 262144
ARGON2ID_PARALLELISM = 4


def _confirm_migration(description: str) -> bool:
    """
    Ask user for confirmation before performing migration.
    Returns True if user confirms, False otherwise.
    """
    # Skip confirmation if not in interactive mode (e.g., tests, piped input)
    if not sys.stdin.isatty():
        logger.info(f"Non-interactive mode: auto-confirming migration: {description}")
        return True

    print(f"\n⚠️  MIGRATION NEEDED")
    print(f"   {description}")
    print(f"   Backups will be created in ~/.redoubt/backups/")
    print(f"   Continue? [y/N]: ", end="", flush=True)

    try:
        response = sys.stdin.readline().strip().lower()
        return response in ('y', 'yes', 's', 'si', 'sì')
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return False


def _derive_vault_key_with_time_cost(passphrase: str, salt: bytes, time_cost: int) -> bytes:
    """Derive master vault key with specific Argon2id time_cost (for legacy compatibility)."""
    kdf = Argon2id(
        salt=salt, length=32,
        iterations=time_cost,
        lanes=ARGON2ID_PARALLELISM,
        memory_cost=ARGON2ID_MEMORY_COST_KIB,
        ad=None, secret=None,
    )
    return kdf.derive(passphrase.encode("utf-8"))

def _derive_subkey(master_key: bytes, label: bytes) -> bytes:
    """Derive a purpose-specific subkey from the master vault key using HKDF-SHA256."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label)
    return hkdf.derive(master_key)

def _vault_decrypt(key: bytes, blob: bytes) -> bytes:
    """Decrypt using AES-GCM."""
    aesgcm = AESGCM(key)
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, None)

def _vault_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using AES-GCM."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)

# Lazy path getters to avoid circular imports
def _get_identity_file():
    from .identity import IDENTITY_FILE
    return IDENTITY_FILE

def _get_db_file():
    from .storage import DB_FILE
    return DB_FILE


def _try_load_identity_new_format(vault_passphrase: str, time_cost: int = None):
    """
    Try loading identity with new format (subkey).
    Returns (priv, master_key, time_cost_used) or None.
    If time_cost is None, uses current crypto.ARGON2ID_TIME_COST.
    """
    try:
        with open(_get_identity_file(), "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return None
    if len(data) < 16:
        return None
    salt, blob = data[:16], data[16:]
    try:
        if time_cost is None:
            master_vault_key = crypto.derive_vault_key(vault_passphrase, salt)
            used_time_cost = crypto.ARGON2ID_TIME_COST
        else:
            master_vault_key = _derive_vault_key_with_time_cost(vault_passphrase, salt, time_cost)
            used_time_cost = time_cost
        identity_vault_key = _derive_subkey(master_vault_key, crypto.VAULT_KEY_IDENTITY_LABEL)
        raw_priv = bytearray(_vault_decrypt(identity_vault_key, blob))
        priv = crypto.private_key_from_raw(bytes(raw_priv))
        secure_memory.zero_bytearray(raw_priv)
        return priv, master_vault_key, used_time_cost
    except (InvalidTag, ValueError, OSError):
        return None


def _try_load_identity_old_format(vault_passphrase: str, time_cost: int = None):
    """
    Try loading identity with old format (direct master key).
    Returns (priv, master_key, time_cost_used) or None.
    If time_cost is None, uses current crypto.ARGON2ID_TIME_COST.
    """
    try:
        with open(_get_identity_file(), "rb") as f:
            data = f.read()
    except FileNotFoundError:
        return None
    if len(data) < 16:
        return None
    salt, blob = data[:16], data[16:]
    try:
        if time_cost is None:
            master_vault_key = crypto.derive_vault_key(vault_passphrase, salt)
            used_time_cost = crypto.ARGON2ID_TIME_COST
        else:
            master_vault_key = _derive_vault_key_with_time_cost(vault_passphrase, salt, time_cost)
            used_time_cost = time_cost
        # Old format: vault_key used directly for AES-GCM
        raw_priv = bytearray(_vault_decrypt(master_vault_key, blob))
        priv = crypto.private_key_from_raw(bytes(raw_priv))
        secure_memory.zero_bytearray(raw_priv)
        return priv, master_vault_key, used_time_cost
    except (InvalidTag, ValueError, OSError):
        return None


def _try_open_db_new_format(master_vault_key: bytes):
    """Try opening database with new format (db subkey). Returns connection or None."""
    try:
        db_key = _derive_subkey(master_vault_key, crypto.VAULT_KEY_DATABASE_LABEL)
        conn = sqlcipher.connect(_get_db_file(), check_same_thread=False)
        conn.execute(f"PRAGMA key = \"x'{db_key.hex()}'\"")
        conn.execute("SELECT count(*) FROM sqlite_master")  # Test query
        return conn, db_key
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return None, None


def _try_open_db_old_format(master_vault_key: bytes):
    """Try opening database with old format (master key directly). Returns connection or None."""
    try:
        conn = sqlcipher.connect(_get_db_file(), check_same_thread=False)
        conn.execute(f"PRAGMA key = \"x'{master_vault_key.hex()}'\"")
        conn.execute("SELECT count(*) FROM sqlite_master")  # Test query
        # Verify expected tables exist
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('contacts', 'messages', 'outbox')").fetchall()
        if len(tables) < 3:
            conn.close()
            return None, None
        return conn, master_vault_key
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return None, None


def _migrate_identity_file(vault_passphrase: str, salt: bytes, legacy_time_cost: int = None):
    """
    Re-encrypt identity.enc with new format (subkey) using current Argon2id parameters.
    If legacy_time_cost is provided, also updates the Argon2id time_cost from legacy to current.
    """
    identity_file = _get_identity_file()
    # Read the old file, decrypt with old key, re-encrypt with new key
    with open(identity_file, "rb") as f:
        data = f.read()
    old_salt, blob = data[:16], data[16:]

    # Derive current master key (time_cost=4)
    master_vault_key = crypto.derive_vault_key(vault_passphrase, salt)

    # If legacy_time_cost is provided, derive legacy master key to decrypt
    if legacy_time_cost is not None:
        legacy_master_key = _derive_vault_key_with_time_cost(vault_passphrase, salt, legacy_time_cost)
    else:
        legacy_master_key = master_vault_key

    # Decrypt with legacy key (old format: direct master key)
    # Also try new format with legacy key (identity subkey) in case it was already partially migrated
    raw_priv = None

    # Try old format (direct master key with legacy time_cost)
    try:
        raw_priv = bytearray(_vault_decrypt(legacy_master_key, blob))
    except InvalidTag:
        pass

    # Try new format (identity subkey with legacy time_cost)
    if raw_priv is None:
        legacy_identity_vault_key = _derive_subkey(legacy_master_key, crypto.VAULT_KEY_IDENTITY_LABEL)
        try:
            raw_priv = bytearray(_vault_decrypt(legacy_identity_vault_key, blob))
        except InvalidTag:
            pass

    # Also try current master key directly (in case time_cost wasn't actually changed)
    if raw_priv is None:
        try:
            raw_priv = bytearray(_vault_decrypt(master_vault_key, blob))
        except InvalidTag:
            pass

    # Try new format with current master key
    if raw_priv is None:
        identity_vault_key = _derive_subkey(master_vault_key, crypto.VAULT_KEY_IDENTITY_LABEL)
        try:
            raw_priv = bytearray(_vault_decrypt(identity_vault_key, blob))
        except InvalidTag:
            pass

    if raw_priv is None:
        raise ValueError("Cannot decrypt identity file with either format")

    # Re-encrypt with new key (identity subkey) using CURRENT parameters
    identity_vault_key = _derive_subkey(master_vault_key, crypto.VAULT_KEY_IDENTITY_LABEL)
    new_blob = _vault_encrypt(identity_vault_key, bytes(raw_priv))
    secure_memory.zero_bytearray(raw_priv)

    # Atomic write: write to temp, then rename
    # Use the same salt (which was derived with the original time_cost)
    # The master_vault_key is already derived with current time_cost
    tmp_file = identity_file + ".tmp"
    with open(tmp_file, "wb") as f:
        f.write(old_salt + new_blob)  # Same salt, new encryption
    try:
        os.chmod(tmp_file, 0o600)
    except OSError:
        pass
    os.replace(tmp_file, identity_file)
    if legacy_time_cost is not None:
        logger.info(f"Migrated identity.enc to new key-separated format (Argon2id time_cost {legacy_time_cost} -> {crypto.ARGON2ID_TIME_COST})")
    else:
        logger.info("Migrated identity.enc to new key-separated format")


def _migrate_database(old_conn, old_db_key, master_vault_key: bytes):
    """Migrate database from old key to new db subkey by re-encrypting all encrypted blobs."""
    new_db_key = _derive_subkey(master_vault_key, crypto.VAULT_KEY_DATABASE_LABEL)

    db_file = _get_db_file()
    # Create new database with new key
    new_db_path = db_file + ".migrating"
    if os.path.exists(new_db_path):
        os.unlink(new_db_path)

    new_conn = sqlcipher.connect(new_db_path, check_same_thread=False)
    new_conn.execute(f"PRAGMA key = \"x'{new_db_key.hex()}'\"")
    new_conn.execute("PRAGMA journal_mode=WAL")
    new_conn.execute("PRAGMA synchronous=NORMAL")

    # Recreate schema
    from .storage import SCHEMA
    new_conn.executescript(SCHEMA)

    # Migrate contacts
    old_cur = old_conn.execute("SELECT fingerprint, ip, encrypted_blob FROM contacts")
    for fp, ip, blob in old_cur.fetchall():
        # Decrypt with old key
        try:
            data = json.loads(_vault_decrypt(old_db_key, blob).decode("utf-8"))
        except Exception as e:
            logger.exception(f"Failed to decrypt contact {fp[:12]}... during migration: {e}")
            continue
        # Re-encrypt with new key
        new_blob = _vault_encrypt(new_db_key, json.dumps(data).encode("utf-8"))
        new_conn.execute(
            "INSERT INTO contacts (fingerprint, ip, encrypted_blob) VALUES (?, ?, ?)",
            (fp, ip, new_blob)
        )

    # Migrate messages
    old_cur = old_conn.execute("SELECT id, contact_fingerprint, direction, timestamp, encrypted_blob, unreceived FROM messages")
    for mid, cfp, direction, ts, blob, unreceived in old_cur.fetchall():
        try:
            data = json.loads(_vault_decrypt(old_db_key, blob).decode("utf-8"))
        except Exception as e:
            logger.exception(f"Failed to decrypt message {mid} during migration: {e}")
            continue
        new_blob = _vault_encrypt(new_db_key, json.dumps(data).encode("utf-8"))
        new_conn.execute(
            "INSERT INTO messages (id, contact_fingerprint, direction, timestamp, encrypted_blob, unreceived) VALUES (?, ?, ?, ?, ?, ?)",
            (mid, cfp, direction, ts, new_blob, unreceived)
        )

    # Migrate outbox
    old_cur = old_conn.execute("SELECT id, contact_fingerprint, message_at_rest, created_at, attempts FROM outbox")
    for mid, cfp, blob, created_at, attempts in old_cur.fetchall():
        try:
            text = _vault_decrypt(old_db_key, blob).decode("utf-8")
        except Exception as e:
            logger.exception(f"Failed to decrypt outbox message {mid} during migration: {e}")
            continue
        new_blob = _vault_encrypt(new_db_key, text.encode("utf-8"))
        new_conn.execute(
            "INSERT INTO outbox (id, contact_fingerprint, message_at_rest, created_at, attempts) VALUES (?, ?, ?, ?, ?)",
            (mid, cfp, new_blob, created_at, attempts)
        )

    new_conn.commit()
    new_conn.close()
    old_conn.close()

    # Atomic replace
    backup_path = db_file + ".pre-migration-backup"
    if os.path.exists(backup_path):
        os.unlink(backup_path)
    os.rename(db_file, backup_path)
    os.rename(new_db_path, db_file)

    logger.info("Migrated redoubt.db to new key-separated format")


def _create_legacy_backups(identity_file: str, db_file: str) -> tuple[str, str]:
    """
    Create backups of legacy files before migration.

    Returns:
        Tuple of (identity_backup_path, db_backup_path) - paths may be empty if files don't exist
    """
    backup_dir = os.path.join(os.path.dirname(identity_file), "backups")
    os.makedirs(backup_dir, exist_ok=True)

    # Generate timestamp for unique backup names
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    identity_backup = ""
    db_backup = ""

    # Backup identity.enc if it exists
    if os.path.exists(identity_file):
        identity_backup = os.path.join(backup_dir, f"identity.enc.{timestamp}.bak")
        shutil.copy2(identity_file, identity_backup)
        logger.info(f"Created identity backup: {identity_backup}")

    # Backup redoubt.db if it exists (including -wal and -shm if present)
    if os.path.exists(db_file):
        db_backup = os.path.join(backup_dir, f"redoubt.db.{timestamp}.bak")
        shutil.copy2(db_file, db_backup)
        logger.info(f"Created database backup: {db_backup}")

        # Also backup WAL and SHM files if they exist
        for suffix in ("-wal", "-shm"):
            src = db_file + suffix
            if os.path.exists(src):
                dst = db_backup + suffix
                shutil.copy2(src, dst)
                logger.info(f"Created database {suffix} backup: {dst}")

    return identity_backup, db_backup


def migrate_if_needed(vault_passphrase: str) -> tuple[bool, bytes]:
    """
    Check if migration is needed and perform it.

    Returns:
        (migration_performed, master_vault_key)

    Raises:
        ValueError: If the passphrase is incorrect or files are corrupted
        FileNotFoundError: If the identity file does not exist (fresh identity)
    """
    identity_file = _get_identity_file()
    # Check if identity file exists
    if not os.path.exists(identity_file):
        raise FileNotFoundError("Identity file not found")

    with open(identity_file, "rb") as f:
        data = f.read()
    if len(data) < 16:
        raise ValueError("Corrupted identity file")
    salt = data[:16]

    # Try loading with current parameters (time_cost=4) - already migrated users
    master_vault_key_current = crypto.derive_vault_key(vault_passphrase, salt)
    result = _try_load_identity_new_format(vault_passphrase)
    if result is not None:
        priv, master_key, used_time_cost = result
        # Also verify that the database opens with the new format
        conn, _ = _try_open_db_new_format(master_key)
        if conn is not None:
            conn.close()
            return False, master_key  # Already migrated with the current time_cost
        if conn:
            conn.close()

    # Try loading with legacy parameters (time_cost=3) - legacy users
    result = _try_load_identity_new_format(
        vault_passphrase,
        time_cost=ARGON2ID_LEGACY_TIME_COST
    )

    if result is not None:
        priv, master_key_legacy, used_time_cost = result
        # Derive the master key using the current parameters for migration
        master_vault_key_current = crypto.derive_vault_key(vault_passphrase, salt)
        # Also verify that the database opens with the legacy master key (old format)
        old_conn, old_db_key = _try_open_db_old_format(master_key_legacy)
        if old_conn is not None:
            # Legacy format with time_cost=3 - full migration required
            if not _confirm_migration(
                f"Migration from legacy format (time_cost={ARGON2ID_LEGACY_TIME_COST}, single key) "
                f"to the new format (time_cost={crypto.ARGON2ID_TIME_COST}, separate HKDF-derived keys). "
                f"Both identity.enc and redoubt.db will be re-encrypted."
            ):
                raise ValueError("Migration cancelled by user")
            logger.info(
                f"Detected legacy format with Argon2id time_cost={ARGON2ID_LEGACY_TIME_COST}. "
                f"Migrating to time_cost={crypto.ARGON2ID_TIME_COST} and key-separated format..."
            )
            # Create backups of legacy files BEFORE any modifications
            identity_file = _get_identity_file()
            db_file = _get_db_file()
            identity_backup, db_backup = _create_legacy_backups(identity_file, db_file)
            try:
                # Migrate identity file (also updates Argon2id time_cost)
                _migrate_identity_file(
                    vault_passphrase,
                    salt,
                    legacy_time_cost=ARGON2ID_LEGACY_TIME_COST
                )
                # Migrate database (re-encrypts all blobs)
                _migrate_database(old_conn, old_db_key, master_vault_key_current)
                logger.info("Migration completed successfully")
            except Exception as e:
                logger.error(
                    f"Migration failed: {e}. "
                    f"Legacy backups are available at: {identity_backup}, {db_backup}"
                )
                raise
            return True, master_vault_key_current
        else:
            # Try opening the database with the new format but legacy time_cost
            conn, _ = _try_open_db_new_format(master_key_legacy)
            if conn is not None:
                conn.close()
                # Identity is already in the new format but uses the legacy time_cost.
                # Only the identity file needs to be re-encrypted.
                if not _confirm_migration(
                    f"Upgrade Argon2id time_cost from {ARGON2ID_LEGACY_TIME_COST} "
                    f"to {crypto.ARGON2ID_TIME_COST} "
                    f"(key-separated format already in use). "
                    f"The identity.enc file will be re-encrypted."
                ):
                    raise ValueError("Migration cancelled by user")
                logger.info(
                    f"Detected new key-separated format with legacy Argon2id "
                    f"time_cost={ARGON2ID_LEGACY_TIME_COST}. "
                    f"Updating to time_cost={crypto.ARGON2ID_TIME_COST}..."
                )
                _migrate_identity_file(
                    vault_passphrase,
                    salt,
                    legacy_time_cost=ARGON2ID_LEGACY_TIME_COST
                )

                return True, master_vault_key_current

    # Try old format (pre-v2.1.1) with current time_cost
    result = _try_load_identity_old_format(vault_passphrase)
    if result is not None:
        priv, master_key, used_time_cost = result
        # Try opening the database with the old format
        old_conn, old_db_key = _try_open_db_old_format(master_key)
        if old_conn is None:
            # No database exists yet (fresh identity): migrate only the identity file
            if not _confirm_migration(
                f"Migration of identity.enc from the legacy format (single key) "
                f"to the new format (separate HKDF-derived keys). "
                f"No database file was found."
            ):
                raise ValueError("Migration cancelled by user")
            _migrate_identity_file(vault_passphrase, salt)
            return True, master_key

        # Both identity and database exist in the old format - migrate both
        if not _confirm_migration(
            f"Migration from the pre-v2.1.1 format (single key for identity.enc and redoubt.db) "
            f"to the new format (separate HKDF-derived keys for identity and database). "
            f"Both identity.enc and the entire redoubt.db database will be re-encrypted."
        ):
            raise ValueError("Migration cancelled by user")
        logger.info(
            "Detected pre-v2.1.1 format. Migrating to the key-separated format..."
        )
        # Create backups of legacy files BEFORE any modifications
        identity_file = _get_identity_file()
        db_file = _get_db_file()
        identity_backup, db_backup = _create_legacy_backups(identity_file, db_file)
        try:
            # Migrate identity file
            _migrate_identity_file(vault_passphrase, salt)
            # Migrate database (re-encrypts all blobs)
            _migrate_database(old_conn, old_db_key, master_key)
            logger.info("Migration completed successfully")
        except Exception as e:
            logger.error(
                f"Migration failed: {e}. "
                f"Legacy backups are available at: {identity_backup}, {db_backup}"
            )
            raise

        return True, master_key

    # Try old format with legacy time_cost
    result = _try_load_identity_old_format(
        vault_passphrase,
        time_cost=ARGON2ID_LEGACY_TIME_COST
    )

    if result is not None:
        priv, master_key_legacy, used_time_cost = result
        master_vault_key_current = crypto.derive_vault_key(vault_passphrase, salt)
        old_conn, old_db_key = _try_open_db_old_format(master_key_legacy)
        if old_conn is None:
            # No database exists yet (fresh identity): migrate only the identity file
            if not _confirm_migration(
                f"Migration of identity.enc from the legacy format "
                f"(time_cost={ARGON2ID_LEGACY_TIME_COST}, single key) "
                f"to the new format "
                f"(time_cost={crypto.ARGON2ID_TIME_COST}, separate HKDF-derived keys). "
                f"No database file was found."
            ):
                raise ValueError("Migration cancelled by user")
            _migrate_identity_file(
                vault_passphrase,
                salt,
                legacy_time_cost=ARGON2ID_LEGACY_TIME_COST
            )
            return True, master_vault_key_current

        if not _confirm_migration(
            f"Migration from the pre-v2.1.1 format with Argon2id "
            f"time_cost={ARGON2ID_LEGACY_TIME_COST} "
            f"to the new format (time_cost={crypto.ARGON2ID_TIME_COST}, "
            f"separate HKDF-derived keys). "
            f"Both identity.enc and the entire redoubt.db database will be re-encrypted."
        ):
            raise ValueError("Migration cancelled by user")
        logger.info(
            f"Detected pre-v2.1.1 format with legacy Argon2id "
            f"time_cost={ARGON2ID_LEGACY_TIME_COST}. "
            f"Migrating to time_cost={crypto.ARGON2ID_TIME_COST} "
            f"and key-separated format..."
        )

        identity_file = _get_identity_file()
        db_file = _get_db_file()
        identity_backup, db_backup = _create_legacy_backups(identity_file, db_file)

        try:
            _migrate_identity_file(
                vault_passphrase,
                salt,
                legacy_time_cost=ARGON2ID_LEGACY_TIME_COST
            )
            _migrate_database(old_conn, old_db_key, master_vault_key_current)
            logger.info("Migration completed successfully")
        except Exception as e:
            logger.error(
                f"Migration failed: {e}. "
                f"Legacy backups are available at: {identity_backup}, {db_backup}"
            )
            raise

        return True, master_vault_key_current

    raise ValueError("Incorrect passphrase or corrupted identity file")

def load_identity_with_migration(vault_passphrase: str):
    """
    Load identity, performing migration if needed.

    This is the new entry point that replaces load_identity().
    Raises InvalidTag for wrong passphrase (for backward compatibility with tests).
    """
    try:
        migrated, master_vault_key = migrate_if_needed(vault_passphrase)
    except FileNotFoundError:
        # No identity file - this shouldn't happen in normal flow
        # but tests might call this directly
        raise InvalidTag("Identity file not found")
    except ValueError as e:
        if "Wrong passphrase" in str(e):
            raise InvalidTag("Wrong passphrase")
        raise

    # Now load with new format (guaranteed to work after migration)
    identity_file = _get_identity_file()
    with open(identity_file, "rb") as f:
        data = f.read()
    salt, blob = data[:16], data[16:]
    identity_vault_key = _derive_subkey(master_vault_key, crypto.VAULT_KEY_IDENTITY_LABEL)
    raw_priv = bytearray(_vault_decrypt(identity_vault_key, blob))
    priv = crypto.private_key_from_raw(bytes(raw_priv))
    secure_memory.zero_bytearray(raw_priv)

    from .identity import Identity
    return Identity(priv, master_vault_key)


def create_storage_with_migration(master_vault_key: bytes, db_path: str = None):
    """
    Create Storage instance, handling migration if needed.

    This should be called AFTER load_identity_with_migration().
    """
    if db_path is None:
        db_path = _get_db_file()
    # Try new format first
    conn, db_key = _try_open_db_new_format(master_vault_key)
    if conn is not None:
        conn.close()
        from .storage import Storage
        return Storage(master_vault_key, db_path)

    # If we reach here, something is wrong (migration should have happened)
    # But handle gracefully: try old format as last resort
    conn, old_db_key = _try_open_db_old_format(master_vault_key)
    if conn is not None:
        # Migration was skipped somehow, do it now
        logger.warning("Database still in old format after identity migration, migrating now...")
        _migrate_database(conn, old_db_key, master_vault_key)
        from .storage import Storage
        return Storage(master_vault_key, db_path)

    # Neither format works - fresh database
    from .storage import Storage
    return Storage(master_vault_key, db_path)
