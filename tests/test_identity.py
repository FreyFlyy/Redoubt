import os
import stat

import pytest
from cryptography.exceptions import InvalidTag

from redoubt import identity


@pytest.fixture(autouse=True)
def isolated_identity(tmp_path, monkeypatch, fast_kdf):
    monkeypatch.setattr(identity, "IDENTITY_DIR", str(tmp_path))
    monkeypatch.setattr(identity, "IDENTITY_FILE", str(tmp_path / "identity.enc"))


def test_create_then_load_same_identity():
    assert not identity.identity_exists()
    created = identity.create_identity("passphrase-123")
    assert identity.identity_exists()
    loaded = identity.load_identity("passphrase-123")
    assert loaded.fingerprint == created.fingerprint
    assert loaded.public_key_raw == created.public_key_raw
    assert loaded.vault_key == created.vault_key


def test_identity_file_permissions():
    identity.create_identity("passphrase-123")
    mode = stat.S_IMODE(os.stat(identity.IDENTITY_FILE).st_mode)
    assert mode == 0o600


def test_private_key_not_stored_in_clear():
    ident = identity.create_identity("passphrase-123")
    from redoubt import crypto
    raw_priv = crypto.private_key_to_raw(ident.private_key)
    with open(identity.IDENTITY_FILE, "rb") as f:
        assert raw_priv not in f.read()


def test_wrong_passphrase_rejected():
    identity.create_identity("passphrase-123")
    with pytest.raises(InvalidTag):
        identity.load_identity("passphrase-124")


def test_wipe_makes_vault_key_unavailable():
    ident = identity.create_identity("passphrase-123")
    ident.wipe()
    with pytest.raises(ValueError):
        _ = ident.vault_key


def test_short_fingerprint_is_prefix():
    ident = identity.create_identity("passphrase-123")
    assert ident.fingerprint.startswith(ident.name_short_fp)
    assert len(ident.name_short_fp) == 16


def test_interactive_rejects_short_passphrase(monkeypatch):
    monkeypatch.setattr(identity.getpass, "getpass", lambda prompt="": "short")
    with pytest.raises(SystemExit):
        identity.load_or_create_identity_interactive()
    assert not identity.identity_exists()


def test_interactive_rejects_mismatch(monkeypatch):
    answers = iter(["longenough-1", "longenough-2"])
    monkeypatch.setattr(identity.getpass, "getpass", lambda prompt="": next(answers))
    with pytest.raises(SystemExit):
        identity.load_or_create_identity_interactive()
    assert not identity.identity_exists()


def test_interactive_wrong_passphrase_exits(monkeypatch):
    identity.create_identity("passphrase-123")
    monkeypatch.setattr(identity.getpass, "getpass", lambda prompt="": "wrong-passphrase")
    with pytest.raises(SystemExit):
        identity.load_or_create_identity_interactive()


## ---------------------------------------------------------------- migration tests

def test_migration_from_old_format(tmp_path, vault_key, fast_kdf, monkeypatch):
    """Test that old-format identity.enc and redoubt.db are migrated transparently."""
    import json
    import sqlcipher3.dbapi2 as sqlcipher
    from redoubt import crypto, storage
    
    # Set up old-format paths
    old_identity_dir = tmp_path / ".redoubt"
    old_identity_file = old_identity_dir / "identity.enc"
    old_db_file = old_identity_dir / "redoubt.db"
    old_identity_dir.mkdir()
    
    passphrase = "migration-test-passphrase"
    
    # Create old-format identity (encrypted directly with master key)
    priv = crypto.generate_x25519_keypair()
    raw_priv = bytearray(crypto.private_key_to_raw(priv))
    salt = os.urandom(16)
    master_key = crypto.derive_vault_key(passphrase, salt)
    old_blob = crypto.vault_encrypt(master_key, bytes(raw_priv))
    
    with open(old_identity_file, "wb") as f:
        f.write(salt + old_blob)
    os.chmod(old_identity_file, 0o600)
    
    # The contact fingerprint must match the identity's fingerprint
    fp = crypto.fingerprint_of(crypto.public_key_to_raw(priv.public_key()))
    
    # Create old-format database with some data
    contact_data = {"name": "Old Contact", "ip": "10.0.0.1", "port": 60717, "public_key_b64": "cHVi"}
    msg_data = {"text": "Old message", "peer_ip": "10.0.0.1"}
    
    old_conn = sqlcipher.connect(str(old_db_file), check_same_thread=False)
    old_conn.execute(f"PRAGMA key = \"x'{master_key.hex()}'\"")
    old_conn.executescript(storage.SCHEMA)
    old_blob = crypto.vault_encrypt(master_key, json.dumps(contact_data).encode())
    old_conn.execute("INSERT INTO contacts (fingerprint, ip, encrypted_blob) VALUES (?, ?, ?)", (fp, "10.0.0.1", old_blob))
    old_blob = crypto.vault_encrypt(master_key, json.dumps(msg_data).encode())
    old_conn.execute("INSERT INTO messages (id, contact_fingerprint, direction, timestamp, encrypted_blob, unreceived) VALUES (?, ?, ?, ?, ?, ?)", 
                     ("old-msg", fp, "in", 1000, old_blob, 1))
    old_conn.commit()
    old_conn.close()
    
    # Now point the modules to the test directory and load
    # Migration module uses lazy getters from identity/storage, so patch those
    monkeypatch.setattr(identity, "IDENTITY_DIR", str(old_identity_dir))
    monkeypatch.setattr(identity, "IDENTITY_FILE", str(old_identity_file))
    monkeypatch.setattr(storage, "DB_DIR", str(old_identity_dir))
    monkeypatch.setattr(storage, "DB_FILE", str(old_db_file))
    
    # Load identity - should trigger migration
    loaded_ident = identity.load_identity(passphrase)
    assert loaded_ident.fingerprint == fp
    
    # Verify database was migrated and data is accessible
    # Pass db_path explicitly because Storage.__init__ default is evaluated at definition time
    store = storage.Storage(loaded_ident.vault_key, db_path=str(old_db_file))
    contact = store.get_contact(fp)
    assert contact is not None
    assert contact[1] == "Old Contact"
    assert contact[2] == "10.0.0.1"
    
    history = store.get_history(fp)
    assert len(history) == 1
    assert history[0]["text"] == "Old message"
    
    # Verify new data can be added (uses new format)
    fp2 = "b" * 64
    store.add_contact(fp2, "New Contact", "10.0.0.2", 60717, "cHVi")
    contact2 = store.get_contact(fp2)
    assert contact2[1] == "New Contact"
    
    # Verify subsequent load works without re-migration (fast path)
    loaded_ident2 = identity.load_identity(passphrase)
    assert loaded_ident2.fingerprint == loaded_ident.fingerprint
    store2 = storage.Storage(loaded_ident2.vault_key, db_path=str(old_db_file))
    assert store2.get_contact(fp)[1] == "Old Contact"
    assert store2.get_contact(fp2)[1] == "New Contact"


def test_migration_fresh_identity_no_db(tmp_path, monkeypatch):
    """Test migration when only identity.enc exists (no database yet)."""
    import sqlcipher3.dbapi2 as sqlcipher
    from redoubt import crypto, storage
    
    old_identity_dir = tmp_path / ".redoubt"
    old_identity_file = old_identity_dir / "identity.enc"
    old_identity_dir.mkdir()
    
    passphrase = "fresh-identity-passphrase"
    priv = crypto.generate_x25519_keypair()
    raw_priv = bytearray(crypto.private_key_to_raw(priv))
    salt = os.urandom(16)
    master_key = crypto.derive_vault_key(passphrase, salt)
    old_blob = crypto.vault_encrypt(master_key, bytes(raw_priv))
    
    with open(old_identity_file, "wb") as f:
        f.write(salt + old_blob)
    os.chmod(old_identity_file, 0o600)
    
    monkeypatch.setattr(identity, "IDENTITY_DIR", str(old_identity_dir))
    monkeypatch.setattr(identity, "IDENTITY_FILE", str(old_identity_file))
    monkeypatch.setattr(storage, "DB_DIR", str(old_identity_dir))
    monkeypatch.setattr(storage, "DB_FILE", str(old_identity_dir / "redoubt.db"))
    
    # Load identity - should migrate identity file only
    loaded_ident = identity.load_identity(passphrase)
    assert loaded_ident.fingerprint == crypto.fingerprint_of(crypto.public_key_to_raw(priv.public_key()))
    
    # Database should be created fresh on first Storage access
    store = storage.Storage(loaded_ident.vault_key, db_path=str(old_identity_dir / "redoubt.db"))
    assert store.get_contact("a" * 64) is None
