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
