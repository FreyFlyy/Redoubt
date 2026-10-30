### identity.py

"""
Identity management module for Redoubt
"""

import os
import getpass
from cryptography.exceptions import InvalidTag
from . import crypto
from . import secure_memory
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)


## Identity paths

IDENTITY_DIR = os.path.join(os.path.expanduser("~"), ".redoubt")
IDENTITY_FILE = os.path.join(IDENTITY_DIR, "identity.enc")


## Identity class

class Identity:
    def __init__(self, private_key, vault_key: bytes):
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.public_key_raw = crypto.public_key_to_raw(self.public_key)
        self.fingerprint = crypto.fingerprint_of(self.public_key_raw)
        self._vault_key_buf = secure_memory.SecureBuffer(vault_key)

    @property
    def vault_key(self) -> bytes:
        """Immutable copy for storage.py/crypto.vault_encrypt/decrypt"""
        return bytes(self._vault_key_buf.view())

    @property
    def name_short_fp(self) -> str:
        """Return shortened fingerprint (can be logged, as only part of the entire sha256)"""
        return self.fingerprint[:16]

    def wipe(self):
        """Call when closing the app: zeroes the mlocked vault key"""
        self._vault_key_buf.zero()


## Identity creation and loading

def _ensure_dir():
    """Ensures the existence of the identity/storage folder exists (~/.redoubt)"""
    os.makedirs(IDENTITY_DIR, exist_ok=True)

def identity_exists() -> bool:
    """Checks for any identity in the folder"""
    return os.path.exists(IDENTITY_FILE)

def create_identity(vault_passphrase: str) -> Identity:
    """Creates identity if no other identity is found. Takes a passphrase and generates Priv/Pub X25519 key pair"""
    _ensure_dir()
    # Generate private key
    priv = crypto.generate_x25519_keypair()
    raw_priv = bytearray(crypto.private_key_to_raw(priv))

    salt = os.urandom(16)
    # Generate vault key from password
    vault_key = crypto.derive_vault_key(vault_passphrase, salt)
    encrypted = crypto.vault_encrypt(vault_key, bytes(raw_priv))
    secure_memory.zero_bytearray(raw_priv)  # zeroing of raw_private key

    with open(IDENTITY_FILE, "wb") as f:
        f.write(salt + encrypted)

    try:
        os.chmod(IDENTITY_FILE, 0o600)
    except OSError:
        pass  # best-effort on Windows, where chmod ha limited effect

    return Identity(priv, vault_key)

def load_identity(vault_passphrase: str) -> Identity:
    """Loads identity from previously created file"""
    with open(IDENTITY_FILE, "rb") as f:
        data = f.read()
    salt, blob = data[:16], data[16:]
    vault_key = crypto.derive_vault_key(vault_passphrase, salt)
    raw_priv = bytearray(crypto.vault_decrypt(vault_key, blob))  # built-in exception if passphrase is wrong
    priv = crypto.private_key_from_raw(bytes(raw_priv))
    secure_memory.zero_bytearray(raw_priv)  # zeroing of raw_private key
    return Identity(priv, vault_key)

def load_or_create_identity_interactive() -> Identity:
    """Interactive create/load identity from CLI"""
    if identity_exists():
        pw = getpass.getpass("Vault passphrase (unlocks local identity): ")
        try:
            return load_identity(pw)
        except InvalidTag:  # Specific exception, either passphrase is wrong or the identity was corrupted
            print("Wrong passphrase (or corrupted identity file)")
            raise SystemExit(1)
        except (OSError, ValueError) as e:  # Other exceptions (permission denied, full disk...)
            logger.exception(f"System Error loading identity (not a wrong password or corrupted file). Could be wrong permissions, full disk or other issues): {e}")
            print(f"System Error loading identity (not a wrong password or corrupted file). Could be wrong permissions, full disk or other issues): {e}")
            raise SystemExit(1)
    else:
        print("No identity found. Creating a new one...")
        pw1 = getpass.getpass("Choose a passphrase (protects the identity and the contacts/messages database, minimum 8 characters): ")
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw1 != pw2:
            print("Passphrases do not match. ABORTING!")
            raise SystemExit(1)
        if len(pw1) < 8:
            print("Short passphrase, security risk. ABORTING!")
            raise SystemExit(1)
        return create_identity(pw1)
