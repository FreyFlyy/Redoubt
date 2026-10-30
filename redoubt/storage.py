### storage.py

"""
Storage module for Redoubt
"""

import os
import time
import json
import threading
from sqlcipher3 import dbapi2 as sqlcipher
from . import crypto
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)


## Path variables and DB schema

DB_DIR = os.path.join(os.path.expanduser("~"), ".redoubt")
DB_FILE = os.path.join(DB_DIR, "redoubt.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (
    fingerprint TEXT PRIMARY KEY,      -- hash of PubKey (doesn't reveal identity but can identify it)
    ip TEXT,                           -- plaintext, for identification
    encrypted_blob BLOB NOT NULL       -- encrypted {name, ip, port, public_key_b64}
);

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,               -- casual UUID4
    contact_fingerprint TEXT NOT NULL, -- plain, needed for identification
    direction TEXT NOT NULL,           -- 'out' or 'in' (direction of the message)
    timestamp INTEGER NOT NULL,        -- plain, needed for ORDER BY
    encrypted_blob BLOB NOT NULL,      -- encrypted {text, peer_ip}
    unreceived INTEGER NOT NULL DEFAULT 0  -- plain, to know what messages to retransmit
);

CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY,               -- casual UUID4
    contact_fingerprint TEXT NOT NULL, -- plain, needed for identification
    message_at_rest BLOB NOT NULL,   -- encrypted
    created_at INTEGER NOT NULL,       -- timestamp of original send, for ORDER_BY
    attempts INTEGER NOT NULL DEFAULT 0 -- number of retransmission attempts
);
"""


## Storage clasS

class Storage:
    def __init__(self, vault_key: bytes, db_path: str = DB_FILE):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.vault_key = vault_key
        self.conn = sqlcipher.connect(db_path, check_same_thread=False)

        self.conn.execute(f"PRAGMA key = \"x'{self.vault_key.hex()}'\"")
        try:
            self.conn.execute("SELECT count(*) FROM sqlite_master")
        except Exception:
            self.conn.close()
            raise ValueError("Cannot open database: wrong passphrase or corrupted data")

        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")

        self._lock = threading.Lock()
        self.conn.executescript(SCHEMA)
        self.conn.commit()


    ## Encryption / Decryption

    def _encrypt_contact(self, name, ip, port, public_key_b64) -> bytes:
        """Encrypts a contact entry for storage"""
        payload = json.dumps({
            "name": name,
            "ip": ip,
            "port": port,
            "public_key_b64": public_key_b64,
        }).encode("utf-8")
        return crypto.vault_encrypt(self.vault_key, payload)

    def _decrypt_contact(self, fingerprint, blob):
        """Decrypts a contact entry for reading"""
        try:
            data = json.loads(crypto.vault_decrypt(self.vault_key, blob).decode("utf-8"))
        except Exception as e:
            logger.exception(f"Contact {fingerprint[:12]}... impossible to decrypt (wrong vault_key or corrupted database): {e}")
            return (fingerprint, "[CONTACT DECRYPT ERROR]", "?", 0, "")
        return (
            fingerprint,
            data["name"],
            data["ip"],
            data["port"],
            data["public_key_b64"],
        )

    def _encrypt_message(self, text: str, peer_ip) -> bytes:
        """Encrypts a message entry for storage"""
        payload = json.dumps({"text": text, "peer_ip": peer_ip}).encode("utf-8")
        return crypto.vault_encrypt(self.vault_key, payload)

    def _decrypt_message(self, blob):
        """Decrypts a message entry for reading"""
        try:
            data = json.loads(crypto.vault_decrypt(self.vault_key, blob).decode("utf-8"))
            return data["text"], data.get("peer_ip")
        except Exception:
            return "[MESSAGE DECRYPTION ERROR]", None


    ## Contacts

    def add_contact(self, fingerprint, name, ip, port, public_key_b64):
        """Add contact passing Name, IP, port (default), PubKey b64 and Fingerprint"""
        blob = self._encrypt_contact(name, ip, port, public_key_b64)
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO contacts (fingerprint, ip, encrypted_blob) VALUES (?, ?, ?)",
                (fingerprint, ip, blob),
            )
            self.conn.commit()

    def delete_contact(self, fingerprint):
        """Remove contact by passing its Fingerprint"""
        with self._lock:
            self.conn.execute("DELETE FROM contacts WHERE fingerprint = ?", (fingerprint,))
            self.conn.execute("DELETE FROM messages WHERE contact_fingerprint = ?", (fingerprint,))
            self.conn.execute("DELETE FROM outbox WHERE contact_fingerprint = ?", (fingerprint,))
            self.conn.commit()

    def get_contact(self, fingerprint):
        """Get contact from Fingerprint"""
        cur = self.conn.execute("SELECT fingerprint, encrypted_blob FROM contacts WHERE fingerprint = ?", (fingerprint,))
        row = cur.fetchone()
        if row is None:
            return None
        fp, blob = row
        return self._decrypt_contact(fp, blob)

    def get_last_message(self, contact_fingerprint):
        """Get last message from a contact"""
        cur = self.conn.execute(
            """
            SELECT direction, timestamp, encrypted_blob
            FROM messages
            WHERE contact_fingerprint = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (contact_fingerprint,),
        )

        row = cur.fetchone()
        if row is None: # no messages
            return None

        direction, timestamp, blob = row
        text, _peer_ip = self._decrypt_message(blob)

        return {
            "direction": direction,
            "timestamp": timestamp,
            "text": text
        }

    def list_contacts(self):
        """List all contacts"""
        cur = self.conn.execute("SELECT fingerprint, encrypted_blob FROM contacts")
        rows = [self._decrypt_contact(fp, blob) for fp, blob in cur.fetchall()]
        rows.sort(key=lambda row: row[1].lower())
        return rows

    def get_contact_by_ip(self, ip):
        """Get all contact rows matching an IP (can be >1 in LANs and special NATs)"""
        cur = self.conn.execute("SELECT fingerprint, encrypted_blob FROM contacts WHERE ip = ?", (ip,))
        return [self._decrypt_contact(fp, blob) for fp, blob in cur.fetchall()]


    ## Messages

    def count_unread_messages(self, contact_fingerprint) -> int:
        """Returns the number of unread messages by us sent by a contact"""
        cur = self.conn.execute("SELECT COUNT(*) FROM messages WHERE contact_fingerprint = ? AND unreceived = 1", (contact_fingerprint,))
        return cur.fetchone()[0]

    def mark_messages_as_read(self, contact_fingerprint):
        """Set as received all pending messages of a contact"""
        with self._lock:
            self.conn.execute("UPDATE messages SET unreceived = 0 WHERE contact_fingerprint = ? AND unreceived = 1", (contact_fingerprint,))
            self.conn.commit()

    def store_message(self, msg_id, contact_fingerprint, direction, timestamp, plaintext, peer_ip=None, unreceived=0):
        """Store a message with its received status"""
        blob = self._encrypt_message(plaintext, peer_ip)
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO messages "
                "(id, contact_fingerprint, direction, timestamp, encrypted_blob, unreceived) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (msg_id, contact_fingerprint, direction, timestamp, blob, unreceived),
            )
            self.conn.commit()

    def message_exists(self, msg_id) -> bool:
        """Returns True if the same message already exists (using ID not text), else False"""
        cur = self.conn.execute("SELECT 1 FROM messages WHERE id = ? LIMIT 1", (msg_id,))
        return cur.fetchone() is not None

    def get_history(self, contact_fingerprint, limit=200):
        """Get message history for a specific contact (last N messages, oldest first)"""
        cur = self.conn.execute(    # get in descending order (to get last 200)
            "SELECT id, direction, timestamp, encrypted_blob FROM messages "
            "WHERE contact_fingerprint = ? ORDER BY timestamp DESC LIMIT ?",
            (contact_fingerprint, limit),
        )
        rows = cur.fetchall()
        out = []
        for mid, direction, ts, blob in reversed(rows): # reverse to mantain timestamp order
            text, peer_ip = self._decrypt_message(blob)
            out.append({"id": mid, "direction": direction, "timestamp": ts, "text": text, "peer_ip": peer_ip})
        return out

    def clear_history(self, contact_fingerprint):
        """Clear message history for a specific contact"""
        with self._lock:
            self.conn.execute("DELETE FROM messages WHERE contact_fingerprint = ?", (contact_fingerprint,))
            self.conn.commit()


    ## Outbox

    def enqueue_outbox(self, msg_id, contact_fingerprint, plaintext):
        """Enqueue a message for a contact in the "unreceived" table"""
        blob = crypto.vault_encrypt(self.vault_key, plaintext.encode("utf-8"))
        with self._lock:
            self.conn.execute(
                "INSERT INTO outbox (id, contact_fingerprint, message_at_rest, created_at, attempts) "
                "VALUES (?, ?, ?, ?, 0)",
                (msg_id, contact_fingerprint, blob, int(time.time())),
            )
            self.conn.commit()

    def pending_for(self, contact_fingerprint):
        """Get "pending" messages for a specific contact (a row exists in outbox <=> it's pending)"""
        cur = self.conn.execute(
            "SELECT id, message_at_rest FROM outbox "
            "WHERE contact_fingerprint = ? ORDER BY created_at ASC",
            (contact_fingerprint,),
        )
        out = []
        for mid, blob in cur.fetchall():
            text = crypto.vault_decrypt(self.vault_key, blob).decode("utf-8")
            out.append((mid, text))
        return out

    def delete_outbox(self, msg_id):
        """Delete a message from the "pending" outbox"""
        with self._lock:
            self.conn.execute("DELETE FROM outbox WHERE id = ?", (msg_id,))
            self.conn.commit()

    def bump_attempts(self, msg_id):
        """Increase retransmission attempts by one for a specific message"""
        with self._lock:
            self.conn.execute("UPDATE outbox SET attempts = attempts + 1 WHERE id = ?", (msg_id,))
            self.conn.commit()

    def has_pending(self, contact_fingerprint) -> bool:
        """Check for pending messages for a specific contact"""
        cur = self.conn.execute("SELECT COUNT(*) FROM outbox WHERE contact_fingerprint = ?", (contact_fingerprint,))
        return cur.fetchone()[0] > 0

    def get_pending_ids(self, contact_fingerprint) -> set:
        """Return the set of message IDs for a contact still awaiting an ACK (still present in outbox, no decryption needed)"""
        cur = self.conn.execute("SELECT id FROM outbox WHERE contact_fingerprint = ?", (contact_fingerprint,))
        return {row[0] for row in cur.fetchall()}
