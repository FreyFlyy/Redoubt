import glob
import os
import time

import pytest

from redoubt import storage as st

FP1, FP2 = "1" * 64, "2" * 64
SECRET_NAME = "zzz-very-secret-name"
SECRET_TEXT = "zzz-very-secret-text"
SECRET_IP = "203.0.113.77"


@pytest.fixture
def db(tmp_path, vault_key):
    s = st.Storage(vault_key, str(tmp_path / "t.db"))
    yield s
    s.conn.close()


def test_contact_crud(db):
    db.add_contact(FP1, "Bob", "10.0.0.2", 60717, "cHVi")
    assert db.get_contact(FP1) == (FP1, "Bob", "10.0.0.2", 60717, "cHVi")
    assert db.get_contact("f" * 64) is None
    assert db.get_contact_by_ip("10.0.0.2")[0][0] == FP1
    assert db.get_contact_by_ip("10.9.9.9") == []


def test_contacts_sorted_case_insensitive(db):
    db.add_contact(FP1, "bob", "1.1.1.1", 1, "k")
    db.add_contact(FP2, "Alice", "2.2.2.2", 1, "k")
    assert [c[1] for c in db.list_contacts()] == ["Alice", "bob"]


def test_same_ip_returns_all_candidates(db):
    db.add_contact(FP1, "a", "10.0.0.2", 1, "k")
    db.add_contact(FP2, "b", "10.0.0.2", 1, "k")
    assert len(db.get_contact_by_ip("10.0.0.2")) == 2


def test_messages_history_order_and_dedup(db):
    db.store_message("m1", FP1, "in", 100, "first", "10.0.0.2", unreceived=1)
    db.store_message("m2", FP1, "out", 200, "second")
    db.store_message("m2", FP1, "out", 300, "DUPLICATE")  # same id: ignored
    hist = db.get_history(FP1)
    assert [m["text"] for m in hist] == ["first", "second"]
    assert db.message_exists("m1") and not db.message_exists("nope")
    assert db.get_last_message(FP1)["text"] == "second"
    assert db.get_last_message(FP2) is None


def test_history_limit_returns_latest_in_order(db):
    for i in range(10):
        db.store_message(f"m{i}", FP1, "in", i, f"t{i}")
    assert [m["text"] for m in db.get_history(FP1, limit=3)] == ["t7", "t8", "t9"]


def test_unread_counter(db):
    db.store_message("m1", FP1, "in", 1, "a", unreceived=1)
    db.store_message("m2", FP1, "in", 2, "b", unreceived=1)
    db.store_message("m3", FP2, "in", 3, "c", unreceived=1)
    assert db.count_unread_messages(FP1) == 2
    db.mark_messages_as_read(FP1)
    assert db.count_unread_messages(FP1) == 0
    assert db.count_unread_messages(FP2) == 1


def test_outbox_lifecycle(db):
    db.enqueue_outbox("o1", FP1, "hello")
    time.sleep(1.1)  # created_at has 1s resolution
    db.enqueue_outbox("o2", FP1, "world")
    assert db.has_pending(FP1) and not db.has_pending(FP2)
    assert db.pending_for(FP1) == [("o1", "hello"), ("o2", "world")]
    assert db.get_pending_ids(FP1) == {"o1", "o2"}
    db.bump_attempts("o1")
    db.delete_outbox("o1")
    assert db.get_pending_ids(FP1) == {"o2"}


def test_delete_contact_cascades(db):
    db.add_contact(FP1, "Bob", "1.1.1.1", 1, "k")
    db.store_message("m1", FP1, "in", 1, "x")
    db.enqueue_outbox("o1", FP1, "y")
    db.delete_contact(FP1)
    assert db.get_contact(FP1) is None
    assert db.get_history(FP1) == []
    assert not db.has_pending(FP1)


def test_clear_history_keeps_contact(db):
    db.add_contact(FP1, "Bob", "1.1.1.1", 1, "k")
    db.store_message("m1", FP1, "in", 1, "x")
    db.clear_history(FP1)
    assert db.get_history(FP1) == []
    assert db.get_contact(FP1) is not None


def test_reopen_with_same_key_and_reject_wrong_key(tmp_path, vault_key):
    path = str(tmp_path / "t.db")
    s = st.Storage(vault_key, path)
    s.add_contact(FP1, "Bob", "1.1.1.1", 1, "k")
    s.conn.close()
    s2 = st.Storage(vault_key, path)
    assert s2.get_contact(FP1)[1] == "Bob"
    s2.conn.close()
    with pytest.raises(ValueError):
        st.Storage(os.urandom(32), path)


def test_no_plaintext_on_disk(tmp_path, vault_key):
    path = str(tmp_path / "t.db")
    s = st.Storage(vault_key, path)
    s.add_contact(FP1, SECRET_NAME, SECRET_IP, 60717, "cHVi")
    s.store_message("m1", FP1, "in", 1, SECRET_TEXT, SECRET_IP)
    s.enqueue_outbox("o1", FP1, SECRET_TEXT)
    s.conn.commit()
    blobs = b""
    for f in glob.glob(path + "*"):  # db + wal + shm
        with open(f, "rb") as fh:
            blobs += fh.read()
    s.conn.close()
    assert b"SQLite format 3" not in blobs[:16]
    assert SECRET_NAME.encode() not in blobs
    assert SECRET_TEXT.encode() not in blobs
