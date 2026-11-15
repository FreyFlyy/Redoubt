"""Onion contacts in storage/validation/CLI, and the OnionService orchestrator (with a fake Tor)."""
import pytest

from redoubt import app, contact_validation as cv, crypto, identity as idmod, network, onion, onion_service as osvc, protocol as proto, storage as st, tor_manager as tm

ADDR = onion.address_from_seed(bytes(range(32)))


@pytest.fixture
def ident(vault_key):
    i = idmod.Identity(crypto.generate_x25519_keypair(), vault_key)
    yield i
    i.wipe()


@pytest.fixture
def store(tmp_path, vault_key):
    s = st.Storage(vault_key, str(tmp_path / "o.db"))
    yield s
    s.conn.close()


def card():
    raw = crypto.public_key_to_raw(crypto.generate_x25519_keypair().public_key())
    return proto.b64(raw), crypto.fingerprint_of(raw)


## ---------------------------------------------------------------- contact ids

def test_contact_id_helpers_roundtrip():
    fp = "ab" * 32
    assert cv.make_contact_id(fp) == fp and cv.make_contact_id(fp, onion=True) == fp + "-onion"
    assert cv.contact_fingerprint(fp + "-onion") == fp and cv.contact_fingerprint(fp) == fp
    assert cv.contact_id_for(fp, ADDR) == fp + "-onion" and cv.contact_id_for(fp, "10.0.0.1") == fp
    assert cv.display_name(fp + "-onion", "Bob") == "(On) Bob" and cv.display_name(fp, "Bob") == "Bob"


## ---------------------------------------------------------------- validation

def test_validation_accepts_onion_and_returns_the_real_fingerprint(store, ident):
    pub, fp = card()
    name, addr, _, got_fp = cv.validate_new_contact(store, ident, " Bob ", " " + ADDR.upper() + " ", pub, fp)
    assert (name, addr, got_fp) == ("Bob", ADDR, fp)


def test_same_key_may_be_saved_once_per_transport_but_not_twice(store, ident):
    pub, fp = card()
    store.add_contact(fp, "Bob", "10.0.0.1", 1, pub)
    cv.validate_new_contact(store, ident, "Bob", ADDR, pub, fp)                      # the onion twin is fine
    store.add_contact(fp + "-onion", "Bob", ADDR, 1, pub)
    with pytest.raises(ValueError, match="onion contact"):
        cv.validate_new_contact(store, ident, "Bob2", ADDR, pub, fp)
    with pytest.raises(ValueError, match="already exists"):
        cv.validate_new_contact(store, ident, "Bob2", "10.0.0.2", pub, fp)


@pytest.mark.parametrize("bad", ["10.0.0.1.onion", "x.onion", ADDR[:-7] + "aaaaaaa.onion", "::1", "example.com", "0.0.0.0", "224.0.0.1"])
def test_validation_rejects_bad_addresses(store, ident, bad):
    pub, fp = card()
    with pytest.raises(ValueError):
        cv.validate_new_contact(store, ident, "Bob", bad, pub, fp)


@pytest.mark.parametrize("name", ["(On) Bob", "(on) bob", " (ON)x"])
def test_names_cannot_fake_the_onion_prefix(store, ident, name):
    pub, fp = card()
    with pytest.raises(ValueError, match=r"\(On\)"):
        cv.validate_new_contact(store, ident, name, "10.0.0.1", pub, fp)


## ---------------------------------------------------------------- storage

def test_storage_keeps_ip_and_onion_twins_separate_and_sorted(store):
    pub, fp = card()
    store.add_contact(fp + "-onion", "Bob", ADDR, 60717, pub)
    store.add_contact(fp, "Bob", "10.0.0.1", 60717, pub)
    assert [c[0] for c in store.list_contacts()] == [fp, fp + "-onion"]             # same name: IP first
    assert [c[0] for c in store.get_onion_contacts()] == [fp + "-onion"]
    assert [c[0] for c in store.get_contact_by_ip("10.0.0.1")] == [fp]
    assert store.get_contact_by_ip(ADDR) == [] or store.get_contact_by_ip(ADDR)[0][0] == fp + "-onion"
    store.delete_contact(fp + "-onion")
    assert store.get_contact(fp) is not None and store.get_contact(fp + "-onion") is None


def test_storage_refuses_a_contact_id_that_disagrees_with_its_address(store):
    pub, fp = card()
    with pytest.raises(ValueError):
        store.add_contact(fp, "x", ADDR, 1, pub)
    with pytest.raises(ValueError):
        store.add_contact(fp + "-onion", "x", "10.0.0.1", 1, pub)


def test_revoking_one_twin_keeps_the_other_chat(store):
    pub, fp = card()
    store.add_contact(fp, "Bob", "10.0.0.1", 1, pub); store.add_contact(fp + "-onion", "Bob", ADDR, 1, pub)
    store.store_message("m1", fp, "in", 1, "ip msg"); store.store_message("m2", fp + "-onion", "in", 2, "onion msg")
    store.delete_contact(fp + "-onion")
    assert [m["text"] for m in store.get_history(fp)] == ["ip msg"] and store.get_history(fp + "-onion") == []


def test_secrets_roundtrip_are_encrypted_and_bound_to_their_name(store):
    assert store.get_secret("k") is None
    store.set_secret("k", b"\x00secret\x00")
    assert store.get_secret("k") == b"\x00secret\x00"
    raw = store.conn.execute("SELECT encrypted_blob FROM secrets").fetchone()[0]
    assert b"secret" not in raw
    store.conn.execute("INSERT INTO secrets VALUES ('other', ?)", (raw,)); store.conn.commit()   # blob moved under another name
    assert store.get_secret("other") is None
    store.delete_secret("k")
    assert store.get_secret("k") is None


def test_secrets_survive_reopening_the_database(tmp_path, vault_key):
    path = str(tmp_path / "r.db")
    a = st.Storage(vault_key, path); a.set_secret("s", b"v"); a.conn.close()
    b = st.Storage(vault_key, path)
    assert b.get_secret("s") == b"v"; b.conn.close()


## ---------------------------------------------------------------- CLI

def feed(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it))


def test_cli_adds_and_lists_an_onion_contact(store, ident, monkeypatch, capsys):
    pub, fp = card()
    feed(monkeypatch, "Bob", ADDR, pub, fp, "yes")
    app.cmd_add_contact(store, ident)
    assert store.get_contact(fp + "-onion")[2] == ADDR and store.get_contact(fp) is None
    app.cmd_list_contacts(store)
    out = capsys.readouterr().out
    assert "(On) Bob" in out and app.format_fingerprint(fp) in out


def test_cli_remove_asks_which_twin_when_both_exist(store, monkeypatch, capsys):
    pub, fp = card()
    store.add_contact(fp, "Bob", "10.0.0.1", 1, pub); store.add_contact(fp + "-onion", "Bob", ADDR, 1, pub)
    feed(monkeypatch, fp, "onion", pub, "yes")
    app.cmd_remove_contact(store)
    assert store.get_contact(fp + "-onion") is None and store.get_contact(fp) is not None


def test_cli_remove_with_an_unclear_choice_removes_nothing(store, monkeypatch):
    pub, fp = card()
    store.add_contact(fp, "Bob", "10.0.0.1", 1, pub); store.add_contact(fp + "-onion", "Bob", ADDR, 1, pub)
    feed(monkeypatch, fp, "both")
    app.cmd_remove_contact(store)
    assert store.get_contact(fp) and store.get_contact(fp + "-onion")


def test_show_card_prints_the_onion_address_only_when_there_is_one(ident, capsys):
    app.cmd_show_card(ident)
    assert "Onion" not in capsys.readouterr().out
    app.cmd_show_card(ident, ADDR)
    assert ADDR in capsys.readouterr().out


## ---------------------------------------------------------------- OnionService

class FakeNet:
    def __init__(self):
        self.calls = []

    def start_onion_listener(self):
        self.calls.append("listen"); return 4242

    def enable_onion_dialing(self, socks):
        self.calls.append(("dial", socks))

    def stop_onion(self):
        self.calls.append("stop")


class FakeTorManager:
    instances = []
    mismatch = False
    ready = True
    start_error = None

    def __init__(self, binary=None, tor_dir=None):
        self.binary, self.state, self.socks, self.published = binary, "stopped", ("127.0.0.1", 9999), False
        self.bootstrap_percent, self.error, self.added, self.stopped = 0, None, None, False
        FakeTorManager.instances.append(self)

    def start(self):
        if FakeTorManager.start_error:
            raise FakeTorManager.start_error
        self.state = "bootstrapping"

    def add_onion(self, seed, vport, host, port):
        self.added = (vport, host, port)
        sid = onion.address_from_seed(seed)[:-6]
        return "a" * 56 if FakeTorManager.mismatch else sid

    def wait_ready(self, cancel=None):
        if FakeTorManager.ready:
            self.state = "ready"
        else:
            self.error = "no network"
        return FakeTorManager.ready

    def stop(self):
        self.stopped = True


@pytest.fixture
def svc(store, monkeypatch, tmp_path):
    FakeTorManager.instances.clear(); FakeTorManager.mismatch = False; FakeTorManager.ready = True; FakeTorManager.start_error = None
    exe = tmp_path / "tor"; exe.write_text("x"); exe.chmod(0o755)
    monkeypatch.setattr(osvc.tor_manager, "find_tor_binary", lambda d=None: str(exe))
    net = FakeNet()
    return osvc.OnionService(store, net, tor_dir=str(tmp_path), tor_factory=FakeTorManager), net


def test_enable_runs_the_whole_sequence_and_publishes_the_stored_address(svc, store):
    s, net = svc
    assert s.address is None and s.state == osvc.OFF
    assert s.enable() is True
    assert s.state == osvc.READY and s.address == s.message and s.address.endswith(".onion")
    assert net.calls == ["listen", ("dial", ("127.0.0.1", 9999))]
    assert FakeTorManager.instances[0].added == (network.DEFAULT_PORT, "127.0.0.1", 4242)
    assert osvc.stored_address(store) == s.address
    assert s.enable() is True and len(FakeTorManager.instances) == 1                 # already on: nothing restarts


def test_the_address_is_stable_across_restarts_of_the_switch(svc):
    s, _ = svc
    s.enable(); first = s.address; s.disable(); s.enable()
    assert s.address == first


def test_missing_tor_stops_at_need_install_without_creating_a_key_or_a_listener(store, monkeypatch, tmp_path):
    FakeTorManager.instances.clear()
    monkeypatch.setattr(osvc.tor_manager, "find_tor_binary", lambda d=None: None)
    net = FakeNet()
    s = osvc.OnionService(store, net, tor_dir=str(tmp_path), tor_factory=FakeTorManager)
    assert s.enable() is False and s.state == osvc.NEED_INSTALL
    assert net.calls == [] and store.get_secret(osvc.SECRET_NAME) is None and FakeTorManager.instances == []


def test_a_corrupt_stored_key_is_an_error_and_is_never_silently_replaced(svc, store):
    s, net = svc
    store.set_secret(osvc.SECRET_NAME, b"short")
    assert s.enable() is False and s.state == osvc.ERROR and "invalid" in s.message
    assert store.get_secret(osvc.SECRET_NAME) == b"short" and net.calls == []
    assert s.address is None
    s.regenerate_key()                                                               # the explicit way out
    assert s.enable() is True


def test_address_mismatch_from_tor_aborts_and_tears_everything_down(svc):
    s, net = svc
    FakeTorManager.mismatch = True
    assert s.enable() is False and s.state == osvc.ERROR and "different onion address" in s.message
    assert net.calls[-1] == "stop" and FakeTorManager.instances[0].stopped and s.tor is None


def test_bootstrap_failure_is_reported_and_cleaned_up(svc):
    s, net = svc
    FakeTorManager.ready = False
    assert s.enable() is False and s.state == osvc.ERROR and "no network" in s.message
    assert ("dial", ("127.0.0.1", 9999)) not in net.calls and net.calls[-1] == "stop"


def test_tor_start_errors_are_reported(svc):
    s, _ = svc
    FakeTorManager.start_error = tm.TorError("boom")
    assert s.enable() is False and s.state == osvc.ERROR and s.message == "boom"
    FakeTorManager.start_error = tm.TorNotInstalled("gone")
    assert s.enable() is False and s.state == osvc.NEED_INSTALL


def test_disable_undoes_everything_and_regenerate_is_blocked_while_on(svc):
    s, net = svc
    s.enable()
    with pytest.raises(RuntimeError):
        s.regenerate_key()
    s.disable()
    assert s.state == osvc.OFF and net.calls[-1] == "stop" and FakeTorManager.instances[0].stopped
    old = s.address
    assert s.regenerate_key() != old


def test_status_text_follows_the_state(svc):
    s, _ = svc
    assert s.status_text == "Off"
    s.enable()
    assert "publishing" in s.status_text
    s.tor.published = True
    assert s.published and "published" in s.status_text
    s.state, s.message = osvc.ERROR, "x"
    assert s.status_text == "Error: x"
