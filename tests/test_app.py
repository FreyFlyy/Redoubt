"""CLI helpers and the entry point of app.py (the Textual UI itself is replaced by a stub)."""
import socket
import sys
import time

import pytest

from redoubt import app, crypto, identity as idmod, network, protocol as proto, storage as st, ui

from test_network_integration import Peer, free_port, wait_for, _silent_server, _add_silent_contact


## ---------------------------------------------------------------- fixtures / helpers

@pytest.fixture
def ident(vault_key):
    i = idmod.Identity(crypto.generate_x25519_keypair(), vault_key)
    yield i
    i.wipe()


@pytest.fixture
def store(tmp_path, vault_key):
    s = st.Storage(vault_key, str(tmp_path / "cli.db"))
    yield s
    s.conn.close()


def port_is_free(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # same option the listener uses (TIME_WAIT must not count)
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def feed(monkeypatch, *answers):
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it))


def other_card():
    key = crypto.generate_x25519_keypair()
    raw = crypto.public_key_to_raw(key.public_key())
    return proto.b64(raw), crypto.fingerprint_of(raw)


## ---------------------------------------------------------------- pure helpers

def test_format_fingerprint_groups_of_four():
    fp = "0123456789abcdef" * 4
    out = app.format_fingerprint(fp)
    assert out.split(" ") == [fp[i:i + 4] for i in range(0, 64, 4)]
    assert len(out.split(" ")) == 16


def test_normalize_fingerprint_strips_all_whitespace_and_lowercases():
    fp = "0123456789abcdef" * 4
    assert app.normalize_fingerprint(app.format_fingerprint(fp).upper()) == fp
    assert app.normalize_fingerprint(" \t" + fp[:10] + "\n" + fp[10:] + "  ") == fp


def test_show_card_prints_fingerprint_and_public_key(ident, capsys):
    app.cmd_show_card(ident)
    out = capsys.readouterr().out
    assert app.format_fingerprint(ident.fingerprint) in out
    assert proto.b64(ident.public_key_raw) in out


## ---------------------------------------------------------------- contacts: add

def test_add_contact_success(ident, store, monkeypatch, capsys):
    pub, fp = other_card()
    feed(monkeypatch, " Bob ", "10.0.0.7", pub, app.format_fingerprint(fp).upper(), "yes")
    app.cmd_add_contact(store, ident)
    assert store.get_contact(fp) == (fp, "Bob", "10.0.0.7", network.DEFAULT_PORT, pub)
    assert "'Bob' added" in capsys.readouterr().out


def test_add_contact_user_declines(ident, store, monkeypatch, capsys):
    pub, fp = other_card()
    feed(monkeypatch, "Bob", "10.0.0.7", pub, fp, "no")
    app.cmd_add_contact(store, ident)
    assert store.get_contact(fp) is None and "ABORTING" in capsys.readouterr().out


@pytest.mark.parametrize("case", ["empty_name", "bad_ip", "unspecified_ip", "multicast_ip", "not_base64", "wrong_length",
                                  "fingerprint_mismatch", "own_identity", "duplicate"])
def test_add_contact_rejections(case, ident, store, monkeypatch, capsys):
    pub, fp = other_card()
    name, ip, pk, fpr = "Bob", "10.0.0.7", pub, fp
    if case == "empty_name": name = "   "
    if case == "bad_ip": ip = "not-an-ip"
    if case == "unspecified_ip": ip = "0.0.0.0"
    if case == "multicast_ip": ip = "224.0.0.1"
    if case == "not_base64": pk = "***"
    if case == "wrong_length": pk = proto.b64(b"\x01" * 31)
    if case == "fingerprint_mismatch": fpr = "0" * 64
    if case == "own_identity":
        pk, fpr = proto.b64(ident.public_key_raw), ident.fingerprint
    if case == "duplicate":
        store.add_contact(fp, "Existing", "10.9.9.9", 1, pub)
    feed(monkeypatch, name, ip, pk, fpr, "yes")
    app.cmd_add_contact(store, ident)
    out = capsys.readouterr().out
    assert "[ERROR]" in out
    if case == "duplicate":
        assert store.get_contact(fp)[1] == "Existing"                  # untouched
    elif case != "own_identity":
        assert store.list_contacts() == []
    else:
        assert store.get_contact(ident.fingerprint) is None


## ---------------------------------------------------------------- contacts: list / remove

def test_list_contacts_empty_and_populated(store, capsys):
    app.cmd_list_contacts(store)
    assert "No saved contact." in capsys.readouterr().out
    pub, fp = other_card()
    store.add_contact(fp, "Bob", "10.0.0.7", 60717, pub)
    app.cmd_list_contacts(store)
    out = capsys.readouterr().out
    assert "Bob (10.0.0.7:60717)" in out and pub in out and app.format_fingerprint(fp) in out


def test_remove_contact_success_cascades(store, monkeypatch, capsys):
    pub, fp = other_card()
    store.add_contact(fp, "Bob", "10.0.0.7", 60717, pub)
    store.store_message("m1", fp, "in", 1, "hello")
    store.enqueue_outbox("o1", fp, "pending")
    feed(monkeypatch, app.format_fingerprint(fp), pub, "yes")
    app.cmd_remove_contact(store)
    assert store.get_contact(fp) is None and store.get_history(fp) == [] and not store.has_pending(fp)
    assert "removed" in capsys.readouterr().out


@pytest.mark.parametrize("case", ["unknown_fp", "invalid_b64", "other_key", "declined"])
def test_remove_contact_refusals_keep_the_contact(case, store, monkeypatch, capsys):
    pub, fp = other_card()
    store.add_contact(fp, "Bob", "10.0.0.7", 60717, pub)
    if case == "unknown_fp":
        feed(monkeypatch, "f" * 64)
    elif case == "invalid_b64":
        feed(monkeypatch, fp, "%%%")
    elif case == "other_key":
        feed(monkeypatch, fp, other_card()[0])
    else:
        feed(monkeypatch, fp, pub, "no")
    app.cmd_remove_contact(store)
    assert store.get_contact(fp) is not None


## ---------------------------------------------------------------- Textual UI wiring: settings menu + theme

class _FakeNetwork:
    """Stand-in NetworkManager: RedoubtApp only assigns its callbacks on the network object"""
    on_message = None
    on_status = None
    on_ack = None
    on_statusbar_message = None


def _make_app(ident, store):
    return ui.RedoubtApp(ident, store, _FakeNetwork())


def _patch_push_screen(monkeypatch, pushed):
    """Record push_screen calls instead of touching the real Textual screen stack"""

    def fake_push(self, screen, callback=None, **kwargs):
        pushed.append((screen, callback))
        return None

    monkeypatch.setattr(ui.RedoubtApp, "push_screen", fake_push)


def test_open_settings_pushes_the_dropdown_when_no_popup_is_open(ident, store, monkeypatch):
    app = _make_app(ident, store)
    monkeypatch.setattr(ui.RedoubtApp, "screen_stack", property(lambda self: []))    # no popup open
    pushed = []
    _patch_push_screen(monkeypatch, pushed)
    app.action_open_settings()
    assert len(pushed) == 1
    screen, callback = pushed[0]
    assert isinstance(screen, ui.SettingsMenuScreen)
    assert callback == app.settings_menu_chosen


def test_open_settings_is_a_no_op_when_a_popup_is_open(ident, store, monkeypatch):
    app = _make_app(ident, store)
    monkeypatch.setattr(ui.RedoubtApp, "screen_stack", property(lambda self: [object(), object()]))    # popup already open
    pushed = []
    _patch_push_screen(monkeypatch, pushed)
    app.action_open_settings()
    assert pushed == []


@pytest.mark.parametrize("choice, expected_screen, expect_callback", [
    ("about", ui.AboutScreen, False),
    ("show_card", ui.ShowCardScreen, False),
    ("contacts", ui.ContactListScreen, False),
    ("add", ui.AddContactScreen, True),
])
def test_settings_menu_chosen_opens_the_expected_screen(ident, store, monkeypatch, choice, expected_screen, expect_callback):
    app = _make_app(ident, store)
    pushed = []
    _patch_push_screen(monkeypatch, pushed)
    app.settings_menu_chosen(choice)
    assert len(pushed) == 1
    screen, callback = pushed[0]
    assert isinstance(screen, expected_screen)
    assert (callback == app.contact_added) is expect_callback


def test_settings_menu_chosen_ignores_unknown_choices(ident, store, monkeypatch):
    app = _make_app(ident, store)
    pushed = []
    _patch_push_screen(monkeypatch, pushed)
    app.settings_menu_chosen("not-a-real-option")
    assert pushed == []


def test_redoubt_app_cycles_through_the_registered_themes(ident, store):
    app = _make_app(ident, store)
    for theme in ui.RedoubtApp.THEMES:
        app.register_theme(theme)
    app.theme = "python"
    app.update_theme_indicator()
    assert app.theme == "python" and app.sub_title == "Python"
    for expected in ui.RedoubtApp.THEME_ORDER[1:]:
        app.action_toggle_theme()
        assert app.theme == expected and app.sub_title == expected.capitalize()
    app.action_toggle_theme()    # back to the first theme
    assert app.theme == "python" and app.sub_title == "Python"


def test_load_and_save_settings_roundtrip():
    ui.save_settings({"theme": "nord"})
    assert ui.load_settings() == {"theme": "nord"}
    ui.save_settings({})
    assert ui.load_settings() == {}


## ---------------------------------------------------------------- entry point

class StubApp:
    """Replaces the Textual UI. `hook(app)` runs inside run() like the user session would"""
    hook = None

    def __init__(self, ident, storage, network):
        self.ident, self.storage, self.network = ident, storage, network

    def run(self):
        if StubApp.hook:
            StubApp.hook(self)


@pytest.fixture
def run_env(tmp_path, ident, monkeypatch, vault_key):
    calls = {"loader": 0, "core": 0}
    real_storage = st.Storage
    priv = ident.private_key

    def loader():
        """Like the real one: every call re-reads the identity (first call hands out the fixture's object)"""
        calls["loader"] += 1
        return ident if calls["loader"] == 1 else idmod.Identity(priv, vault_key)

    monkeypatch.setattr(app.identity_mod, "load_or_create_identity_interactive", loader)
    monkeypatch.setattr(app.storage_mod, "Storage",       # same module object other tests use: keep db_path overridable
                        lambda key, db_path=None: real_storage(key, db_path or str(tmp_path / "app.db")))
    monkeypatch.setattr(app.secure_memory, "disable_core_dumps", lambda: calls.__setitem__("core", calls["core"] + 1))
    monkeypatch.setattr(app, "RedoubtApp", StubApp)
    StubApp.hook = None
    port = free_port()
    monkeypatch.setattr(app.network_mod, "DEFAULT_PORT", port)

    def argv(*a):
        monkeypatch.setattr(sys, "argv", ["redoubt", *a])

    yield calls, argv, port, tmp_path
    StubApp.hook = None


def test_version_flag_exits_before_asking_for_the_vault_passphrase(run_env, capsys):
    calls, argv, *_ = run_env
    argv("--version")
    with pytest.raises(SystemExit) as e:
        app._run()
    assert e.value.code == 0 and "redoubt 2.1.0" in capsys.readouterr().out
    assert calls["loader"] == 0 and calls["core"] == 1               # core dumps disabled first, no passphrase prompt


def test_cli_commands_are_mutually_exclusive(run_env):
    calls, argv, *_ = run_env
    argv("--show-card", "--list-contacts")
    with pytest.raises(SystemExit) as e:
        app._run()
    assert e.value.code == 2 and calls["loader"] == 0


@pytest.mark.parametrize("flag", ["--show-card", "--list-contacts"])
def test_cli_commands_run_without_starting_the_network_and_wipe_the_identity(run_env, ident, capsys, flag):
    calls, argv, port, _ = run_env
    argv(flag)
    assert app._run() == 0
    out = capsys.readouterr().out
    assert ("Identity card" in out) or ("No saved contact." in out)
    assert "Closing..." in out
    with pytest.raises(ValueError):
        _ = ident.vault_key                                            # wiped in `finally`
    assert port_is_free(port)                                        # nothing was listening


def test_add_and_remove_contact_commands_dispatch(run_env, monkeypatch, capsys):
    calls, argv, *_ = run_env
    pub, fp = other_card()
    feed(monkeypatch, "Bob", "10.0.0.7", pub, fp, "yes")
    argv("--add-contact")
    assert app._run() == 0
    feed(monkeypatch, fp, pub, "yes")
    argv("--remove-contact")
    assert app._run() == 0
    out = capsys.readouterr().out
    assert "'Bob' added" in out and "removed" in out


def test_normal_run_starts_and_stops_the_network(run_env, capsys):
    calls, argv, port, _ = run_env
    argv()
    seen = {}

    def hook(a):
        seen["listening"] = (a.network.listen_port == port)
        s = socket.create_connection(("127.0.0.1", port), timeout=2)   # the listener is really up
        s.close()

    StubApp.hook = hook
    assert app._run() == 0
    assert seen["listening"]
    out = capsys.readouterr().out
    assert "Starting..." in out and "Closing..." in out
    assert wait_for(lambda: port_is_free(port), 3)                     # port released


def test_port_already_in_use_is_reported_and_exit_code_is_1(run_env, capsys):
    calls, argv, port, _ = run_env
    blocker = socket.socket(); blocker.bind(("0.0.0.0", port)); blocker.listen(1)
    try:
        argv()
        assert app._run() == 1
        out = capsys.readouterr().out
        assert "Cannot listen on port" in out and "Closing..." in out
    finally:
        blocker.close()


def test_shutdown_is_fast_with_unreachable_contacts_and_tells_live_peers_we_are_offline(run_env, tmp_path, ident, capsys):
    """Regression for the 5-6 s hang on exit: offline presence used to dial every contact sequentially"""
    calls, argv, port, _ = run_env
    bob = Peer(tmp_path, "bob")
    srv, sport, accepted = _silent_server()

    def hook(a):
        a.storage.add_contact(bob.fp, "bob", "127.0.0.1", bob.port, proto.b64(bob.ident.public_key_raw))
        _add_silent_contact(a, sport)                                   # contact that never answers a handshake
        bob.storage.add_contact(ident.fingerprint, "app", "127.0.0.1", port, proto.b64(ident.public_key_raw))
        a.network._get_or_connect(a.storage.get_contact(bob.fp))        # one live session
        assert wait_for(lambda: bob.net.sessions.get(ident.fingerprint) is not None)
        a.network.broadcast_presence("online")                          # in-flight attempt to the silent contact

    StubApp.hook = hook
    argv()
    app_fp = ident.fingerprint                                          # (wipe() clears only the vault key)
    try:
        t0 = time.monotonic()
        assert app._run() == 0
        elapsed = time.monotonic() - t0
        assert elapsed < 3.0, f"shutdown took {elapsed:.1f}s"
        assert wait_for(lambda: (app_fp, "offline") in bob.status, 5)   # live peer was told
        assert len(accepted) <= 1                                       # at most the single "online" attempt; offline never dials
    finally:
        srv.close(); bob.close()


@pytest.mark.parametrize("exc", [KeyboardInterrupt, EOFError])
def test_main_maps_interrupts_to_exit_code_130(monkeypatch, capsys, exc):
    def boom():
        raise exc()
    monkeypatch.setattr(app, "_run", boom)
    assert app.main() == 130
    assert "Aborted." in capsys.readouterr().out


def test_main_returns_the_exit_code_of_run(monkeypatch):
    monkeypatch.setattr(app, "_run", lambda: 7)
    assert app.main() == 7
