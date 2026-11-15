"""Textual UI for the onion feature, driven headless with the real widgets."""
import asyncio

import pytest
from textual.widgets import Button, Input, Static, Switch

from redoubt import contact_validation as cv, crypto, identity as idmod, onion, onion_service as osvc, protocol as proto, storage as st, ui

ADDR = onion.address_from_seed(bytes(range(32)))


class FakeNet:
    on_message = on_status = on_ack = on_statusbar_message = None

    def drop_contact(self, cid):
        pass


class FakeOnion:
    """OnionService stand-in with a scripted outcome for enable()"""
    def __init__(self, outcome=osvc.READY, address=None):
        self.state, self.message, self.address, self.outcome = osvc.OFF, "", address, outcome
        self.enabled = self.disabled = 0
        self.tor = None

    busy = property(lambda s: s.state in osvc.BUSY_STATES)
    status_text = property(lambda s: {"off": "Off", "ready": "Online: onion service published", "need_install": "Tor is not installed"}.get(s.state, s.state))

    def enable(self):
        self.enabled += 1
        self.state = self.outcome
        if self.outcome == osvc.READY:
            self.address = ADDR
        return self.outcome == osvc.READY

    def disable(self):
        self.disabled += 1; self.state = osvc.OFF

    def regenerate_key(self):
        self.address = "regenerated.onion"; return self.address


@pytest.fixture(autouse=True)
def clean_settings():
    ui.save_settings({})
    yield
    ui.save_settings({})


@pytest.fixture
def env(tmp_path, vault_key):
    ident = idmod.Identity(crypto.generate_x25519_keypair(), vault_key)
    store = st.Storage(vault_key, str(tmp_path / "ui.db"))
    yield ident, store
    store.conn.close(); ident.wipe()


def run(coro):
    return asyncio.run(coro)


def card():
    raw = crypto.public_key_to_raw(crypto.generate_x25519_keypair().public_key())
    return proto.b64(raw), crypto.fingerprint_of(raw)


async def settle(pilot, n=6):
    for _ in range(n):
        await pilot.pause(0.05)


def test_settings_has_the_tor_switch_off_by_default_and_shows_status(env):
    ident, store = env

    async def go():
        app = ui.RedoubtApp(ident, store, FakeNet(), FakeOnion())
        async with app.run_test(size=(120, 50)) as pilot:
            app.push_screen(ui.SettingsScreen()); await settle(pilot)
            sw = app.screen.query_one("#use_tor_switch", Switch)
            assert sw.value is False
            assert "Off" in str(app.screen.query_one("#tor_status", Static).render())
            assert app.screen.query_one("#new_onion", Button).disabled
    run(go())


def test_turning_the_switch_on_saves_the_setting_and_starts_onion_in_the_background(env):
    ident, store = env
    fake = FakeOnion()

    async def go():
        app = ui.RedoubtApp(ident, store, FakeNet(), fake)
        async with app.run_test(size=(120, 50)) as pilot:
            app.push_screen(ui.SettingsScreen()); await settle(pilot)
            app.screen.query_one("#use_tor_switch", Switch).value = True
            await settle(pilot, 20)
            assert ui.load_settings()[ui.SETTING_USE_TOR] is True and fake.enabled == 1
            assert "published" in str(app.screen.query_one("#tor_status", Static).render())
            assert ADDR in str(app.screen.query_one("#onion_address", Static).render())
            app.screen.query_one("#use_tor_switch", Switch).value = False
            await settle(pilot, 20)
            assert ui.load_settings()[ui.SETTING_USE_TOR] is False and fake.disabled == 1
    run(go())


def test_missing_tor_opens_the_install_helper_and_cancelling_turns_the_switch_back_off(env, monkeypatch):
    monkeypatch.setattr(ui.tor_manager, "find_tor_binary", lambda d=None: None)
    ident, store = env
    fake = FakeOnion(outcome=osvc.NEED_INSTALL)

    async def go():
        app = ui.RedoubtApp(ident, store, FakeNet(), fake)
        async with app.run_test(size=(120, 50)) as pilot:
            app.push_screen(ui.SettingsScreen()); await settle(pilot)
            app.screen.query_one("#use_tor_switch", Switch).value = True
            await settle(pilot, 20)
            assert isinstance(app.screen, ui.TorSetupScreen)
            assert app.screen.query_one("#tor_command", Static)                    # shows the exact command / manual steps
            app.screen.query_one("#cancel", Button).press()
            await settle(pilot, 30)
            assert isinstance(app.screen, ui.SettingsScreen)
            assert ui.load_settings()[ui.SETTING_USE_TOR] is False
            assert app.screen.query_one("#use_tor_switch", Switch).value is False
    run(go())


def test_install_helper_check_again_succeeds_when_tor_appears(env, monkeypatch):
    ident, store = env
    fake = FakeOnion(outcome=osvc.NEED_INSTALL)
    monkeypatch.setattr(ui.tor_manager, "find_tor_binary", lambda d=None: None)     # whatever this machine has

    async def go():
        app = ui.RedoubtApp(ident, store, FakeNet(), fake)
        async with app.run_test(size=(120, 50)) as pilot:
            app.push_screen(ui.TorSetupScreen(), app.tor_setup_done); await settle(pilot)
            app.screen.query_one("#check", Button).press(); await settle(pilot)
            assert isinstance(app.screen, ui.TorSetupScreen)                       # still missing
            fake.outcome = osvc.READY
            monkeypatch.setattr(ui.tor_manager, "find_tor_binary", lambda d=None: "/usr/bin/tor")
            app.screen.query_one("#check", Button).press(); await settle(pilot, 20)
            assert fake.enabled == 1                                               # installed -> onion started again
    run(go())


def test_startup_does_not_touch_onion_when_the_setting_is_off_and_does_when_on(env):
    ident, store = env

    async def go(setting):
        ui.save_settings({ui.SETTING_USE_TOR: setting} if setting else {})
        fake = FakeOnion()
        app = ui.RedoubtApp(ident, store, FakeNet(), fake)
        async with app.run_test(size=(120, 50)) as pilot:
            await settle(pilot, 20)
        return fake
    assert run(go(False)).enabled == 0
    assert run(go(True)).enabled == 1


def test_adding_an_onion_contact_shows_the_prefix_and_keeps_the_ip_twin_separate(env):
    ident, store = env
    pub, fp = card()
    store.add_contact(fp, "Bob", "10.0.0.1", 60717, pub)

    async def go():
        app = ui.RedoubtApp(ident, store, FakeNet(), FakeOnion())
        async with app.run_test(size=(120, 50)) as pilot:
            app.push_screen(ui.AddContactScreen(store, ident), app.contact_added); await settle(pilot)
            for fid, val in zip(ui.AddContactScreen.FIELD_ORDER, ("Bob", ADDR, pub, fp)):
                app.screen.query_one(f"#{fid}", Input).value = val
            app.screen.submit(); await settle(pilot, 10)
            shown = [i.contact_name for i in app._items.values()]
            assert shown == ["Bob", "(On) Bob"]
            assert set(app._items) == {fp, fp + "-onion"}
            assert "Tor is off" in str(app.query_one("#statusbar", Static).render())
    run(go())


def test_add_form_reports_onion_validation_errors(env):
    ident, store = env
    pub, fp = card()

    async def go():
        app = ui.RedoubtApp(ident, store, FakeNet(), FakeOnion())
        async with app.run_test(size=(120, 50)) as pilot:
            app.push_screen(ui.AddContactScreen(store, ident)); await settle(pilot)
            for fid, val in zip(ui.AddContactScreen.FIELD_ORDER, ("Bob", ADDR[:-8] + "xxxx.onion", pub, fp)):
                app.screen.query_one(f"#{fid}", Input).value = val
            app.screen.submit(); await settle(pilot)
            assert "onion" in str(app.screen.query_one("#form_error", Static).render()).lower()
            assert store.list_contacts() == []
    run(go())


def test_contact_list_and_card_show_onion_information_and_revoke_only_the_onion_twin(env):
    ident, store = env
    pub, fp = card()
    store.add_contact(fp, "Bob", "10.0.0.1", 60717, pub)
    store.add_contact(fp + "-onion", "Bob", ADDR, 60717, pub)

    async def go():
        app = ui.RedoubtApp(ident, store, FakeNet(), FakeOnion(address=ADDR))
        async with app.run_test(size=(140, 60)) as pilot:
            app.menu_chosen("show_card"); await settle(pilot)
            assert ADDR in str(app.screen.query_one("#card_onion", Label_ := Static).render())
            app.screen.dismiss(); await settle(pilot)
            app.menu_chosen("contacts"); await settle(pilot)
            text = " ".join(str(w.render()) for w in app.screen.query(".contact_info"))
            assert "(On) Bob" in text and f"Onion: {ADDR}" in text and "IP: 10.0.0.1" in text
            assert text.count(cv.format_fingerprint(fp)) == 2                      # the REAL fingerprint for both
            app.revoke_contact(fp + "-onion"); await settle(pilot)
            assert store.get_contact(fp) is not None and store.get_contact(fp + "-onion") is None
    run(go())


def test_new_onion_address_button_needs_confirmation(env):
    ident, store = env
    fake = FakeOnion(address=ADDR)

    async def go():
        app = ui.RedoubtApp(ident, store, FakeNet(), fake)
        async with app.run_test(size=(120, 50)) as pilot:
            app.push_screen(ui.SettingsScreen()); await settle(pilot)
            btn = app.screen.query_one("#new_onion", Button)
            assert not btn.disabled
            btn.press(); await settle(pilot)
            assert isinstance(app.screen, ui.ConfirmScreen)
            app.screen.query_one("#no", Button).press(); await settle(pilot)
            assert fake.address == ADDR
            app.screen.query_one("#new_onion", Button).press(); await settle(pilot)
            app.screen.query_one("#yes", Button).press(); await settle(pilot, 10)
            assert fake.address == "regenerated.onion"
    run(go())
