"""Tor manager: discovery, install plans, control protocol, SAFECOOKIE, and a real tor when one is installed."""
import hashlib
import hmac
import os
import socket
import threading
import time

import pytest

from redoubt import onion, tor_manager as tm


## ---------------------------------------------------------------- parsers

def test_parse_tor_version():
    assert tm.parse_tor_version("Tor version 0.4.8.12.\n") == (0, 4, 8, 12)
    assert tm.parse_tor_version("Tor version 0.3.5.1-alpha (git-x)") == (0, 3, 5, 1)
    with pytest.raises(ValueError):
        tm.parse_tor_version("nginx 1.2")


def test_parse_bootstrap_and_socks_and_hs_desc():
    assert tm.parse_bootstrap('STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY="x"') == (45, "loading_descriptors")
    assert tm.parse_bootstrap("nothing") is None
    assert tm.parse_socks_listener('net/listeners/socks="[::1]:9" "127.0.0.1:41231"') == ("127.0.0.1", 41231)
    assert tm.parse_socks_listener('net/listeners/socks=""') is None
    assert tm.parse_hs_desc_uploaded("HS_DESC UPLOADED abc UNKNOWN $HSDIR desc", "abc")
    assert not tm.parse_hs_desc_uploaded("HS_DESC UPLOADED other UNKNOWN $HSDIR", "abc")
    assert not tm.parse_hs_desc_uploaded("HS_DESC FAILED abc UNKNOWN $HSDIR", "abc")


def test_torrc_quote_handles_windows_paths_and_quotes():
    assert tm._torrc_quote('C:\\Users\\a b\\x"y') == '"C:/Users/a b/x\\"y"'


## ---------------------------------------------------------------- discovery

def test_find_tor_binary_prefers_the_private_folder(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"; bindir.mkdir()
    exe = bindir / tm._TOR_EXE
    exe.write_text("#!/bin/sh\n"); exe.chmod(0o755)
    assert tm.find_tor_binary(str(tmp_path)) == str(exe)


def test_find_tor_binary_ignores_non_executables(tmp_path, monkeypatch):
    monkeypatch.setattr(tm.shutil, "which", lambda n: None)
    monkeypatch.setattr(tm, "_candidate_paths", lambda d: iter([str(tmp_path / "missing")]))
    (tmp_path / "plain").write_text("x")
    assert tm.find_tor_binary(str(tmp_path)) is None


## ---------------------------------------------------------------- install plans

DEBIAN = 'ID=ubuntu\nID_LIKE="debian"\n'


def plan(os_release=DEBIAN, euid=1000, which=lambda n: "/usr/bin/" + n, platform_name="linux"):
    return tm.get_install_plan("/t", os_release=os_release, platform_name=platform_name, which=which, geteuid=lambda: euid)


def test_debian_family_updates_then_installs_with_sudo():
    p = plan()
    assert p.commands == [["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y", "tor"]] and p.can_run


def test_root_needs_no_sudo_and_derivatives_resolve_through_id_like():
    p = plan(os_release='ID=mydistro\nID_LIKE="arch"\n', euid=0)
    assert p.commands == [["pacman", "-S", "--needed", "--noconfirm", "tor"]]


@pytest.mark.parametrize("osr, first", [("ID=fedora", "dnf"), ("ID=opensuse-tumbleweed", "zypper"), ("ID=alpine", "apk"), ("ID=void", "xbps-install")])
def test_other_package_managers(osr, first):
    assert plan(os_release=osr, euid=0).commands[0][0] == first


def test_unknown_distro_falls_back_to_the_package_manager_present():
    p = plan(os_release="ID=weird", euid=0, which=lambda n: "/x" if n == "dnf" else None)
    assert p.commands == [["dnf", "install", "-y", "tor"]]


def test_unknown_everything_is_manual_only():
    p = plan(os_release="", which=lambda n: None)
    assert not p.can_run and "tor" in p.manual


def test_no_privilege_tool_means_manual_instructions():
    p = plan(which=lambda n: "/x" if n == "apt-get" else None)
    assert not p.can_run and "root" in p.manual


def test_windows_is_manual_and_points_at_the_private_folder():
    p = plan(platform_name="win32")
    assert not p.can_run and os.path.join("/t", "bin") in p.manual


def test_os_release_parsing():
    assert tm.parse_os_release('ID=ubuntu\nID_LIKE="debian foo"\n# c\n') == ["ubuntu", "debian", "foo"]


def test_run_install_plan_stops_at_the_first_failure(monkeypatch):
    calls = []

    class R:
        def __init__(self, rc): self.returncode = rc

    def fake_run(cmd, **kw):
        calls.append(cmd[0]); return R(1 if cmd[0] == "b" else 0)

    monkeypatch.setattr(tm.subprocess, "run", fake_run)
    assert tm.run_install_plan(tm.InstallPlan("d", commands=[["a"], ["b"], ["c"]])) is False and calls == ["a", "b"]
    assert tm.run_install_plan(tm.InstallPlan("d", commands=[["a"], ["c"]])) is True


def test_child_env_drops_pyinstaller_library_path(monkeypatch):
    monkeypatch.setattr(tm.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/bundle")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/orig")
    assert tm._subprocess_env()["LD_LIBRARY_PATH"] == "/orig"
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG")
    assert "LD_LIBRARY_PATH" not in tm._subprocess_env()


## ---------------------------------------------------------------- control protocol against a fake tor

COOKIE = os.urandom(32)


class FakeControl:
    """Speaks just enough of the control protocol: SAFECOOKIE auth, GETINFO, a data block, events"""
    def __init__(self, cookie=COOKIE, honest=True):
        self.cookie, self.honest = cookie, honest
        self.srv = socket.socket(); self.srv.bind(("127.0.0.1", 0)); self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.commands = []
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        c, _ = self.srv.accept()
        f = c.makefile("rwb", buffering=0)
        cn = sn = None
        while True:
            line = f.readline().decode().strip()
            if not line:
                return
            self.commands.append(line)
            if line.startswith("AUTHCHALLENGE"):
                cn = bytes.fromhex(line.split()[2]); sn = os.urandom(32)
                key = self.cookie if self.honest else os.urandom(32)
                sh = hmac.new(tm._SAFECOOKIE_SERVER, key + cn + sn, hashlib.sha256).hexdigest()
                f.write(f"250 AUTHCHALLENGE SERVERHASH={sh} SERVERNONCE={sn.hex()}\r\n".encode())
            elif line.startswith("AUTHENTICATE"):
                good = hmac.new(tm._SAFECOOKIE_CLIENT, self.cookie + cn + sn, hashlib.sha256).hexdigest()
                f.write(b"250 OK\r\n" if line.split()[1] == good else b"515 Authentication failed\r\n")
            elif line == "GETINFO multi":
                f.write(b"650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=10 TAG=x\r\n250+multi=\r\nline1\r\n..dot\r\n.\r\n250 OK\r\n")
            else:
                f.write(b"510 Unrecognized command\r\n")


def test_safecookie_authentication_succeeds_and_data_blocks_and_events_parse():
    fc, events = FakeControl(), []
    conn = tm.ControlConnection("127.0.0.1", fc.port, on_event=events.append)
    conn.authenticate_safecookie(COOKIE)
    r = conn.request("GETINFO multi")
    assert r.ok and r.lines == ["multi=\nline1\n.dot", "OK"]
    time.sleep(0.2)
    assert events == ["STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=10 TAG=x"]
    assert conn.request("BOGUS").code == 510
    with pytest.raises(ValueError):
        conn.request("A\r\nB")
    conn.close()


def test_a_listener_that_does_not_know_the_cookie_is_rejected():
    fc = FakeControl(honest=False)
    conn = tm.ControlConnection("127.0.0.1", fc.port)
    with pytest.raises(tm.TorError, match="not our Tor"):
        conn.authenticate_safecookie(COOKIE)
    conn.close()


def test_wrong_cookie_is_refused_by_tor():
    fc = FakeControl()
    conn = tm.ControlConnection("127.0.0.1", fc.port)
    with pytest.raises(tm.TorError):
        conn.authenticate_safecookie(os.urandom(32))
    conn.close()


def test_request_after_the_connection_dropped_fails_cleanly():
    fc = FakeControl()
    conn = tm.ControlConnection("127.0.0.1", fc.port)
    conn.close()
    assert conn.closed.wait(2)
    with pytest.raises(tm.TorError):
        conn.request("GETINFO version")


## ---------------------------------------------------------------- manager without tor

def test_start_without_tor_raises_not_installed_and_leaves_state_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(tm, "find_tor_binary", lambda d=None: None)
    m = tm.TorManager(tor_dir=str(tmp_path))
    with pytest.raises(tm.TorNotInstalled):
        m.start()
    assert m.state == "failed" and "not installed" in m.error
    m.stop()


def test_too_old_tor_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(tm, "tor_version", lambda b: (0, 2, 9, 1))
    m = tm.TorManager(binary="/bin/true", tor_dir=str(tmp_path))
    with pytest.raises(tm.TorError, match="too old"):
        m.start()


def test_stop_is_idempotent(tmp_path):
    m = tm.TorManager(tor_dir=str(tmp_path))
    m.stop(); m.stop()
    assert m.state == "stopped"


## ---------------------------------------------------------------- real tor (skipped where it is not installed)

real_tor = pytest.mark.skipif(tm.find_tor_binary() is None, reason="tor is not installed")


@real_tor
def test_real_tor_creates_exactly_the_address_derived_from_our_key(tmp_path):
    m = tm.TorManager(tor_dir=str(tmp_path / "tor dir"))
    try:
        m.start()
        assert m.state in ("bootstrapping", "ready") and m.socks and m.socks[0] == "127.0.0.1"
        seed = onion.generate_seed()
        sid = m.add_onion(seed, 60717, "127.0.0.1", 45454)
        assert sid + ".onion" == onion.address_from_seed(seed)      # proves the key format is what Tor expects
        if os.name == "posix":
            assert oct(os.stat(m.tor_dir).st_mode & 0o777) == "0o700"
            assert oct(os.stat(m._torrc).st_mode & 0o777) == "0o600"
        m.remove_onion()
    finally:
        m.stop()
    assert m.state == "stopped" and m.socks is None


@real_tor
def test_real_tor_dies_with_its_owner_and_stop_kills_the_process(tmp_path):
    m = tm.TorManager(tor_dir=str(tmp_path / "t"))
    m.start()
    proc = m._proc
    m.stop()
    assert proc.poll() is not None
