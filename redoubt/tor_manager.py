### tor_manager.py

"""
Tor manager for Redoubt.

Redoubt never touches the system Tor service: when "Use Tor/Onion network" is on it launches its OWN private Tor
instance (own DataDirectory, random SocksPort/ControlPort, client only) and talks to it through the control port.
The onion service is created at runtime with ADD_ONION from a key kept in the encrypted vault, so the service
private key is never written to disk by Tor. The Tor process is tied to the Redoubt process
(__OwningControllerProcess), so it dies with it even after a crash or a kill -9.

Nothing here runs unless the user turned the switch on (this module is not even imported by the network code path).
"""

import hashlib
import hmac
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

from . import onion as onion_mod
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)


## Variables

TOR_DIR = os.path.join(os.path.expanduser("~"), ".redoubt", "tor")
MIN_TOR_VERSION = (0, 3, 5, 0)     # first stable series with v3 onion services through ADD_ONION ED25519-V3

START_TIMEOUT = 30.0            # tor process up, control port written and authenticated
BOOTSTRAP_TIMEOUT = 180.0       # Tor can take a while on a cold start / slow network
CONTROL_TIMEOUT = 15.0
STOP_TIMEOUT = 5.0

_IS_WINDOWS = sys.platform == "win32"
_TOR_EXE = "tor.exe" if _IS_WINDOWS else "tor"

_SAFECOOKIE_SERVER = b"Tor safe cookie authentication server-to-controller hash"
_SAFECOOKIE_CLIENT = b"Tor safe cookie authentication controller-to-server hash"

TOR_DOWNLOAD_URL = "https://www.torproject.org/download/tor/"


## Exceptions

class TorError(Exception):
    """Tor could not be started, controlled or reached (message is user-presentable)"""


class TorNotInstalled(TorError):
    """No usable tor executable was found"""


## Environment helpers

def _subprocess_env() -> dict:
    """Environment for the child processes (tor, package manager). A PyInstaller/AppImage build points LD_LIBRARY_PATH
    at its own bundled libraries: the system tor (linked against the system OpenSSL/libevent) must not load those"""
    env = dict(os.environ)
    if getattr(sys, "frozen", False):
        orig = env.get("LD_LIBRARY_PATH_ORIG")
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)
    return env


def _popen_flags() -> dict:
    """Keep the child out of the terminal's foreground process group (Ctrl+C must not kill tor behind our back: Redoubt stops it itself)"""
    if _IS_WINDOWS:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW}
    return {"start_new_session": True}


def _make_private_dir(path: str):
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)   # Tor refuses a DataDirectory that other users can read
    except OSError:
        pass


## Binary discovery

def _candidate_paths(tor_dir: str):
    yield os.path.join(tor_dir, "bin", _TOR_EXE)
    yield os.path.join(tor_dir, "bin", "tor", _TOR_EXE)     # Windows Tor Expert Bundle extracted as-is
    found = shutil.which(_TOR_EXE)
    if found:
        yield found
    if not _IS_WINDOWS:     # /usr/sbin is often missing from a normal user's PATH, but Debian/Ubuntu install tor there
        for p in ("/usr/bin/tor", "/usr/sbin/tor", "/usr/local/bin/tor", "/usr/local/sbin/tor",
                  "/opt/homebrew/bin/tor", "/snap/bin/tor"):
            yield p


def find_tor_binary(tor_dir: str = TOR_DIR):
    """Path of the first executable tor found (private folder first, then PATH and well-known locations), or None"""
    for path in _candidate_paths(tor_dir):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def parse_tor_version(text: str):
    """'Tor version 0.4.8.12.' -> (0, 4, 8, 12). Raises ValueError"""
    m = re.search(r"Tor version (\d+)\.(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        raise ValueError("unrecognized tor --version output")
    return tuple(int(x or 0) for x in m.groups())


def tor_version(binary: str, timeout: float = 10.0):
    """Version tuple of a tor executable. Raises TorError if it is not a working tor"""
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=timeout,
                             env=_subprocess_env(), stdin=subprocess.DEVNULL, check=False).stdout
        return parse_tor_version(out)
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        raise TorError(f"'{binary}' does not look like a working Tor executable: {e}") from e


## Install helper

@dataclass
class InstallPlan:
    """How to get Tor on this machine. `commands` (each an argv list, run in order, no shell) is empty when only manual steps exist"""
    description: str
    commands: list = field(default_factory=list)
    manual: str = ""
    note: str = ""

    @property
    def can_run(self) -> bool:
        return bool(self.commands)

    @property
    def display(self) -> str:
        return " && ".join(" ".join(c) for c in self.commands) if self.commands else self.manual


_APT_LIKE = {"debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali", "elementary", "zorin", "mx", "neon", "devuan"}
_DNF_LIKE = {"fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn"}
_PACMAN_LIKE = {"arch", "manjaro", "endeavouros", "garuda", "artix", "cachyos"}
_ZYPPER_LIKE = {"opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse", "sles"}


def parse_os_release(text: str) -> list:
    """Distro identifiers from /etc/os-release content: [ID, *ID_LIKE]"""
    values = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            values[k.strip()] = v.strip().strip('"').strip("'").lower()
    ids = [values["ID"]] if values.get("ID") else []
    ids += values.get("ID_LIKE", "").split()
    return ids


def _read_os_release() -> str:
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except OSError:
            continue
    return ""


def get_install_plan(tor_dir: str = TOR_DIR, *, os_release: str = None, platform_name: str = None,
                     which=shutil.which, geteuid=None) -> InstallPlan:
    """Pick the right way to install Tor on this system (pure: everything environmental can be injected for tests)"""
    platform_name = platform_name or sys.platform

    if platform_name == "win32":
        return InstallPlan(
            "Tor must be installed manually on Windows.",
            manual=(f"1. Download the \"Tor Expert Bundle\" for Windows from {TOR_DOWNLOAD_URL}\n"
                    f"2. Extract it and copy the contents of its \"tor\" folder (tor.exe and the .dll files) into:\n"
                    f"   {os.path.join(tor_dir, 'bin')}\n"
                    f"3. Press \"Check again\"."),
            note="Verify the signature of the download as described on the Tor Project website.",
        )

    ids = parse_os_release(_read_os_release() if os_release is None else os_release)
    if platform_name == "darwin":
        manager = "brew" if which("brew") else None
    else:
        manager = None
        for ident in ids:
            if ident in _APT_LIKE:
                manager = "apt"
            elif ident in _DNF_LIKE:
                manager = "dnf"
            elif ident in _PACMAN_LIKE:
                manager = "pacman"
            elif ident in _ZYPPER_LIKE:
                manager = "zypper"
            elif ident == "alpine":
                manager = "apk"
            elif ident == "void":
                manager = "xbps"
            if manager:
                break
        if manager is None:     # unknown distro: go by whichever package manager exists
            for exe, name in (("apt-get", "apt"), ("dnf", "dnf"), ("pacman", "pacman"), ("zypper", "zypper"),
                              ("apk", "apk"), ("xbps-install", "xbps")):
                if which(exe):
                    manager = name
                    break

    base = {
        "apt": [["apt-get", "update"], ["apt-get", "install", "-y", "tor"]],
        "dnf": [["dnf", "install", "-y", "tor"]],
        "pacman": [["pacman", "-S", "--needed", "--noconfirm", "tor"]],
        "zypper": [["zypper", "--non-interactive", "install", "tor"]],
        "apk": [["apk", "add", "tor"]],
        "xbps": [["xbps-install", "-Sy", "tor"]],
        "brew": [["brew", "install", "tor"]],
    }.get(manager)

    if base is None:
        return InstallPlan(
            "Tor must be installed manually.",
            manual=f"Install the \"tor\" package with your package manager (or see {TOR_DOWNLOAD_URL}), then press \"Check again\".",
        )

    if manager == "brew":
        commands = base     # Homebrew refuses to run as root
    else:
        euid = geteuid() if geteuid is not None else (os.geteuid() if hasattr(os, "geteuid") else 0)
        if euid == 0:
            commands = base
        elif which("sudo"):
            commands = [["sudo", *c] for c in base]
        elif which("doas"):
            commands = [["doas", *c] for c in base]
        else:
            return InstallPlan(
                f"Installing Tor needs root privileges ({manager}).",
                manual="Run as root:  " + " && ".join(" ".join(c) for c in base) + "\nThen press \"Check again\".",
            )

    note = ("Redoubt runs its own private Tor instance and does not use the system Tor service: "
            "the package may start one anyway (it can be disabled, e.g. \"systemctl disable --now tor\").")
    if manager == "dnf" and ids and ids[0] in ("rhel", "centos", "rocky", "almalinux", "ol"):
        note += " On RHEL-like systems the package comes from EPEL."
    return InstallPlan(f"Install the Tor package with {manager}.", commands=commands, note=note)


def run_install_plan(plan: InstallPlan) -> bool:
    """Run the plan's commands in the foreground, in order, attached to the terminal (the user sees every output line and
    types the sudo password there). Returns True if every command exited with 0"""
    for cmd in plan.commands:
        try:
            result = subprocess.run(cmd, env=_subprocess_env(), check=False)
        except OSError as e:
            logger.warning(f"Install command failed to start: {cmd[0]}: {e}")
            return False
        if result.returncode != 0:
            logger.warning(f"Install command exited with {result.returncode}: {cmd[0]}")
            return False
    return True


## Control port protocol

@dataclass
class Reply:
    code: int
    lines: list     # one str per reply line (data blocks are folded into the line they belong to, newline separated)

    @property
    def ok(self) -> bool:
        return 200 <= self.code < 300

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


class ControlConnection:
    """Minimal Tor control protocol client: one reader thread, strictly sequential requests, async events (650) to a callback"""

    def __init__(self, host: str, port: int, on_event=None, on_close=None, timeout: float = CONTROL_TIMEOUT):
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(None)
        self._file = self._sock.makefile("rb")
        self._on_event = on_event or (lambda line: None)
        self._on_close = on_close or (lambda: None)
        self._replies: "queue.Queue" = queue.Queue()
        self._request_lock = threading.Lock()
        self.closed = threading.Event()
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        lines, data_mode = [], False
        try:
            while True:
                raw = self._file.readline()
                if not raw:
                    break
                line = raw.rstrip(b"\r\n").decode("utf-8", "replace")
                if data_mode:   # inside a "+" data block: ends with a lone "."
                    if line == ".":
                        data_mode = False
                    else:
                        lines[-1] += "\n" + (line[1:] if line.startswith("..") else line)
                    continue
                if len(line) < 4 or not line[:3].isdigit():
                    continue
                code, sep, text = int(line[:3]), line[3], line[4:]
                if code == 650:     # async event: never mixed with the reply being collected
                    if sep == " " or sep == "-":
                        self._dispatch_event(text)
                    continue
                lines.append(text)
                if sep == "+":
                    data_mode = True
                elif sep == " ":    # final line of the reply
                    self._replies.put(Reply(code, lines))
                    lines = []
        except (OSError, ValueError):
            pass
        finally:
            self.closed.set()
            self._replies.put(None)     # wake a waiting request
            try:
                self._on_close()
            except Exception:
                logger.exception("Control connection close handler failed")

    def _dispatch_event(self, text: str):
        try:
            self._on_event(text)
        except Exception:
            logger.exception("Control event handler failed")

    def request(self, command: str, timeout: float = CONTROL_TIMEOUT) -> Reply:
        """Send one command and wait for its reply. The command is never logged (ADD_ONION carries the service key)"""
        if "\r" in command or "\n" in command:
            raise ValueError("control command must be a single line")
        with self._request_lock:
            if self.closed.is_set():
                raise TorError("Tor control connection is closed")
            try:
                self._sock.sendall(command.encode("utf-8") + b"\r\n")
                reply = self._replies.get(timeout=timeout)
            except queue.Empty:
                raise TorError("Tor did not answer on the control port in time") from None
            except OSError as e:
                raise TorError(f"Tor control connection failed: {e}") from e
            if reply is None:
                raise TorError("Tor control connection was closed")
            return reply

    def authenticate_safecookie(self, cookie: bytes):
        """SAFECOOKIE: proves we know the cookie without ever sending it, and proves Tor does too (a rogue listener on the port can't fake it)"""
        client_nonce = secrets.token_bytes(32)
        reply = self.request(f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}")
        if not reply.ok:
            raise TorError(f"Tor refused the authentication challenge: {reply.text}")
        m = re.search(r"SERVERHASH=([0-9A-Fa-f]{64}) SERVERNONCE=([0-9A-Fa-f]{64})", reply.text)
        if not m:
            raise TorError("Unexpected AUTHCHALLENGE reply from Tor")
        server_hash, server_nonce = bytes.fromhex(m.group(1)), bytes.fromhex(m.group(2))
        material = cookie + client_nonce + server_nonce
        if not hmac.compare_digest(_hmac(_SAFECOOKIE_SERVER, material), server_hash):
            raise TorError("The process on the control port failed cookie authentication (it is not our Tor)")
        reply = self.request("AUTHENTICATE " + _hmac(_SAFECOOKIE_CLIENT, material).hex())
        if not reply.ok:
            raise TorError(f"Tor refused the authentication: {reply.text}")

    def close(self):
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def parse_bootstrap(text: str):
    """'... BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY="..."' -> (45, 'loading_descriptors') or None"""
    m = re.search(r"BOOTSTRAP PROGRESS=(\d+)(?: TAG=(\S+))?", text)
    return (int(m.group(1)), m.group(2) or "") if m else None


def parse_socks_listener(text: str):
    """'net/listeners/socks="127.0.0.1:41231" "[::1]:41232"' -> ('127.0.0.1', 41231) (IPv4 preferred)"""
    addrs = re.findall(r'"([^"]+)"', text) or [text.split("=", 1)[-1].strip()]
    parsed = []
    for a in addrs:
        host, _, port = a.rpartition(":")
        if host and port.isdigit():
            parsed.append((host.strip("[]"), int(port)))
    for host, port in parsed:
        if "." in host:
            return host, port
    return parsed[0] if parsed else None


def parse_hs_desc_uploaded(text: str, service_id: str) -> bool:
    """True for an 'HS_DESC UPLOADED <service id> ...' event about OUR service"""
    parts = text.split()
    return len(parts) >= 3 and parts[0] == "HS_DESC" and parts[1] == "UPLOADED" and parts[2] == service_id


def _torrc_quote(value: str) -> str:
    """torrc string value (quoted; Windows paths use forward slashes, which Tor accepts)"""
    value = value.replace("\\", "/").replace('"', '\\"')
    return f'"{value}"'


## Tor manager

class TorManager:
    """Owns one private Tor process. States: stopped -> starting -> bootstrapping -> ready (or failed). Thread-safe"""

    def __init__(self, binary: str = None, tor_dir: str = TOR_DIR, on_change=None):
        self.tor_dir = tor_dir
        self.binary = binary
        self._on_change = on_change or (lambda: None)
        self._lock = threading.RLock()
        self._proc = None
        self._control: ControlConnection = None
        self._service_id = None
        self._closing = False       # True while WE are shutting the control connection down (not a Tor failure)
        self.state = "stopped"
        self.bootstrap_percent = 0
        self.bootstrap_tag = ""
        self.error = None
        self.socks = None       # (host, port) of the private SocksPort, known once started
        self.published = False  # the onion service descriptor was uploaded to the HSDirs
        self.version = None

    ## paths

    @property
    def _datadir(self): return os.path.join(self.tor_dir, "data")
    @property
    def _torrc(self): return os.path.join(self.tor_dir, "torrc")
    @property
    def _control_port_file(self): return os.path.join(self.tor_dir, "control_port")
    @property
    def _cookie_file(self): return os.path.join(self.tor_dir, "control_auth_cookie")
    @property
    def _log_file(self): return os.path.join(self.tor_dir, "tor.log")

    ## state

    def _set(self, **changes):
        with self._lock:
            for k, v in changes.items():
                setattr(self, k, v)
        try:
            self._on_change()
        except Exception:
            logger.exception("Tor state change handler failed")

    def _fail(self, message: str):
        logger.warning(f"Tor: {message}")
        self._set(state="failed", error=message)

    def log_tail(self, lines: int = 6) -> str:
        """Last lines of tor's own log (diagnostics for the user)"""
        try:
            with open(self._log_file, "r", encoding="utf-8", errors="replace") as f:
                return "\n".join(f.read().strip().splitlines()[-lines:])
        except OSError:
            return ""

    def _write_torrc(self):
        cfg = [
            f"DataDirectory {_torrc_quote(self._datadir)}",
            "SocksPort auto",                       # random free port on 127.0.0.1: never collides with a system Tor on 9050
            "ControlPort auto",
            f"ControlPortWriteToFile {_torrc_quote(self._control_port_file)}",
            "CookieAuthentication 1",
            f"CookieAuthFile {_torrc_quote(self._cookie_file)}",
            "ClientOnly 1",                         # never a relay
            "NoExec 1",
            "AvoidDiskWrites 1",
            "SafeLogging 1",
            f"Log notice file {self._log_file.replace(chr(92), '/')}",    # NOT quoted: Log takes the rest of the line literally
            f"__OwningControllerProcess {os.getpid()}",
        ]
        fd = os.open(self._torrc, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(cfg) + "\n")

    ## lifecycle

    def start(self, timeout: float = START_TIMEOUT):
        """Launch tor and authenticate on its control port. Returns once the control connection is ready (bootstrap continues
        in the background: see wait_ready()). Raises TorNotInstalled / TorError"""
        with self._lock:
            if self.state in ("starting", "bootstrapping", "ready"):
                return
            self._closing = False
            self._set(state="starting", error=None, bootstrap_percent=0, bootstrap_tag="", published=False, socks=None)

        try:
            binary = self.binary or find_tor_binary(self.tor_dir)
            if binary is None:
                raise TorNotInstalled("Tor is not installed.")
            self.binary = binary
            self.version = tor_version(binary)
            if self.version < MIN_TOR_VERSION:
                raise TorError("Installed Tor is too old: " + ".".join(map(str, self.version)) +
                               " (minimum " + ".".join(map(str, MIN_TOR_VERSION)) + ").")

            _make_private_dir(self.tor_dir)
            _make_private_dir(self._datadir)
            for stale in (self._control_port_file, self._cookie_file):
                try:
                    os.remove(stale)
                except FileNotFoundError:
                    pass
            with open(self._log_file, "w", encoding="utf-8"):    # fresh log each run (it never grows unbounded)
                pass
            self._write_torrc()

            self._proc = subprocess.Popen(
                [binary, "-f", self._torrc, "--ignore-missing-torrc"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=_subprocess_env(), **_popen_flags(),
            )
            self._connect_control(timeout)
        except TorError as e:
            self._abort(str(e))
            raise
        except OSError as e:
            self._abort(f"Cannot launch Tor: {e}")
            raise TorError(f"Cannot launch Tor: {e}") from e

    def _connect_control(self, timeout: float):
        deadline = time.monotonic() + timeout
        port = None
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                tail = self.log_tail()
                raise TorError("Tor exited right after starting." + (f"\n{tail}" if tail else ""))
            try:
                with open(self._control_port_file, "r", encoding="utf-8") as f:
                    m = re.match(r"PORT=(\S+):(\d+)", f.read().strip())
                if m and os.path.exists(self._cookie_file):
                    host, port = m.group(1), int(m.group(2))
                    break
            except OSError:
                pass
            time.sleep(0.1)
        if port is None:
            raise TorError("Tor did not open its control port in time.")

        try:
            self._control = ControlConnection(host, port, on_event=self._handle_event, on_close=self._control_closed)
            with open(self._cookie_file, "rb") as f:
                cookie = f.read()
            if len(cookie) != 32:
                raise TorError("Unexpected Tor control cookie.")
            self._control.authenticate_safecookie(cookie)

            reply = self._control.request("GETINFO net/listeners/socks")
            socks = parse_socks_listener(reply.text) if reply.ok else None
            if socks is None:
                raise TorError("Tor did not report its SOCKS port.")
            if not self._control.request("SETEVENTS STATUS_CLIENT HS_DESC").ok:
                raise TorError("Cannot subscribe to Tor events.")
            reply = self._control.request("GETINFO status/bootstrap-phase")
            boot = parse_bootstrap(reply.text) if reply.ok else None
        except OSError as e:
            raise TorError(f"Cannot connect to the Tor control port: {e}") from e

        percent, tag = boot or (0, "")
        with self._lock:    # an event may already have reported a newer percentage than this snapshot
            if percent < self.bootstrap_percent:
                percent, tag = self.bootstrap_percent, self.bootstrap_tag
        self._set(socks=socks, bootstrap_percent=percent, bootstrap_tag=tag,
                  state="ready" if percent >= 100 else "bootstrapping")

    def _handle_event(self, text: str):
        boot = parse_bootstrap(text) if text.startswith("STATUS_CLIENT") else None
        if boot is not None:
            percent, tag = boot
            with self._lock:
                if self.state not in ("bootstrapping", "ready", "starting"):
                    return
                state = "ready" if percent >= 100 else self.state
            self._set(bootstrap_percent=percent, bootstrap_tag=tag, state="bootstrapping" if state == "starting" else state)
            return
        with self._lock:
            sid = self._service_id
        if sid and parse_hs_desc_uploaded(text, sid):
            self._set(published=True)

    def _control_closed(self):
        with self._lock:
            expected = self._closing or self.state in ("stopped", "failed")
        if not expected:
            tail = self.log_tail()
            self._fail("Tor stopped unexpectedly." + (f"\n{tail}" if tail else ""))

    def wait_ready(self, timeout: float = BOOTSTRAP_TIMEOUT, cancel: threading.Event = None) -> bool:
        """Block until Tor finished bootstrapping. False on timeout, cancellation or failure"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                state = self.state
            if state == "ready":
                return True
            if state in ("failed", "stopped") or (cancel is not None and cancel.is_set()):
                return False
            time.sleep(0.2)
        return False

    def add_onion(self, seed: bytes, virtual_port: int, target_host: str, target_port: int) -> str:
        """Publish the onion service of `seed`: virtual_port on the .onion -> target_host:target_port.
        Returns the service id (the address without '.onion'). The service lives as long as the control connection"""
        control = self._control
        if control is None or control.closed.is_set():
            raise TorError("Tor is not running.")
        expected = onion_mod.address_from_seed(seed)[:-len(onion_mod.ONION_SUFFIX)]
        with self._lock:
            self._service_id = expected     # set BEFORE the command: the first HS_DESC event can be very fast
        reply = control.request(f"ADD_ONION {onion_mod.add_onion_key_arg(seed)} Port={virtual_port},{target_host}:{target_port}")
        if not reply.ok:
            with self._lock:
                self._service_id = None
            raise TorError(f"Tor refused to create the onion service: {reply.lines[0] if reply.lines else reply.code}")
        m = re.search(r"ServiceID=([a-z2-7]{56})", reply.text)
        if not m or m.group(1) != expected:
            self.remove_onion(m.group(1) if m else None)
            with self._lock:
                self._service_id = None
            raise TorError("Tor created a different onion address than the one derived from the stored key (refusing to use it).")
        return expected

    def remove_onion(self, service_id: str = None):
        sid = service_id or self._service_id
        control = self._control
        if sid and control is not None and not control.closed.is_set():
            try:
                control.request(f"DEL_ONION {sid}", timeout=3.0)
            except TorError:
                pass
        with self._lock:
            if sid == self._service_id:
                self._service_id = None
        self._set(published=False)

    def _abort(self, message: str):
        """Startup failed: tear everything down, remember the error"""
        self._terminate()
        self._fail(message)

    def _terminate(self):
        with self._lock:
            self._closing = True
        control, proc = self._control, self._proc
        self._control, self._proc = None, None
        if control is not None:
            if not control.closed.is_set():
                try:
                    control.request("SIGNAL HALT", timeout=2.0)     # immediate exit (no 30 s relay-style delay)
                except TorError:
                    pass
            control.close()
        if proc is not None:
            try:
                proc.wait(timeout=STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=STOP_TIMEOUT)
            except OSError:
                pass

    def stop(self):
        """Stop Tor (and with it the onion service). Safe to call at any time, any number of times"""
        with self._lock:
            if self.state == "stopped" and self._proc is None:
                return
            self._set(state="stopped")
            self._service_id = None
        self._terminate()
        self._set(state="stopped", socks=None, published=False, bootstrap_percent=0, bootstrap_tag="")
