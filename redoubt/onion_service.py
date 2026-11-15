### onion_service.py

"""
Onion service orchestration for Redoubt: everything the "Use Tor/Onion network" switch turns on and off.

Turning it ON, in order:
  1. look for a tor executable (none -> state "need_install": the UI offers the install helper, nothing is started)
  2. get-or-create the onion service key (kept encrypted in the vault database) and check the address it derives to
  3. open the loopback listener the onion service forwards to
  4. start Redoubt's private Tor, publish the service with ADD_ONION and check that Tor created EXACTLY the expected address
  5. wait for Tor to bootstrap, then let the network layer dial onion contacts through Tor's SOCKS port
Turning it OFF undoes all of it (and with the switch off none of this code, nor Tor, ever runs).

enable()/disable() block (bootstrap can take a minute): call them from a worker thread. State is read with plain attributes.
"""

import threading

from . import network as network_mod
from . import onion as onion_mod
from . import tor_manager
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)


## Variables

SECRET_NAME = "onion_service_seed"

# States
OFF = "off"
CHECKING = "checking"
NEED_INSTALL = "need_install"
STARTING = "starting"
BOOTSTRAPPING = "bootstrapping"
READY = "ready"
ERROR = "error"
BUSY_STATES = (CHECKING, STARTING, BOOTSTRAPPING)


## Helpers

def stored_address(storage):
    """Own onion address if a key was already generated (read-only: never creates a key, never needs Tor), else None"""
    seed = storage.get_secret(SECRET_NAME)
    if seed is None or len(seed) != onion_mod.SEED_LEN:
        return None
    try:
        return onion_mod.address_from_seed(seed)
    except ValueError:
        return None


## OnionService class

class OnionService:
    def __init__(self, storage, network, tor_dir: str = tor_manager.TOR_DIR, tor_factory=tor_manager.TorManager,
                 virtual_port: int = network_mod.DEFAULT_PORT):
        self.storage = storage
        self.network = network
        self.tor_dir = tor_dir
        self._tor_factory = tor_factory
        self.virtual_port = virtual_port    # the port contacts use on our .onion address (same default port as IP contacts)

        self.tor = None
        self.state = OFF
        self.message = ""
        self._cancel = threading.Event()
        self._op_lock = threading.Lock()    # one enable()/disable() at a time

    ## Status

    def _set(self, state, message=""):
        self.state, self.message = state, message
        logger.info(f"Onion: {state} {message}".strip())

    @property
    def address(self):
        """Own onion address (from the stored key), or None if no key exists yet"""
        return stored_address(self.storage)

    @property
    def busy(self) -> bool:
        return self.state in BUSY_STATES

    @property
    def published(self) -> bool:
        return self.state == READY and bool(self.tor is not None and self.tor.published)

    @property
    def status_text(self) -> str:
        tor = self.tor
        if self.state == OFF:
            return "Off"
        if self.state == CHECKING:
            return "Checking Tor installation and onion address..."
        if self.state == NEED_INSTALL:
            return "Tor is not installed"
        if self.state == STARTING:
            return "Starting Tor..."
        if self.state == BOOTSTRAPPING:
            return f"Connecting to the Tor network... {tor.bootstrap_percent if tor else 0}%"
        if self.state == READY:
            return ("Online: onion service published" if self.published
                    else "Connected to Tor: publishing the onion service...")
        return f"Error: {self.message}"

    ## Key

    def ensure_key(self) -> str:
        """Get-or-create the onion service key and CHECK the address it derives to. Returns the address.
        Raises ValueError if a stored key is unusable (it is never silently replaced: that would change the address contacts know)"""
        seed = self.storage.get_secret(SECRET_NAME)
        if seed is None:
            seed = onion_mod.generate_seed()
            self.storage.set_secret(SECRET_NAME, seed)
        if len(seed) != onion_mod.SEED_LEN:
            raise ValueError("The stored onion key is invalid (wrong length). Generate a new onion address from Settings.")
        address = onion_mod.address_from_seed(seed)
        if onion_mod.parse_onion_address(address) != onion_mod.pubkey_from_seed(seed):    # derive -> parse round trip
            raise ValueError("The onion address derived from the stored key is not valid.")
        return address

    def regenerate_key(self) -> str:
        """Replace the onion key with a new one (new address: contacts must be given the new one). Only while Tor is off"""
        with self._op_lock:
            if self.state == READY or self.state in BUSY_STATES:
                raise RuntimeError("Turn the Tor/Onion network off before generating a new onion address.")
            self.storage.delete_secret(SECRET_NAME)
            return self.ensure_key()

    ## Lifecycle

    def enable(self) -> bool:
        """Turn the onion side on (blocking). True when Tor is up and the onion service is created; on False see .state:
        NEED_INSTALL (call enable() again after installing Tor), ERROR (see .message), or OFF (cancelled)"""
        self._cancel.clear()
        with self._op_lock:
            if self.state == READY:
                return True
            try:
                self._set(CHECKING)
                binary = tor_manager.find_tor_binary(self.tor_dir)
                if binary is None:
                    self._set(NEED_INSTALL, "Tor is not installed.")
                    return False
                try:
                    expected = self.ensure_key()
                except ValueError as e:
                    self._set(ERROR, str(e))
                    return False
                if self._cancel.is_set():
                    return self._cancelled()

                local_port = self.network.start_onion_listener()
                self.tor = self._tor_factory(binary=binary, tor_dir=self.tor_dir)
                self._set(STARTING)
                self.tor.start()

                seed = bytearray(self.storage.get_secret(SECRET_NAME))
                try:
                    service_id = self.tor.add_onion(bytes(seed), self.virtual_port, "127.0.0.1", local_port)
                finally:
                    for i in range(len(seed)):  # best effort: do not leave the key around longer than needed
                        seed[i] = 0
                if service_id + onion_mod.ONION_SUFFIX != expected:     # add_onion already checks it: belt and braces
                    raise tor_manager.TorError("Tor created a different onion address than expected.")

                self._set(BOOTSTRAPPING)
                if not self.tor.wait_ready(cancel=self._cancel):
                    if self._cancel.is_set():
                        return self._cancelled()
                    detail = self.tor.error or "Tor did not finish connecting to the network in time (check your internet connection)."
                    raise tor_manager.TorError(detail)
                if self._cancel.is_set():
                    return self._cancelled()

                self.network.enable_onion_dialing(self.tor.socks)
                self._set(READY, expected)
                return True
            except tor_manager.TorNotInstalled:
                self._teardown()
                self._set(NEED_INSTALL, "Tor is not installed.")
                return False
            except (tor_manager.TorError, OSError) as e:
                self._teardown()
                self._set(ERROR, str(e))
                return False
            except Exception as e:
                logger.exception("Unexpected error while enabling the onion network")
                self._teardown()
                self._set(ERROR, f"Unexpected error: {e}")
                return False

    def _cancelled(self) -> bool:
        self._teardown()
        self._set(OFF)
        return False

    def _teardown(self):
        """Undo everything enable() may have done (idempotent)"""
        self.network.stop_onion()
        tor, self.tor = self.tor, None
        if tor is not None:
            tor.stop()

    def disable(self):
        """Turn the onion side off (blocking, up to a few seconds while Tor shuts down). Also cancels a running enable()"""
        self._cancel.set()
        with self._op_lock:
            self._teardown()
            self._set(OFF)
