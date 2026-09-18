### secure_memory.py

"""
Secure memory module for Redoubt
"""

import sys
import ctypes
import ctypes.util
import resource
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)


## Get libc for Linux (better memory management)

_libc = None
if sys.platform.startswith("linux"):
    try:
        _lib_path = ctypes.util.find_library("c")
        _libc = ctypes.CDLL(_lib_path, use_errno=True) if _lib_path else None
    except OSError:
        _libc = None


## Disable dumps on supported OSs

def disable_core_dumps():
    """To call ASAP in app.py, disables potentially information-leaking dumps"""
    if not hasattr(resource, "RLIMIT_CORE"):
        return  # platform without support (e.g. Windows)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        logger.warning(f"Cannot disable core dumps (RLIMIT_CORE): {RuntimeWarning}")


def zero_bytearray(buf: bytearray):
    """In-place zeroing of a bytearray"""
    if not isinstance(buf, bytearray):
        raise TypeError("zero_bytearray needs a mutable bytearray, not bytes")
    for i in range(len(buf)):
        buf[i] = 0


## Secure buffer class

class SecureBuffer:
    """
    Mlock and zeroing of critical information

    Typical usage:
        sb = SecureBuffer(some_bytes_from_hkdf)
        try:
            do_something(sb.view())
        finally:
            sb.zero()
    """

    __slots__ = ("_buf", "_locked", "_size", "_zeroed")

    def __init__(self, size_or_data):
        if isinstance(size_or_data, (int, bytes, bytearray)):
            self._buf = bytearray(size_or_data)
        else:
            raise TypeError("SecureBuffer only accepts int (size) or bytes/bytearray")

        self._size = len(self._buf)
        self._locked = False
        self._zeroed = False
        self._mlock()

    def _addr(self) -> int:
        """Return address of a piece of information in RAM"""
        return ctypes.addressof((ctypes.c_char * self._size).from_buffer(self._buf))

    def _mlock(self):
        """Lock all info in RAM and blocks swap on disk (leakage)"""
        if _libc is None or self._size == 0:
            return
        rc = _libc.mlock(ctypes.c_void_p(self._addr()), ctypes.c_size_t(self._size))
        self._locked = (rc == 0)
        if not self._locked:
            errno = ctypes.get_errno()
            logger.exception(f"mlock() failed (errno {errno}): this info CAN finish on disk with swap: {RuntimeWarning}")

    def zero(self):
        """Zeroing of a piece of information in RAM"""
        if self._zeroed:
            return
        for i in range(self._size):
            self._buf[i] = 0
        self._zeroed = True
        if self._locked and _libc is not None:
            _libc.munlock(ctypes.c_void_p(self._addr()), ctypes.c_size_t(self._size))
            self._locked = False

    def view(self) -> bytearray:
        """Returns correspondent bytearray (prefer this as it's mutable and zero-able)"""
        if self._zeroed:
            raise ValueError("SecureBuffer already zeroed, cannot fetch data")
        return self._buf

    def __bytes__(self) -> bytes:
        """Returns an IMMUTABLE bytes object. USE ONLY WHEN STRICTLY NEEDED"""
        if self._zeroed:
            raise ValueError("SecureBuffer already zeroed, cannot fetch data")
        return bytes(self._buf)

    def __len__(self):
        """Returns item length"""
        return self._size

    def __enter__(self):
        """Enters the context manager and returns the mutable bytearray buffer"""
        return self._buf

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exits the context manager and securely zeroes the buffer"""
        self.zero()
        return False

    def __del__(self):
        """Ensures the buffer is securely zeroed before garbage collection"""
        try:
            self.zero()
        except Exception:
            pass
