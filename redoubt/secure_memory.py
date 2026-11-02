### secure_memory.py

"""
Secure memory module for Redoubt
"""

import sys
import ctypes
import ctypes.util
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)

_IS_WINDOWS = sys.platform == "win32"
if not _IS_WINDOWS:
    import resource     # POSIX only: the module does not exist on Windows
else:
    resource = None


## Get libc for Linux (better memory management)

_libc = None
if sys.platform.startswith("linux"):
    try:
        _lib_path = ctypes.util.find_library("c")
        _libc = ctypes.CDLL(_lib_path, use_errno=True) if _lib_path else None
    except OSError:
        _libc = None


## Get kernel32 for Windows (VirtualLock / VirtualUnlock)

_k32 = None
if _IS_WINDOWS:
    try:
        from ctypes import wintypes
        _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _k32.VirtualLock.argtypes = [wintypes.LPVOID, ctypes.c_size_t]
        _k32.VirtualLock.restype = wintypes.BOOL
        _k32.VirtualUnlock.argtypes = [wintypes.LPVOID, ctypes.c_size_t]
        _k32.VirtualUnlock.restype = wintypes.BOOL
        _k32.GetCurrentProcess.argtypes = []
        _k32.GetCurrentProcess.restype = wintypes.HANDLE
        _k32.GetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
        _k32.GetProcessWorkingSetSize.restype = wintypes.BOOL
        _k32.SetProcessWorkingSetSize.argtypes = [wintypes.HANDLE, ctypes.c_size_t, ctypes.c_size_t]
        _k32.SetProcessWorkingSetSize.restype = wintypes.BOOL
        _k32.SetErrorMode.argtypes = [wintypes.UINT]
        _k32.SetErrorMode.restype = wintypes.UINT
    except (OSError, AttributeError):
        _k32 = None

# VirtualLock counts every locked page against the process MINIMUM working set (default is tiny): raise it once, lazily
_WS_EXTRA_BYTES = 4 * 1024 * 1024
_ws_raised = False

def _raise_working_set_quota():
    """Windows only: grow the working set (min and max) by _WS_EXTRA_BYTES so that VirtualLock has room. Never shrinks"""
    global _ws_raised
    if _ws_raised or _k32 is None:
        return
    _ws_raised = True   # try only once
    proc = _k32.GetCurrentProcess()
    ws_min, ws_max = ctypes.c_size_t(0), ctypes.c_size_t(0)
    if not _k32.GetProcessWorkingSetSize(proc, ctypes.byref(ws_min), ctypes.byref(ws_max)):
        logger.warning(f"GetProcessWorkingSetSize failed (error {ctypes.get_last_error()}): VirtualLock may fail")
        return
    if not _k32.SetProcessWorkingSetSize(proc, ws_min.value + _WS_EXTRA_BYTES, ws_max.value + _WS_EXTRA_BYTES):
        logger.warning(f"SetProcessWorkingSetSize failed (error {ctypes.get_last_error()}): VirtualLock may fail")


## Platform-neutral page locking

def _locking_supported() -> bool:
    """True if this platform has a page-locking backend"""
    return _libc is not None or _k32 is not None

def _lock_memory(addr: int, size: int):
    """Pin [addr, addr+size) in RAM. Returns (ok, error_code)"""
    if _k32 is not None:
        _raise_working_set_quota()
        ok = bool(_k32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(size)))
        return ok, (0 if ok else ctypes.get_last_error())
    rc = _libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
    return rc == 0, (0 if rc == 0 else ctypes.get_errno())

def _unlock_memory(addr: int, size: int):
    """Release the pin made by _lock_memory"""
    if _k32 is not None:
        _k32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
    elif _libc is not None:
        _libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))


## Disable dumps on supported OSs

def disable_core_dumps():
    """To call ASAP in app.py, disables potentially information-leaking dumps"""
    if _IS_WINDOWS:
        # No RLIMIT_CORE on Windows. SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX only suppresses the crash dialog/report
        # of this process: it does NOT guarantee that WER LocalDumps (registry-configured, system-wide) won't write a dump
        if _k32 is not None:
            _k32.SetErrorMode(0x0001 | 0x0002)
        logger.info("Core dumps cannot be disabled on Windows (best-effort only: crash UI/report suppressed)")
        return
    if resource is None or not hasattr(resource, "RLIMIT_CORE"):
        return  # platform without support
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError) as e:
        logger.warning(f"Cannot disable core dumps (RLIMIT_CORE): {e}")


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
        if not _locking_supported() or self._size == 0:
            return
        self._locked, err = _lock_memory(self._addr(), self._size)
        if not self._locked:
            logger.warning(f"Memory lock failed (OS error {err}): this info CAN finish on disk with swap")

    def zero(self):
        """Zeroing of a piece of information in RAM"""
        if self._zeroed:
            return
        for i in range(self._size):
            self._buf[i] = 0
        self._zeroed = True
        if self._locked:
            _unlock_memory(self._addr(), self._size)
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
