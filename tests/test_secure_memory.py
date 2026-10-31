import resource
import sys

import pytest

from redoubt import secure_memory as sm


def test_zero_bytearray():
    b = bytearray(b"\x01\x02\x03")
    sm.zero_bytearray(b)
    assert b == bytearray(3)


def test_zero_bytearray_rejects_immutable():
    with pytest.raises(TypeError):
        sm.zero_bytearray(b"abc")


def test_securebuffer_accepts_only_int_bytes_bytearray():
    with pytest.raises(TypeError):
        sm.SecureBuffer("string")


def test_securebuffer_lifecycle():
    sb = sm.SecureBuffer(b"\xaa" * 32)
    assert len(sb) == 32
    assert bytes(sb) == b"\xaa" * 32
    view = sb.view()
    sb.zero()
    assert view == bytearray(32)  # zeroed in place, not just dereferenced
    with pytest.raises(ValueError):
        sb.view()
    with pytest.raises(ValueError):
        bytes(sb)
    sb.zero()  # idempotent


def test_securebuffer_context_manager_zeroes():
    with sm.SecureBuffer(b"\xff" * 16) as buf:
        assert buf == bytearray(b"\xff" * 16)
    assert buf == bytearray(16)


def test_securebuffer_from_size():
    assert bytes(sm.SecureBuffer(8)) == bytes(8)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_disable_core_dumps():
    sm.disable_core_dumps()
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
