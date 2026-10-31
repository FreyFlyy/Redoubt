"""
Shared test setup for Redoubt.

HOME is redirected BEFORE any `redoubt` import, because identity/storage/logger
compute their paths (~/.redoubt) at import time. This keeps tests away from
the real user data.
"""
import os
import tempfile

_TEST_HOME = tempfile.mkdtemp(prefix="redoubt-test-home-")
os.environ["HOME"] = _TEST_HOME

import pytest  # noqa: E402

from redoubt import crypto  # noqa: E402


@pytest.fixture
def fast_kdf(monkeypatch):
    """Cheap Argon2id parameters so tests don't spend 256 MiB per derivation."""
    monkeypatch.setattr(crypto, "ARGON2ID_TIME_COST", 1)
    monkeypatch.setattr(crypto, "ARGON2ID_MEMORY_COST_KIB", 64)
    monkeypatch.setattr(crypto, "ARGON2ID_PARALLELISM", 1)


@pytest.fixture
def vault_key():
    return os.urandom(32)
