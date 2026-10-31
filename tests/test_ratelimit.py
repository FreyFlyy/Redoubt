import types

import pytest

from redoubt import ratelimit


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(ratelimit, "time", types.SimpleNamespace(monotonic=lambda: now[0]))
    return now


def test_count_limiter_blocks_then_recovers(clock):
    lim = ratelimit.CountRateLimiter(2, 10)
    assert lim.allow() and lim.allow()
    assert not lim.allow()
    clock[0] += 10.5
    assert lim.allow()


def test_byte_limiter_is_weighted(clock):
    lim = ratelimit.ByteRateLimiter(100, 10)
    assert lim.allow(60)
    assert not lim.allow(50)  # 110 > 100
    assert lim.allow(40)
    assert not lim.allow(1)


def test_rejected_request_is_not_counted(clock):
    lim = ratelimit.CountRateLimiter(1, 10)
    assert lim.allow()
    for _ in range(5):
        assert not lim.allow()
    clock[0] += 10.5
    assert lim.allow()  # rejected attempts must not extend the block


def test_flood_guard_is_per_ip(clock):
    g = ratelimit.ConnectionFloodGuard(max_per_window=1, window_seconds=10)
    assert g.allow("1.1.1.1")
    assert not g.allow("1.1.1.1")
    assert g.allow("2.2.2.2")


def test_flood_guard_hard_cap_evicts_oldest(clock):
    g = ratelimit.ConnectionFloodGuard(5, 10, prune_threshold=10_000, hard_cap=2)
    g.allow("a"), g.allow("b"), g.allow("c")
    assert len(g._by_ip) == 2
    assert "a" not in g._by_ip


def test_flood_guard_prunes_idle_ips(clock):
    g = ratelimit.ConnectionFloodGuard(5, 10, prune_threshold=1, hard_cap=100)
    g.allow("a")
    clock[0] += 60
    g.allow("b")
    g.allow("c")  # triggers prune (len > threshold)
    assert "a" not in g._by_ip


def test_global_session_cap():
    cap = ratelimit.GlobalSessionCap(3)
    assert cap.allow(2)
    assert not cap.allow(3)
    assert not cap.allow(10)
