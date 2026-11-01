### ratelimit.py

"""
Rate-limiting module for Redoubt
"""

import time
import threading
from collections import deque, OrderedDict
from typing import Optional


## Generic sliding windown limiter

class _SlidingWindowLimiter:
    def __init__(self, limit: float, window_seconds: float):
        self.limit = limit
        self.window_seconds = window_seconds
        self._entries = deque()  # (timestamp, size), in order or arrival
        self._total = 0.0
        self._lock = threading.Lock()

    def _evict(self, now: float):
        """Only select observations in the sliding window"""
        cutoff = now - self.window_seconds
        while self._entries and self._entries[0][0] < cutoff:
            _, weight = self._entries.popleft()
            self._total -= weight

    def allow(self, weight: float = 1) -> bool:
        """True if the peer hasn't reached the limit, False otherwise"""
        now = time.monotonic()

        with self._lock:
            self._evict(now)

            if self._total + weight > self.limit:
                return False

            self._entries.append((now, weight))
            self._total += weight
            return True

    def is_idle(self, now: Optional[float] = None) -> bool:
        """True if there are no observations in the sliding window"""
        now = now if now is not None else time.monotonic()
        with self._lock:
            self._evict(now)
            return not self._entries


## Limiters

class ByteRateLimiter(_SlidingWindowLimiter):
    """Limit = max bytes in sliding window"""
    pass


class CountRateLimiter(_SlidingWindowLimiter):
    """Limit = max events (e.g. connections) in sliding window"""
    pass


## Connection flood guard class (per-IP)

class ConnectionFloodGuard:
    """Per-IP session guard (to avoid malicious users to flood with sessions)"""
    def __init__(self, max_per_window: int, window_seconds: float, prune_threshold: int = 10_000, hard_cap: int = 10_000):
        self.max_per_window = max_per_window
        self.window_seconds = window_seconds
        self.prune_threshold = prune_threshold
        self.hard_cap = hard_cap    # real cap, independent of idle/active state
        self._by_ip: OrderedDict[str, CountRateLimiter] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        """True if an IP is allowed to connect, False if it has reached the limit in the current sliding window"""
        with self._lock:
            limiter = self._by_ip.get(ip)

            if limiter is None:
                if len(self._by_ip) > self.prune_threshold:
                    self._prune_locked()

                if len(self._by_ip) >= self.hard_cap:
                    # hard cap reached: evict the oldest (LRU), regardless of idle or not
                    self._by_ip.popitem(last=False)

                limiter = CountRateLimiter(self.max_per_window, self.window_seconds)
                self._by_ip[ip] = limiter
            else:
                self._by_ip.move_to_end(ip)   # refresh recency for LRU

        return limiter.allow()

    def _prune_locked(self):
        """Deletes IPs from the dict if there are no observations in the current sliding window"""
        now = time.monotonic()
        stale = [ip for ip, limiter in self._by_ip.items() if limiter.is_idle(now)]
        for ip in stale:
            del self._by_ip[ip]


## Global concurrent-session cap class

class GlobalSessionCap:
    """Global session cap for ALL contacts (to avoid malicious users to flood with different IPs and avoiding ConnectionFloodGuard)"""
    def __init__(self, max_sessions: int):
        self.max_sessions = max_sessions

    def allow(self, current_count: int) -> bool:
        """True if another session can be initialized"""
        return current_count < self.max_sessions