"""A small in-memory rate limiter (sliding window).

Used to slow down password guessing, account spam and expensive requests.

Good to know:
  * It lives in memory. Restarting the server clears it, and several server
    processes would each keep their own counts. A real deployment with more
    than one process should use a shared store such as Redis.
  * The clock can be replaced, so tests never have to wait.
"""

import math
import threading
import time
from collections import deque


class RateLimiter:
    """Allow at most `max_events` events per key inside `window_seconds`."""

    def __init__(self, max_events, window_seconds, clock=time.monotonic, max_keys=10_000):
        if max_events < 1 or max_keys < 1 or window_seconds <= 0:
            raise ValueError(
                "max_events and max_keys must be at least 1 and window_seconds must be positive."
            )
        self.max_events = max_events
        self.window_seconds = window_seconds
        self.clock = clock
        self.max_keys = max_keys
        self._events = {}
        self._lock = threading.Lock()

    # -- internal helpers (the caller already holds the lock) -----------------
    def _recent(self, key, now):
        """Events still inside the window. Old ones are dropped."""
        events = self._events.get(key)
        if events is None:
            return None
        while events and now - events[0] >= self.window_seconds:
            events.popleft()
        if not events:
            del self._events[key]
            return None
        return events

    def _add(self, key, now):
        events = self._events.get(key)
        if events is None:
            if len(self._events) >= self.max_keys:
                self._make_room(now)
            events = self._events[key] = deque()
        events.append(now)

    def _make_room(self, now):
        """Keep memory bounded even if an attacker invents endless keys."""
        for old_key in list(self._events):
            self._recent(old_key, now)  # forgets keys whose events all expired
        while len(self._events) >= self.max_keys:
            del self._events[next(iter(self._events))]  # forget the oldest key

    # -- public API ------------------------------------------------------------
    def is_blocked(self, key):
        with self._lock:
            events = self._recent(key, self.clock())
            return events is not None and len(events) >= self.max_events

    def retry_after(self, key):
        """Whole seconds until this key may try again (0 if it is not blocked)."""
        with self._lock:
            now = self.clock()
            events = self._recent(key, now)
            if events is None or len(events) < self.max_events:
                return 0
            oldest_that_must_expire = events[len(events) - self.max_events]
            return max(1, math.ceil(oldest_that_must_expire + self.window_seconds - now))

    def record(self, key):
        """Count one event, for example one failed login."""
        with self._lock:
            self._add(key, self.clock())

    def hit(self, key):
        """Count one use. Returns False, counting nothing, if already at the limit."""
        with self._lock:
            now = self.clock()
            events = self._recent(key, now)
            if events is not None and len(events) >= self.max_events:
                return False
            self._add(key, now)
            return True

    def reset(self, key):
        with self._lock:
            self._events.pop(key, None)

    def clear(self):
        with self._lock:
            self._events.clear()