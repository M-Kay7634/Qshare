"""Tests for app/rate_limiter.py (uses a fake clock, so nothing ever waits)."""

import threading

import pytest

from app.rate_limiter import RateLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make(max_events=3, window=60, **options):
    clock = FakeClock()
    return RateLimiter(max_events, window, clock=clock, **options), clock


def test_blocks_only_after_the_limit_is_reached():
    limiter, _ = make(max_events=3)
    for _ in range(2):
        limiter.record("a")
        assert not limiter.is_blocked("a")
    limiter.record("a")
    assert limiter.is_blocked("a")


def test_events_expire_one_by_one_as_the_window_slides():
    limiter, clock = make(max_events=3, window=60)
    limiter.record("a")      # t = 0
    clock.advance(20)
    limiter.record("a")      # t = 20
    clock.advance(20)
    limiter.record("a")      # t = 40  -> blocked
    assert limiter.is_blocked("a")

    clock.advance(19)        # t = 59: the first event is still inside the window
    assert limiter.is_blocked("a")
    clock.advance(2)         # t = 61: the first event has expired
    assert not limiter.is_blocked("a")


def test_retry_after_counts_down_to_the_moment_of_release():
    limiter, clock = make(max_events=2, window=60)
    assert limiter.retry_after("a") == 0        # not blocked
    limiter.record("a")
    clock.advance(10)
    limiter.record("a")                         # blocked until t = 60
    assert limiter.retry_after("a") == 50
    clock.advance(49.5)
    assert limiter.retry_after("a") == 1        # never reports 0 while blocked
    clock.advance(1)
    assert limiter.retry_after("a") == 0


def test_hit_counts_until_the_limit_and_blocked_hits_are_not_counted():
    limiter, clock = make(max_events=2, window=60)
    assert limiter.hit("a") is True             # t = 0
    assert limiter.hit("a") is True             # t = 0
    for _ in range(3):                          # three refused attempts, spread out
        clock.advance(10)
        assert limiter.hit("a") is False
    # t = 30. Refused attempts must NOT extend the lockout: it ends at t = 60.
    clock.advance(31)                           # t = 61
    assert limiter.hit("a") is True


def test_keys_are_independent_and_reset_works():
    limiter, _ = make(max_events=1)
    limiter.record("a")
    assert limiter.is_blocked("a")
    assert not limiter.is_blocked("b")
    limiter.reset("a")
    assert not limiter.is_blocked("a")
    limiter.record("a")
    limiter.record("b")
    limiter.clear()
    assert not limiter.is_blocked("a") and not limiter.is_blocked("b")


def test_memory_stays_bounded_when_keys_never_repeat():
    limiter, _ = make(max_events=5, max_keys=3)
    for number in range(10):
        limiter.record(f"key{number}")
    assert len(limiter._events) <= 3
    assert "key9" in limiter._events            # the newest key is kept


def test_expired_keys_are_forgotten_before_live_ones_are_evicted():
    limiter, clock = make(max_events=5, window=60, max_keys=2)
    limiter.record("old1")
    limiter.record("old2")
    clock.advance(61)
    limiter.record("fresh1")
    limiter.record("fresh2")
    assert set(limiter._events) == {"fresh1", "fresh2"}


def test_many_threads_never_get_more_than_the_limit():
    limiter, _ = make(max_events=500, window=3600)
    allowed = []

    def worker():
        for _ in range(100):
            allowed.append(limiter.hit("shared"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(allowed) == 800
    assert sum(allowed) == 500


@pytest.mark.parametrize("max_events, window, max_keys",
                         [(0, 60, 10), (3, 0, 10), (3, -1, 10), (3, 60, 0)])
def test_invalid_settings_are_rejected(max_events, window, max_keys):
    with pytest.raises(ValueError):
        RateLimiter(max_events, window, max_keys=max_keys)