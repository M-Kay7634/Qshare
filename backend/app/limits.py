"""Rate limits for the whole app, in one place.

Each limiter counts events per key (an account, an address or a user id).
They are in memory, so restarting the server clears them.
"""

from app.rate_limiter import RateLimiter

# Password guessing: per account (from one address) and per address overall.
login_failures_per_account = RateLimiter(max_events=5, window_seconds=15 * 60)
login_failures_per_ip = RateLimiter(max_events=30, window_seconds=15 * 60)

# Account spam.
registrations_per_ip = RateLimiter(max_events=10, window_seconds=60 * 60)

# Expensive work that needs a login.
uploads_per_user = RateLimiter(max_events=30, window_seconds=60)
crypto_calls_per_user = RateLimiter(max_events=30, window_seconds=60)

ALL = (
    login_failures_per_account,
    login_failures_per_ip,
    registrations_per_ip,
    uploads_per_user,
    crypto_calls_per_user,
)


def reset_all():
    """Forget every count (used by the tests)."""
    for limiter in ALL:
        limiter.clear()