"""
Defense-in-Depth — Layer 1: Rate Limiter (sliding window, per-user)

Why this layer?
  - Catches: script / bot abuse (someone trying 1000 prompts/sec to find a
    jailbreak), brute-force "forgot password" attempts, and accidental
    infinite loops from a buggy client.
  - Catches what other layers don't: a single user can pass the topic
    filter and the injection detector on EVERY message but still be
    abusive. Rate-limiting is orthogonal to content checks.
  - In production this is the FIRST thing a real API gateway does.

Design:
  - In-memory sliding window via collections.deque.
  - Per-user (and per-IP) so one noisy user can't starve everyone else.
  - Returns the number of seconds the user must wait before retrying.
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    """Outcome of a rate-limit check."""
    allowed: bool          # True = request may proceed
    retry_after: float     # seconds the caller should wait (0 if allowed)
    current_count: int     # how many requests the user has in the window now
    limit: int             # configured max


class RateLimiter:
    """Sliding-window rate limiter (per-user, per-key).

    Defaults: 10 requests / 60 seconds.
    """

    def __init__(self, max_requests: int = 10, window_seconds: float = 60.0):
        # user_id -> deque[float] of request timestamps
        self._buckets: dict[str, deque] = defaultdict(deque)
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    def check(self, user_id: str) -> RateLimitResult:
        """Atomically check + record a request from `user_id`."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        bucket = self._buckets[user_id]

        # 1) Drop timestamps that have aged out of the window.
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        # 2) If at capacity, reject and tell the caller when to retry.
        if len(bucket) >= self.max_requests:
            # The oldest in-window request will expire at bucket[0] + window.
            retry_after = max(0.0, (bucket[0] + self.window_seconds) - now)
            return RateLimitResult(
                allowed=False,
                retry_after=retry_after,
                current_count=len(bucket),
                limit=self.max_requests,
            )

        # 3) Otherwise, record this request and allow it.
        bucket.append(now)
        return RateLimitResult(
            allowed=True,
            retry_after=0.0,
            current_count=len(bucket),
            limit=self.max_requests,
        )

    def reset(self, user_id: str | None = None) -> None:
        """Clear rate-limit history. If user_id is None, clear all users."""
        if user_id is None:
            self._buckets.clear()
        else:
            self._buckets.pop(user_id, None)


# ---- Self-test (run as `python defense/rate_limiter.py`) ----
if __name__ == "__main__":
    rl = RateLimiter(max_requests=3, window_seconds=2.0)
    for i in range(5):
        r = rl.check("alice")
        print(f"req {i+1}: allowed={r.allowed} count={r.current_count}/{r.limit} "
              f"retry_after={r.retry_after:.2f}s")
