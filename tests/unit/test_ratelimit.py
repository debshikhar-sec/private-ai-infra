"""Unit tests for the per-principal token-bucket rate limiter.

Pure logic — no MLX import — so these run everywhere. A fake clock makes refill
deterministic.
"""

from private_ai_gateway.ratelimit import RateLimiter


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


def test_zero_limit_is_unlimited():
    rl = RateLimiter(0)
    for _ in range(1000):
        allowed, retry = rl.allow("p")
        assert allowed and retry == 0.0


def test_burst_then_throttle():
    clock = FakeClock()
    rl = RateLimiter(60, clock=clock)  # 60 rpm = 1 token/sec, burst 60
    # Drain the full burst without advancing time.
    for _ in range(60):
        allowed, _ = rl.allow("p")
        assert allowed
    # 61st is throttled.
    allowed, retry = rl.allow("p")
    assert not allowed
    assert 0.0 < retry <= 1.0


def test_refill_over_time():
    clock = FakeClock()
    rl = RateLimiter(60, clock=clock)
    for _ in range(60):
        rl.allow("p")
    assert rl.allow("p")[0] is False
    # One second later, ~1 token has refilled.
    clock.advance(1.0)
    assert rl.allow("p")[0] is True
    assert rl.allow("p")[0] is False


def test_buckets_are_per_principal():
    clock = FakeClock()
    rl = RateLimiter(1, clock=clock)
    assert rl.allow("a")[0] is True
    assert rl.allow("a")[0] is False
    # b has its own bucket, untouched by a's traffic.
    assert rl.allow("b")[0] is True


def test_per_principal_override_beats_default():
    clock = FakeClock()
    rl = RateLimiter(1, clock=clock)  # default 1 rpm
    # An explicit rpm=0 means unlimited for this principal.
    for _ in range(100):
        assert rl.allow("vip", rpm=0)[0] is True
