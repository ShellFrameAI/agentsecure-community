import re
import time


DEFAULT_TTL_SECONDS = 2 * 60 * 60
MAX_TTL_SECONDS = 24 * 60 * 60


class DurationError(Exception):
    pass


def now_seconds() -> float:
    return time.time()


def parse_duration_seconds(value: str) -> int:
    text = (value or "").strip().lower()
    if not text:
        return DEFAULT_TTL_SECONDS
    match = re.match(r"^(\d+)([smhd]?)$", text)
    if not match:
        raise DurationError("invalid duration: %s" % value)
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    multipliers = {
        "s": 1,
        "m": 60,
        "h": 60 * 60,
        "d": 24 * 60 * 60,
    }
    seconds = amount * multipliers[unit]
    if seconds <= 0:
        raise DurationError("duration must be positive")
    if seconds > MAX_TTL_SECONDS:
        raise DurationError("duration exceeds max TTL of 24h")
    return seconds

