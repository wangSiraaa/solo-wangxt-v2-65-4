"""
Injectable clock.

All time-dependent exception logic (activation / expiry ticking, timelines,
"current" synthesis) goes through this module instead of calling
``datetime.now`` directly, so tests can freeze or advance time deterministically.

Times are timezone-aware UTC throughout; naive input is rejected/normalized at
the schema boundary (see exceptions_service.parse_dt).
"""
from __future__ import annotations

import datetime as dt
import threading
from typing import Optional


class Clock:
    def now(self) -> dt.datetime:
        raise NotImplementedError


class SystemClock(Clock):
    def now(self) -> dt.datetime:
        return dt.datetime.now(dt.timezone.utc)


class FixedClock(Clock):
    """Clock frozen at a settable instant; advance/set under a lock."""

    def __init__(self, start: Optional[dt.datetime] = None):
        self._t = start or dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        self._lock = threading.Lock()

    def now(self) -> dt.datetime:
        with self._lock:
            return self._t

    def set(self, t: dt.datetime) -> None:
        with self._lock:
            self._t = _aware(t)

    def advance(self, delta: dt.timedelta) -> dt.datetime:
        with self._lock:
            self._t = _aware(self._t) + delta
            return self._t


def _aware(t: dt.datetime) -> dt.datetime:
    if t.tzinfo is None:
        return t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc)


_state_lock = threading.Lock()
_clock: Clock = SystemClock()


def get_clock() -> Clock:
    return _clock


def now() -> dt.datetime:
    return _clock.now()


def set_clock(clock: Clock) -> None:
    global _clock
    with _state_lock:
        _clock = clock


def reset_clock() -> None:
    global _clock
    with _state_lock:
        _clock = SystemClock()


def freeze(t: Optional[dt.datetime] = None) -> FixedClock:
    """Install a FixedClock (tests/lab) and return it for advancing."""
    fixed = FixedClock(t)
    set_clock(fixed)
    return fixed
