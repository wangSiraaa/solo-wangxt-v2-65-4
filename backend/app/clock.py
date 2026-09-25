"""
Injectable clock.

All time-bounded exception logic reads ``clock.now()`` instead of
``datetime.now()`` directly, so tests (and the lab UI) can freeze / advance
time deterministically. The override is process-wide and also drives the
background sweep scheduler, which is what makes late timer events safe:
nothing ever "catches up" against an uncontrolled wall clock.
"""
from __future__ import annotations

import datetime as dt
from typing import Optional


class Clock:
    def __init__(self) -> None:
        self._override: Optional[dt.datetime] = None

    def now(self) -> dt.datetime:
        """Current time as timezone-aware UTC."""
        if self._override is not None:
            return self._override
        return dt.datetime.now(dt.timezone.utc)

    def set(self, value: Optional[dt.datetime]) -> None:
        """Freeze at ``value`` (aware/naive->UTC), or pass None for real time."""
        if value is None:
            self._override = None
        else:
            self._override = as_utc(value)

    def reset(self) -> None:
        self._override = None

    @property
    def override(self) -> Optional[dt.datetime]:
        return self._override


clock = Clock()


def as_utc(value: dt.datetime) -> dt.datetime:
    """Normalize possibly-naive DB values / user input to aware UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)
