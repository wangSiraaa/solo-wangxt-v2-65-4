"""
Background timer for exception boundaries.

A single asyncio task periodically runs the idempotent catch-up sweep against
the injectable clock. On startup it sweeps immediately, so boundaries missed
while the process was down are applied once at boot (and recorded once).
Nothing here ever fires on the uncontrolled wall clock.
"""
from __future__ import annotations

import asyncio
import contextlib
import os

from .clock import clock
from .db import SessionLocal
from . import exception_service as es

SWEEP_INTERVAL = float(os.environ.get("RLAB_SWEEP_INTERVAL", "5"))
ENABLED = os.environ.get("RLAB_SWEEP_DISABLED", "").lower() not in ("1", "true", "yes")


class SweepScheduler:
    def __init__(self, interval: float = SWEEP_INTERVAL) -> None:
        self.interval = interval
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def _run(self) -> None:
        self.sweep_once()
        while True:
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval)
                return                       # stop requested
            except asyncio.TimeoutError:
                self.sweep_once()            # periodic tick

    def sweep_once(self) -> None:
        s = SessionLocal()
        try:
            es.sweep(s, now=clock.now())
        except Exception:  # noqa: BLE001 - timer must never kill the loop
            pass
        finally:
            s.close()

    def start(self) -> None:
        if not ENABLED or self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None


scheduler = SweepScheduler()
