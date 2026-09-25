"""
Background ticker for exception activation/expiry.

Every RLAB_TICK_INTERVAL seconds (default 5) it runs the idempotent
run_due_ticks() catch-up against the INJECTED clock. The catch-up also runs on
API startup, so events missed while the process was down are applied once
(unique idempotency keys prevent duplicate history rows).
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os

from . import clock, db as dbmod
from . import exceptions_service as xs

log = logging.getLogger("rlab.exceptions")

TICK_INTERVAL = float(os.environ.get("RLAB_TICK_INTERVAL", "5"))

_started = False
_task: asyncio.Task | None = None


async def _loop(interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            s = dbmod.SessionLocal()
            try:
                xs.run_due_ticks(s, at=clock.now())
            finally:
                s.close()
        except Exception:  # pragma: no cover - ticker must never kill the app
            log.exception("exception tick failed")


def start(interval: float = TICK_INTERVAL) -> None:
    global _started, _task
    if _started:
        return
    _started = True
    _task = asyncio.create_task(_loop(interval))


def stop() -> None:
    global _started, _task
    if _task is not None:
        _task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            pass
        _task = None
    _started = False
