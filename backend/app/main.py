"""FastAPI entrypoint."""
import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import scheduler
from .config import CORS_ORIGINS
from .db import SessionLocal, init_db
from .exceptions_service import run_due_ticks
from . import clock as clockmod
from .routers.api import router
from .routers.exceptions_api import router as exceptions_router

app = FastAPI(
    title="Routing Policy Rehearsal Workbench",
    version="1.1.0",
    description="Offline prefix-list / route-policy simulation, shadow and "
                "semantic-diff analysis, time-bounded policy exceptions with "
                "immutable baselines, and FRR cross-validation.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(exceptions_router)


@app.on_event("startup")
def _startup():
    init_db()
    # catch up activations/expiries missed while the process was down; the
    # transition is idempotent and emits each history row at most once.
    s = SessionLocal()
    try:
        run_due_ticks(s, at=clockmod.now())
    except Exception:
        logging.getLogger("rlab.exceptions").exception("startup tick failed")
    finally:
        s.close()
    if os.environ.get("RLAB_DISABLE_SCHEDULER") != "1":
        scheduler.start()


@app.get("/api")
def api_root():
    return {"service": "rpolicy-lab", "docs": "/docs", "health": "/api/health"}


# Serve the built React bundle when present (single-port deployment).
# In development use `npm run dev` (Vite proxies /api to :8765).
_DIST = Path(os.environ.get(
    "RLAB_UI_DIST",
    Path(__file__).resolve().parents[2] / "frontend" / "dist"))
if _DIST.is_dir():
    app.mount("/assets",
              StaticFiles(directory=str(_DIST / "assets")), name="assets")

    @app.get("/")
    def _index():
        return FileResponse(str(_DIST / "index.html"))

    @app.get("/{full_path:path}")
    def _spa(full_path: str):
        if full_path.startswith(("api/", "docs", "openapi.json")):
            return {"detail": "not found"}
        return FileResponse(str(_DIST / "index.html"))
else:
    @app.get("/")
    def _root():
        return {"service": "rpolicy-lab", "docs": "/docs",
                "health": "/api/health", "ui": "run npm run dev in frontend/"}
