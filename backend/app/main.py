"""FastAPI entrypoint."""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import CORS_ORIGINS
from .db import init_db
from .routers.api import router
from .routers.exceptions import router as exceptions_router
from .scheduler import scheduler


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # catch up on exception boundaries missed while the process was down,
    # then keep sweeping against the injectable clock.
    scheduler.start()
    try:
        yield
    finally:
        await scheduler.stop()


app = FastAPI(
    title="Routing Policy Rehearsal Workbench",
    version="1.1.0",
    description="Offline prefix-list / route-policy simulation, shadow and "
                "semantic-diff analysis, time-bounded maintenance exceptions, "
                "and FRR cross-validation.",
    lifespan=lifespan,
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
