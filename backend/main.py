"""
Universal Log Pre-processing Framework — FastAPI Application
SIH 2026 Prototype for NTRO (SIH26156)

Central principle:
  DETERMINISTIC WHEN KNOWN. ADAPTIVE WHEN UNKNOWN.
  VERIFIED BEFORE TRUST. LEARNED PARSERS RETURN TO THE FAST PATH.
  RAW EVIDENCE REMAINS TRACEABLE.

  AI PROPOSES. TRUST GATE DECIDES. LEDGER PROVES.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.storage.database import init_db
from backend.core.pipeline import pipeline


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    # Startup
    await init_db()
    await pipeline.initialize()
    yield
    # Shutdown (nothing special needed)


app = FastAPI(
    title="Universal Log Pre-processing Framework",
    description="SIH26156 — Heterogeneous log preprocessing with adaptive parsing, "
                "cryptographic provenance, and self-healing parser registry.",
    version="1.0.0-prototype",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routers
from backend.api.events import router as events_router
from backend.api.parsers import router as parsers_router
from backend.api.quarantine import router as quarantine_router
from backend.api.integrity import router as integrity_router
from backend.api.metrics import router as metrics_router
from backend.api.demo import router as demo_router
from backend.api.benchmark_api import router as benchmark_router
from backend.api.onboarding import router as onboarding_router

app.include_router(events_router)
app.include_router(parsers_router)
app.include_router(quarantine_router)
app.include_router(integrity_router)
app.include_router(metrics_router)
app.include_router(demo_router)
app.include_router(benchmark_router)
app.include_router(onboarding_router)


@app.get("/")
async def root():
    return {
        "name": "Universal Log Pre-processing Framework",
        "version": "1.0.0-prototype",
        "organization": "NTRO — SIH26156",
        "principle": "AI PROPOSES. TRUST GATE DECIDES. LEDGER PROVES.",
    }
