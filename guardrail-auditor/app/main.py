"""FastAPI entrypoint."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import engine
from app.models import Base
from app.routes import rules as rules_routes
from app.routes import scans as scans_routes


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="Guardrail Auditor", version="0.1.0", lifespan=lifespan)
app.include_router(scans_routes.router, prefix="/scans", tags=["scans"])
app.include_router(rules_routes.router, prefix="/rules", tags=["rules"])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
