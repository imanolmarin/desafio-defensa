import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request

from . import routes_secure, routes_vuln
from .db import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title="Comments service: demo de manejo de entradas", lifespan=lifespan)
app.include_router(routes_vuln.router)
app.include_router(routes_secure.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    if request.url.path.startswith("/secure"):
        response.headers["Content-Security-Policy"] = (
            f"default-src 'none'; script-src 'nonce-{nonce}'; img-src 'self'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/internal/config")
def internal_config():
    # Pensado para ser accesible solo dentro del cluster; el gateway bloquea /internal/.
    # Igual la ruta vulnerable de avatar puede llegar (SSRF).
    return {"db_password": "demo-value-not-a-real-secret", "feature_flags": ["beta"]}
