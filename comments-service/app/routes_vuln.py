"""Endpoints VULNERABLES A PROPÓSITO. Solo para demos locales en clase."""

import logging
import os
import subprocess

from fastapi import APIRouter, Body
from fastapi.responses import HTMLResponse, PlainTextResponse
from jinja2 import Environment, FileSystemLoader

from . import net
from .db import get_conn
from .paths import FILES_DIR, TEMPLATES_DIR

router = APIRouter(prefix="/vuln", tags=["vulnerable"])
templates = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=False)
logger = logging.getLogger("comments")


@router.get("/comments/search")
def search_comments(author: str):
    # SQL injection: la entrada se concatena en la consulta.
    with get_conn() as conn:
        rows = conn.execute(f"SELECT id, author, body FROM comments WHERE author = '{author}'").fetchall()
    return [dict(r) for r in rows]


@router.post("/comments", status_code=201)
def create_comment(payload: dict = Body(...)):
    # Sin validación: se guarda cualquier cosa.
    with get_conn() as conn:
        conn.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (payload.get("author"), payload.get("body")))
    return {"status": "created"}


@router.get("/comments", response_class=HTMLResponse)
def list_comments(filter: str = ""):
    # XSS almacenado (sin autoescape) e inyección en contexto JS vía ?filter=.
    with get_conn() as conn:
        rows = conn.execute("SELECT author, body FROM comments ORDER BY id").fetchall()
    return templates.get_template("vuln_comments.html").render(comments=rows, filter=filter)


@router.post("/users", status_code=201)
def create_user(payload: dict = Body(...)):
    # Mass assignment: cada clave enviada por el cliente se vuelve una columna (incluida is_admin).
    columns = ", ".join(payload)
    placeholders = ", ".join("?" for _ in payload)
    with get_conn() as conn:
        cur = conn.execute(f"INSERT INTO users ({columns}) VALUES ({placeholders})", tuple(payload.values()))
        row = conn.execute("SELECT id, username, email, is_admin FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


@router.get("/files", response_class=PlainTextResponse)
def download(name: str):
    # Path traversal: ../ o un path absoluto escapan de FILES_DIR.
    with open(os.path.join(FILES_DIR, name)) as f:
        return f.read()


@router.get("/ping")
def ping(host: str):
    # Command injection: shell=True con la entrada interpolada.
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=10)
    return {"output": result.stdout + result.stderr}


@router.post("/avatar")
def fetch_avatar(payload: dict = Body(...)):
    # SSRF: pide cualquier URL, sigue redirects y devuelve el cuerpo.
    response = net.http_get(payload["url"], follow_redirects=True)
    return {"status": response.status_code, "content": response.text[:500]}


@router.post("/login")
def login(payload: dict = Body(...)):
    # Log injection: la entrada cruda se escribe en una línea de log de texto plano.
    line = f"login failed for user {payload['username']}"
    logger.info(line)
    return {"logged": line}
