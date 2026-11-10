"""Versiones mitigadas de los endpoints de routes_vuln.py."""

import csv
import io
import subprocess
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import encoding, moderation_client, net
from .db import get_conn
from .logging_conf import log_event
from .paths import FILES_DIR, TEMPLATES_DIR
from .sanitize import sanitize_html
from .schemas import USERNAME_PATTERN, AvatarFetch, CommentIn, LoginIn, UserCreate
from .validation import safe_path, safe_redirect_target, validate_host, validate_outbound_url

router = APIRouter(prefix="/secure", tags=["secure"])
templates = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape(["html"]))


def bad_request(message: str) -> HTTPException:
    # Mensaje genérico: no se devuelve la entrada ni detalles internos.
    return HTTPException(status_code=400, detail=message)


@router.get("/comments/search")
def search_comments(author: Annotated[str, Query(pattern=USERNAME_PATTERN)]):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, author, body FROM comments WHERE author = ? AND status = 'approved'", (author,)
        ).fetchall()
    return [dict(r) for r in rows]


# Reto 1: los "?" solo sirven para VALORES. Columna y dirección son estructura de
# la consulta, así que salen de estas tablas (código nuestro), nunca de la entrada.
SORT_COLUMNS = {"id": "id", "author": "author"}
SORT_DIRECTIONS = {"asc": "ASC", "desc": "DESC"}


@router.get("/comments/sorted")
def sorted_comments(
    sort: Literal["id", "author"] = "id",
    direction: Annotated[str, Query(max_length=4)] = "asc",
):
    order = SORT_DIRECTIONS.get(direction.lower())
    if order is None:
        # Se rechaza antes de tocar la base: sin consulta, sin oráculo.
        raise HTTPException(status_code=422, detail="direction must be asc or desc")
    column = SORT_COLUMNS[sort]
    # id como segundo criterio: orden estable cuando hay autores repetidos.
    sql = f"SELECT id, author, body FROM comments WHERE status = 'approved' ORDER BY {column} {order}, id {order}"  # nosec B608 - fragmentos de allowlist
    with get_conn() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


@router.get("/comments/export.csv")
def export_csv():
    """Reto 2: dos contextos de salida, dos encoders.

    - estructura del CSV (comas, comillas, saltos de línea): csv.writer con QUOTE_ALL;
    - contenido de la celda (fórmulas): encoding.spreadsheet_cell.
    Se codifica al exportar, así también salen neutralizadas las filas guardadas antes.
    """
    with get_conn() as conn:
        rows = conn.execute("SELECT author, body FROM comments WHERE status = 'approved' ORDER BY id").fetchall()
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(["author", "body"])
    for r in rows:
        writer.writerow([encoding.spreadsheet_cell(r["author"]), encoding.spreadsheet_cell(r["body"])])
    return Response(
        buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="comments.csv"'},
    )


@router.get("/comments.json")
def list_comments_json():
    # API JSON: devuelve los datos crudos. Codificar o sanear es responsabilidad de quien los renderiza.
    with get_conn() as conn:
        rows = conn.execute("SELECT id, author, body FROM comments WHERE status = 'approved' ORDER BY id").fetchall()
    return [dict(r) for r in rows]


@router.post("/comments", status_code=201)
def create_comment(payload: CommentIn):
    # Etapa 2: el comentario nace 'pending' y solo se publica con un veredicto válido.
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO comments (author, body, status) VALUES (?, ?, 'pending')", (payload.author, payload.body)
        )
        comment_id = cur.lastrowid

    try:
        verdict = moderation_client.moderate(comment_id, payload.author, payload.body)
    except moderation_client.ModerationUnavailable as exc:
        # Falla cerrado: queda 'pending' (no se publica, no se pierde) y el cliente se entera.
        log_event("moderation_unavailable", comment_id=str(comment_id), error=type(exc.__cause__ or exc).__name__)
        return JSONResponse(
            status_code=503,
            content={"status": "pending", "detail": "moderation unavailable; the comment was not published"},
        )

    with get_conn() as conn:
        conn.execute(
            "UPDATE comments SET status = ?, moderation_reason = ? WHERE id = ?",
            (verdict.status, verdict.reason, comment_id),
        )
    if verdict.status == "rejected":
        # reason viene de otro servicio: dato no confiable. Va en JSON (no en HTML)
        # y el front lo muestra con textContent.
        return JSONResponse(status_code=422, content={"status": "rejected", "reason": verdict.reason})
    return {"status": "approved", "id": comment_id}


@router.get("/comments", response_class=HTMLResponse)
def list_comments(request: Request, filter: Annotated[str, Query(max_length=50)] = ""):
    with get_conn() as conn:
        rows = conn.execute("SELECT author, body FROM comments WHERE status = 'approved' ORDER BY id").fetchall()
    # Se sanitiza en la salida, así también quedan seguras las filas guardadas antes (o por la ruta vulnerable).
    comments = [{"author": r["author"], "body_html": sanitize_html(r["body"])} for r in rows]
    return templates.get_template("secure_comments.html").render(
        comments=comments, filter=filter, nonce=request.state.csp_nonce
    )


@router.post("/users", status_code=201)
def create_user(payload: UserCreate):
    with get_conn() as conn:
        cur = conn.execute("INSERT INTO users (username, email) VALUES (?, ?)", (payload.username, payload.email))
        row = conn.execute("SELECT id, username, email, is_admin FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return dict(row)


@router.get("/files", response_class=PlainTextResponse)
def download(name: Annotated[str, Query(max_length=80)]):
    try:
        path = safe_path(FILES_DIR, name)
    except ValueError:
        raise bad_request("invalid file name")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return path.read_text()


@router.get("/ping")
def ping(host: Annotated[str, Query(max_length=253)]):
    try:
        host = validate_host(host)
    except ValueError:
        raise bad_request("invalid host")
    # Sin shell, argumentos como lista: el host siempre es un único argumento.
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=10)
    return {"output": result.stdout + result.stderr}


@router.post("/avatar")
def fetch_avatar(payload: AvatarFetch):
    try:
        url = validate_outbound_url(payload.url)
    except (ValueError, OSError):
        raise bad_request("url not allowed")
    response = net.http_get(url, follow_redirects=False)
    if not response.headers.get("content-type", "").startswith("image/"):
        raise HTTPException(status_code=415, detail="not an image")
    # Solo se devuelven metadatos, nunca el cuerpo crudo del servicio remoto.
    return {"status": response.status_code, "bytes": len(response.content)}


@router.post("/login")
def login(payload: LoginIn):
    return {"logged": log_event("login_failed", username=payload.username)}


@router.get("/encode")
def encode(value: Annotated[str, Query(max_length=200)]):
    return encoding.all_contexts(value)


@router.get("/redirect")
def redirect_after_login(next: str = "/"):
    # Reto 3: solo paths relativos del mismo sitio y de una allowlist de prefijos.
    # Un destino inválido no da error: se vuelve al inicio (fallar cerrado sin romper el flujo).
    return RedirectResponse(safe_redirect_target(next), status_code=302)
