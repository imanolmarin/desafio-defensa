"""moderation-service: el request se valida con schema estricto aunque llegue por mTLS."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.server import client_identities, is_authorized

client = TestClient(app)
OK = {"comment_id": 12, "author": "alice", "body": "texto"}


def test_aprueba_texto_normal():
    r = client.post("/moderate", json=OK)
    assert r.status_code == 200
    assert r.json() == {"status": "approved", "reason": "ok"}


@pytest.mark.parametrize("body", ["esto es SPAM", "una estafa total", "Ganá en el casino"])
def test_rechaza_palabras_prohibidas(body):
    r = client.post("/moderate", json={**OK, "body": body}).json()
    assert r["status"] == "rejected"


def test_rechaza_demasiados_links():
    body = "https://a.example https://b.example http://c.example"
    assert client.post("/moderate", json={**OK, "body": body}).json()["status"] == "rejected"


def test_dos_links_esta_bien():
    body = "https://a.example y https://b.example"
    assert client.post("/moderate", json={**OK, "body": body}).json()["status"] == "approved"


@pytest.mark.parametrize(
    "payload",
    [
        {**OK, "is_admin": True},  # campo extra
        {**OK, "comment_id": "12"},  # tipo incorrecto (strict)
        {**OK, "comment_id": 0},
        {**OK, "comment_id": True},
        {**OK, "author": 123},
        {**OK, "author": "<script>"},
        {**OK, "body": ""},
        {**OK, "body": "x" * 2001},  # longitud excesiva
        {"comment_id": 1, "author": "alice"},  # falta body
        [OK],
    ],
)
def test_request_invalido_422(payload):
    assert client.post("/moderate", json=payload).status_code == 422


def test_sin_docs_expuestos():
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


# ── Autorización por identidad (bonus) ──────────────────────────────────────

def _cert(cn, sans=()):
    cert = {"subject": ((("commonName", cn),),)}
    if sans:
        cert["subjectAltName"] = tuple(("DNS", s) for s in sans)
    return cert


def test_identidad_por_san():
    assert is_authorized(_cert("x", ["comments-service"]))
    assert client_identities(_cert("x", ["comments-service"])) == {"comments-service"}


def test_identidad_por_cn_si_no_hay_san():
    assert is_authorized(_cert("comments-service"))


@pytest.mark.parametrize(
    "cert",
    [None, {}, _cert("otro-servicio"), _cert("comments-service", ["intruso"]), _cert("comments-service-evil")],
)
def test_identidad_no_autorizada(cert):
    assert not is_authorized(cert)
