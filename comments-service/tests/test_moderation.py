"""Etapa 2, parte B: comments-service valida la respuesta de moderation y falla cerrado.

Se simula moderation reemplazando moderation_client._post (como test_ssrf hace con
net.http_get): así se prueban respuestas que un moderation sano nunca mandaría.
"""

import ssl

import httpx
import pytest

from app import moderation_client
from app.db import get_conn

pytestmark = pytest.mark.real_moderation


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("MODERATION_URL", "https://moderation-service:8443")


def _respond(monkeypatch, *, status=200, json=None, content=None, exc=None):
    calls = []

    def fake_post(url, payload):
        calls.append((url, payload))
        if exc is not None:
            raise exc
        if content is not None:
            return httpx.Response(status, content=content)
        return httpx.Response(status, json=json)

    monkeypatch.setattr(moderation_client, "_post", fake_post)
    return calls


def _publicados(client):
    return [c["body"] for c in client.get("/secure/comments.json").json()]


def _estado(body):
    with get_conn() as conn:
        row = conn.execute("SELECT status FROM comments WHERE body = ? ORDER BY id DESC", (body,)).fetchone()
    return row["status"] if row else None


def test_aprobado_se_publica(client, monkeypatch):
    calls = _respond(monkeypatch, json={"status": "approved", "reason": "ok"})
    r = client.post("/secure/comments", json={"author": "alice", "body": "aprobado-1"})
    assert r.status_code == 201 and r.json()["status"] == "approved"
    assert "aprobado-1" in _publicados(client)
    # El contrato que se manda a moderation:
    url, payload = calls[0]
    assert url.endswith("/moderate")
    assert set(payload) == {"comment_id", "author", "body"} and payload["body"] == "aprobado-1"


def test_rechazado_no_se_publica_y_reason_es_dato(client, monkeypatch):
    reason = "<img src=x onerror=alert(1)>"
    _respond(monkeypatch, json={"status": "rejected", "reason": reason})
    r = client.post("/secure/comments", json={"author": "alice", "body": "rechazado-1"})
    assert r.status_code == 422
    assert r.headers["content-type"].startswith("application/json")  # nunca HTML
    assert r.json() == {"status": "rejected", "reason": reason}
    assert "rechazado-1" not in _publicados(client)
    assert _estado("rechazado-1") == "rejected"


@pytest.mark.parametrize(
    "respuesta",
    [
        {"status": "approved", "is_admin": True},  # caso de la consigna
        {"status": "approved", "reason": "ok", "is_admin": True},  # campo extra
        {"status": "maybe", "reason": "ok"},  # status desconocido
        {"status": "APPROVED", "reason": "ok"},
        {"status": True, "reason": "ok"},  # tipo incorrecto
        {"status": "approved", "reason": 1},
        {"status": "approved", "reason": "x" * 201},  # reason demasiado largo
        {"status": "approved"},  # falta reason
        ["approved"],
        {},
    ],
)
def test_respuesta_invalida_no_publica(client, monkeypatch, respuesta):
    body = f"invalida-{abs(hash(str(respuesta)))}"
    _respond(monkeypatch, json=respuesta)
    r = client.post("/secure/comments", json={"author": "alice", "body": body})
    assert r.status_code == 503
    assert body not in _publicados(client)
    assert _estado(body) == "pending"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": 500, "json": {"status": "approved", "reason": "ok"}},  # error HTTP aunque el body "apruebe"
        {"status": 200, "content": b"no es json"},
        {"status": 200, "content": b'{"status": "approved", "reason": "' + b"a" * 5000 + b'"}'},
        {"exc": httpx.ReadTimeout("timeout")},  # moderation tarda demasiado
        {"exc": httpx.ConnectError("connection refused")},  # moderation caído
        {"exc": ssl.SSLCertVerificationError("certificate verify failed")},  # servidor con cert ajeno
    ],
    ids=["http-500", "no-json", "respuesta-enorme", "timeout", "caido", "cert-invalido"],
)
def test_moderation_caido_o_roto_no_publica(client, monkeypatch, kwargs):
    body = f"fallo-{kwargs.get('status', '')}-{type(kwargs.get('exc')).__name__}-{len(str(kwargs))}"
    _respond(monkeypatch, **kwargs)
    r = client.post("/secure/comments", json={"author": "alice", "body": body})
    assert r.status_code == 503
    assert r.json()["status"] == "pending"
    assert body not in _publicados(client)


def test_sin_configuracion_falla_cerrado(client, monkeypatch):
    monkeypatch.delenv("MODERATION_URL")
    r = client.post("/secure/comments", json={"author": "alice", "body": "sin-config"})
    assert r.status_code == 503
    assert "sin-config" not in _publicados(client)


def test_pendientes_no_aparecen_en_ninguna_salida(client, monkeypatch):
    _respond(monkeypatch, exc=httpx.ConnectError("down"))
    client.post("/secure/comments", json={"author": "pendiente", "body": "pendiente-secreto"})
    assert "pendiente-secreto" not in client.get("/secure/comments").text
    assert "pendiente-secreto" not in client.get("/secure/comments/export.csv").text
    assert client.get("/secure/comments/search", params={"author": "pendiente"}).json() == []
    sorted_rows = client.get("/secure/comments/sorted", params={"sort": "author"}).json()
    assert "pendiente-secreto" not in [r["body"] for r in sorted_rows]


def test_tls_context_sin_certificados_falla_cerrado(monkeypatch):
    for var in ("MODERATION_CA", "MODERATION_CERT", "MODERATION_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(moderation_client.ModerationUnavailable):
        moderation_client.moderate(1, "alice", "hola")
