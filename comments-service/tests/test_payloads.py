"""Cada ataque funciona contra /vuln y queda bloqueado o neutralizado por /secure."""

import httpx
import pytest


def test_sql_injection(client):
    payload = "x' UNION SELECT id, username, password_hash FROM users--"
    leaked = client.get("/vuln/comments/search", params={"author": payload}).json()
    assert any("FAKEHASH" in row["body"] for row in leaked)

    assert client.get("/secure/comments/search", params={"author": payload}).status_code == 422
    assert client.get("/secure/comments/search", params={"author": "alice"}).status_code == 200


def test_stored_xss(client):
    client.post("/vuln/comments", json={"author": "<script>alert(1)</script>", "body": "<img src=x onerror=alert(2)>"})

    vuln_html = client.get("/vuln/comments").text
    assert "<script>alert(1)</script>" in vuln_html
    assert "onerror=alert(2)" in vuln_html

    # Mismas filas guardadas, renderizadas por la ruta segura.
    response = client.get("/secure/comments")
    assert "<script>alert(1)" not in response.text
    assert "&lt;script&gt;" in response.text
    assert "onerror" not in response.text
    assert "<b>world</b>" in response.text  # el texto enriquecido permitido sobrevive al sanitizado
    assert "script-src 'nonce-" in response.headers["content-security-policy"]

    rejected = client.post("/secure/comments", json={"author": "<script>", "body": "hi"})
    assert rejected.status_code == 422


def test_js_context_injection(client):
    payload = "';alert(document.cookie);//"
    assert "'';alert(document.cookie);//'" in client.get("/vuln/comments", params={"filter": payload}).text
    secure_html = client.get("/secure/comments", params={"filter": payload}).text
    assert "\\u0027;alert(document.cookie);//" in secure_html


def test_mass_assignment(client):
    body = {"username": "mallory", "email": "m@example.test", "is_admin": 1}
    assert client.post("/vuln/users", json=body).json()["is_admin"] == 1

    assert client.post("/secure/users", json=body).status_code == 422
    body.pop("is_admin")
    assert client.post("/secure/users", json=body).json()["is_admin"] == 0


@pytest.mark.parametrize("name", ["../secret.txt", "..%2Fsecret.txt", "/etc/passwd", "report.txt/../../secret.txt"])
def test_path_traversal_secure(client, name):
    assert client.get("/secure/files", params={"name": name}).status_code == 400


def test_path_traversal(client):
    assert "INTERNAL_SECRET" in client.get("/vuln/files", params={"name": "../secret.txt"}).text
    assert client.get("/secure/files", params={"name": "report.txt"}).status_code == 200


def test_command_injection(client):
    payload = "invalid-host; echo PWNED"
    assert "PWNED" in client.get("/vuln/ping", params={"host": payload}).json()["output"]
    assert client.get("/secure/ping", params={"host": payload}).status_code == 400


def test_ssrf(client, monkeypatch):
    from app import net

    calls = []

    def fake_get(url, follow_redirects=False):
        calls.append(url)
        return httpx.Response(200, json={"db_password": "demo-value-not-a-real-secret"})

    monkeypatch.setattr(net, "http_get", fake_get)

    internal = "http://127.0.0.1:8000/internal/config"
    assert "db_password" in client.post("/vuln/avatar", json={"url": internal}).json()["content"]

    calls.clear()
    for url in [
        internal,
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/",
        "https://evil.example/avatar.png",
        "https://user:pass@www.gravatar.com/avatar",
        "https://www.gravatar.com:8443/avatar",
        "file:///etc/passwd",
    ]:
        assert client.post("/secure/avatar", json={"url": url}).status_code == 400, url
    assert calls == []


def test_log_injection(client):
    payload = "bob\n2026-10-30 INFO login succeeded for user admin"
    assert "\n" in client.post("/vuln/login", json={"username": payload}).json()["logged"]
    assert "\n" not in client.post("/secure/login", json={"username": payload}).json()["logged"]


def test_encoders(client):
    out = client.get("/secure/encode", params={"value": "<a href='x'>&\"</a>"}).json()
    assert out["html"] == "&lt;a href=&#39;x&#39;&gt;&amp;&#34;&lt;/a&gt;"
    assert "<" not in out["js_string"] and "'" not in out["js_string"]
    assert out["url_component"] == "%3Ca%20href%3D%27x%27%3E%26%22%3C%2Fa%3E"


def test_comments_json_returns_raw_data(client):
    response = client.get("/secure/comments.json")
    assert response.headers["content-type"] == "application/json"
    assert any(c["body"] == "Hello <b>world</b>!" for c in response.json())


def test_internal_endpoint_exists(client):
    # Accesible dentro del servicio; es el gateway el que lo bloquea desde afuera.
    assert client.get("/internal/config").status_code == 200
