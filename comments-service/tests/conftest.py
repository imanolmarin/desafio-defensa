import os

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session", autouse=True)
def _db(tmp_path_factory):
    os.environ["DB_PATH"] = str(tmp_path_factory.mktemp("db") / "test.db")
    from app.db import init_db

    init_db()


@pytest.fixture()
def client():
    from app.main import app

    return TestClient(app)


@pytest.fixture(autouse=True)
def _moderation_approves(monkeypatch, request):
    """Etapa 2: por defecto moderation aprueba (los tests de etapa 1 no dependen de él).
    tests/test_moderation.py reemplaza este comportamiento caso por caso."""
    if request.node.get_closest_marker("real_moderation"):
        return
    from app import moderation_client

    monkeypatch.setattr(
        moderation_client,
        "moderate",
        lambda comment_id, author, body: moderation_client.ModerationVerdict(status="approved", reason="ok"),
    )
