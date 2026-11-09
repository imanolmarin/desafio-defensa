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
