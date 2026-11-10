"""Acceso a SQLite. El código seguro usa solo consultas parametrizadas."""

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "app.db"

SCHEMA = """
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS comments;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL DEFAULT '',
    is_admin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT NOT NULL,
    body TEXT NOT NULL,
    -- Etapa 2: solo los 'approved' se publican. Las rutas /vuln insertan sin
    -- pasar por moderación (quedan 'approved' por defecto, a propósito).
    status TEXT NOT NULL DEFAULT 'approved' CHECK (status IN ('pending', 'approved', 'rejected')),
    moderation_reason TEXT
);
"""

# Datos de demo: el hash no es una credencial real.
SEED = """
INSERT INTO users (username, email, password_hash, is_admin)
    VALUES ('admin', 'admin@example.test', 'pbkdf2_sha256$demo$FAKEHASH', 1);
INSERT INTO users (username, email, password_hash, is_admin)
    VALUES ('alice', 'alice@example.test', 'pbkdf2_sha256$demo$ALICEHASH', 0);
INSERT INTO comments (author, body) VALUES ('alice', 'Hello <b>world</b>!');
"""


def db_path() -> str:
    return os.environ.get("DB_PATH", str(DEFAULT_DB_PATH))


@contextmanager
def get_conn():
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA + SEED)
