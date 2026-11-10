"""Bonus: handle_comment_event valida los eventos de la cola como cualquier entrada externa."""

import json

import pytest

from app.events import MAX_EVENT_BYTES, InvalidEvent, handle_comment_event

VALID = {
    "event_type": "comment.created",
    "event_id": "3f2b8c1e-9d4a-4e6b-8a1f-0c5d7e9b2a14",
    "schema_version": 1,
    "comment": {"author": "alice", "body": "hola <b>mundo</b>"},
}


def _raw(obj):
    return json.dumps(obj).encode()


def _with(**changes):
    event = json.loads(json.dumps(VALID))
    for path, value in changes.items():
        target = event
        *parents, leaf = path.split("__")
        for p in parents:
            target = target[p]
        target[leaf] = value
    return event


def test_evento_valido():
    event = handle_comment_event(_raw(VALID))
    assert event.comment.author == "alice"


@pytest.mark.parametrize(
    "event",
    [
        _with(is_admin=True),  # campo extra arriba
        _with(comment__is_admin=True),  # campo extra adentro
        _with(schema_version="1"),  # tipo incorrecto: strict, no se coerciona
        _with(schema_version=2),  # versión de contrato desconocida
        _with(event_type="comment.deleted"),
        _with(event_id="no-es-un-uuid"),
        _with(comment__author=123),
        _with(comment__author="<script>"),
        _with(comment__body="x" * 2001),
        _with(comment__body="   "),
        _with(comment__body="linea\x00nula"),
        {k: v for k, v in VALID.items() if k != "comment"},  # falta un campo
    ],
)
def test_evento_invalido_se_rechaza(event):
    with pytest.raises(InvalidEvent):
        handle_comment_event(_raw(event))


@pytest.mark.parametrize(
    "raw",
    [b"", b"no es json", b"[1, 2, 3]", b"\xff\xfe\x00", b"{" * 10, b'{"event_type": "comment.created",}'],
)
def test_bytes_invalidos_se_rechazan(raw):
    with pytest.raises(InvalidEvent):
        handle_comment_event(raw)


def test_evento_demasiado_grande():
    raw = _raw(_with(comment__body="a" * 100)) + b" " * MAX_EVENT_BYTES
    with pytest.raises(InvalidEvent):
        handle_comment_event(raw)


def test_no_acepta_str():
    with pytest.raises(InvalidEvent):
        handle_comment_event(json.dumps(VALID))
