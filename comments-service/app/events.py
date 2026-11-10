"""Bonus "confianza cero entre servicios": eventos que llegan de una cola.

Que un mensaje venga de "adentro" (otro servicio, un broker) no lo vuelve
confiable: el productor puede tener un bug, estar comprometido o ser una
versión vieja con otro contrato. Se valida igual que un request público:
tamaño, encoding, JSON bien formado y schema estricto (sin campos extra, sin
coerción de tipos).
"""

from typing import Annotated, Literal

from pydantic import Field, ValidationError

from .logging_conf import log_event
from .schemas import CommentIn, StrictModel

MAX_EVENT_BYTES = 8 * 1024


class InvalidEvent(ValueError):
    """El evento se descarta. El mensaje es genérico a propósito."""


class CommentCreatedEvent(StrictModel):
    event_type: Literal["comment.created"]
    event_id: Annotated[str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
    schema_version: Literal[1]
    # Mismo schema que el endpoint público: una sola definición de "comentario válido".
    comment: CommentIn


def handle_comment_event(raw: bytes) -> CommentCreatedEvent:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_EVENT_BYTES:
        log_event("event_rejected", reason="size_or_type")
        raise InvalidEvent("invalid event")
    try:
        text = bytes(raw).decode("utf-8")  # strict: bytes inválidos -> UnicodeDecodeError
        event = CommentCreatedEvent.model_validate_json(text)
    except (UnicodeDecodeError, ValidationError) as exc:
        # Se loguea el tipo de error, nunca el contenido del mensaje.
        log_event("event_rejected", reason=type(exc).__name__)
        raise InvalidEvent("invalid event") from None
    return event
