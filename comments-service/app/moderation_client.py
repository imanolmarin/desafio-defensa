"""Cliente mTLS hacia moderation-service.

- Verifica el certificado del SERVIDOR contra la CA del proyecto (y su nombre,
  moderation-service), nunca contra las CAs del sistema y nunca con verify=False.
- Se presenta con su propio certificado de CLIENTE (clientAuth).
- La respuesta es entrada no confiable: se valida con un schema estricto.
- Cualquier problema (conexión, TLS, timeout, HTTP != 200, JSON o schema
  inválido) termina en ModerationUnavailable: quien llama falla cerrado.
"""

import os
import ssl
from typing import Annotated, Literal

import httpx
from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

TIMEOUT_SECONDS = 3.0
MAX_RESPONSE_BYTES = 4096


class ModerationUnavailable(Exception):
    """No hay veredicto confiable: el comentario no se publica."""


class ModerationVerdict(BaseModel):
    # Mismo contrato que moderation-service, definido de nuevo de este lado:
    # no confiamos en que el otro servicio cumpla el suyo.
    model_config = ConfigDict(extra="forbid", strict=True)

    status: Literal["approved", "rejected"]
    reason: Annotated[str, StringConstraints(max_length=200)]


def _tls_context() -> ssl.SSLContext:
    ca, cert, key = os.environ.get("MODERATION_CA"), os.environ.get("MODERATION_CERT"), os.environ.get("MODERATION_KEY")
    if not (ca and cert and key):
        raise ModerationUnavailable("mTLS no configurado")
    # create_default_context: CERT_REQUIRED + check_hostname. cafile: SOLO la CA del proyecto.
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context


def _post(url: str, payload: dict) -> httpx.Response:
    """Aislado para que los tests puedan simular respuestas de moderation."""
    with httpx.Client(verify=_tls_context(), timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
        return client.post(url, json=payload)


def moderate(comment_id: int, author: str, body: str) -> ModerationVerdict:
    url = os.environ.get("MODERATION_URL")
    if not url:
        raise ModerationUnavailable("MODERATION_URL no configurada")
    try:
        response = _post(f"{url.rstrip('/')}/moderate", {"comment_id": comment_id, "author": author, "body": body})
    except (httpx.HTTPError, ssl.SSLError, OSError) as exc:
        raise ModerationUnavailable("moderation no responde") from exc
    if response.status_code != 200 or len(response.content) > MAX_RESPONSE_BYTES:
        raise ModerationUnavailable(f"respuesta inesperada ({response.status_code})")
    try:
        return ModerationVerdict.model_validate_json(response.content)
    except ValidationError as exc:
        raise ModerationUnavailable("respuesta de moderation inválida") from exc
