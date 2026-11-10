"""Arranque de moderation-service con mTLS obligatorio + autorización por identidad.

Equivale a:
    uvicorn app.main:app --host 0.0.0.0 --port 8443 \
        --ssl-keyfile $TLS_KEY --ssl-certfile $TLS_CERT \
        --ssl-ca-certs $TLS_CA --ssl-cert-reqs 2        # 2 = ssl.CERT_REQUIRED
más un control que uvicorn no trae: además de exigir un certificado firmado por la
CA del proyecto, solo acepta clientes cuya identidad (SAN DNS o CN) esté en
ALLOWED_CLIENTS. Otro servicio con un certificado válido de la misma CA no entra.
"""

import logging
import os
import ssl

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

log = logging.getLogger("uvicorn.error")  # mismo handler que los logs de uvicorn

ALLOWED_CLIENTS = frozenset(
    name.strip() for name in os.environ.get("ALLOWED_CLIENTS", "comments-service").split(",") if name.strip()
)


def client_identities(peercert: dict | None) -> set[str]:
    """Nombres del certificado del cliente: SAN de tipo DNS y, si no hay SAN, el CN."""
    if not peercert:
        return set()
    sans = {value for kind, value in peercert.get("subjectAltName", ()) if kind == "DNS"}
    if sans:
        return sans
    return {value for rdn in peercert.get("subject", ()) for key, value in rdn if key == "commonName"}


def is_authorized(peercert: dict | None, allowed: frozenset[str] = ALLOWED_CLIENTS) -> bool:
    return bool(client_identities(peercert) & allowed)


class AuthorizedH11Protocol(H11Protocol):
    """connection_made se llama cuando el handshake TLS ya terminó: el certificado
    del cliente ya fue verificado contra la CA y se puede leer acá."""

    _authorized = False

    def connection_made(self, transport):  # type: ignore[override]
        peercert = transport.get_extra_info("peercert")
        if not is_authorized(peercert):
            log.warning("mTLS: cliente no autorizado %s", sorted(client_identities(peercert)) or "(sin certificado)")
            transport.abort()
            return
        self._authorized = True
        super().connection_made(transport)

    def connection_lost(self, exc):  # type: ignore[override]
        if self._authorized:  # una conexión rechazada nunca llegó a registrarse
            super().connection_lost(exc)


def main() -> None:
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",  # nosec B104 - solo red interna de Docker, sin ports publicados
        port=int(os.environ.get("PORT", "8443")),
        http=AuthorizedH11Protocol,
        ssl_keyfile=os.environ["TLS_KEY"],
        ssl_certfile=os.environ["TLS_CERT"],
        ssl_ca_certs=os.environ["TLS_CA"],
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
