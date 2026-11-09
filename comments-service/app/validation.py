"""Helpers de validación de entrada: primero canonicalizar, después validar contra una allowlist.

Todos rechazan la entrada inválida (lanzan ValueError) en lugar de intentar "arreglarla".
"""

import ipaddress
import re
import socket
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

SAFE_FILENAME = re.compile(r"^[A-Za-z0-9_-]{1,64}\.(txt|png|pdf)$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)
ALLOWED_AVATAR_HOSTS = {"avatars.githubusercontent.com", "www.gravatar.com"}


def canonicalize(value):
    """Normaliza Unicode (NFKC) y rechaza caracteres de control salvo salto de línea y tab.

    Si se valida antes de normalizar, caracteres parecidos (homoglyphs) pueden saltear los controles.
    """
    if not isinstance(value, str):
        return value
    value = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(ch) == "Cc" and ch not in "\n\t" for ch in value):
        raise ValueError("control characters are not allowed")
    return value


def safe_path(base_dir: Path, name: str) -> Path:
    """Valida el nombre contra una allowlist y confirma que el path resuelto quede dentro de base_dir."""
    if not SAFE_FILENAME.fullmatch(name):
        raise ValueError("invalid file name")
    base = base_dir.resolve()
    path = (base / name).resolve()
    if not path.is_relative_to(base):
        raise ValueError("path escapes base directory")
    return path


def validate_host(host: str) -> str:
    """Acepta una IP literal o un hostname RFC 1123, nada más."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not HOSTNAME.fullmatch(host):
        raise ValueError("invalid host")
    return host.lower()


def validate_outbound_url(url: str) -> str:
    """Protección contra SSRF: solo https, host en allowlist, puerto por defecto, solo IPs públicas.

    El chequeo de DNS por sí solo es vulnerable a DNS rebinding; en producción conviene además
    fijar la IP resuelta para el request o enrutar el tráfico saliente por un egress proxy.
    """
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise ValueError("only https is allowed")
    if parts.username or parts.password:
        raise ValueError("credentials in URL are not allowed")
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_AVATAR_HOSTS:
        raise ValueError("host not allowed")
    if parts.port not in (None, 443):
        raise ValueError("port not allowed")
    for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP):
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise ValueError("host resolves to a non-public address")
    return url


# Reto 3: destinos internos a los que tiene sentido volver después del login.
REDIRECT_ALLOWED_PREFIXES = ("/app/", "/secure/")
REDIRECT_FALLBACK = "/"


def _redirect_problem(target: str) -> str | None:
    """Devuelve por qué el destino no es seguro, o None si lo es."""
    if len(target) > 2048:
        return "too long"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in target):
        return "control characters"  # tab/CR/LF: los navegadores los descartan y //evil aparece
    if "\\" in target:
        return "backslash"  # muchos navegadores tratan \ como /
    if not target.startswith("/") or target.startswith("//"):
        return "not a same-site relative path"
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return "absolute URL"
    # Una segunda decodificación no debe convertirlo en algo peligroso (%2F%2F, %5C, %2e%2e).
    decoded_path = unquote(parts.path)
    if decoded_path.startswith("//") or "\\" in decoded_path:
        return "encoded host"
    if any(segment in (".", "..") for segment in decoded_path.split("/")):
        return "dot segments"  # /app/../vuln/... saltearía la allowlist de prefijos
    if target != "/" and not target.startswith(REDIRECT_ALLOWED_PREFIXES):
        return "path not in allowlist"
    return None


def safe_redirect_target(target) -> str:
    """Allowlist de redirecciones: path relativo del mismo sitio, con prefijo conocido.

    Falla cerrado: ante cualquier duda devuelve "/" en lugar de un error.
    """
    if not isinstance(target, str) or _redirect_problem(target) is not None:
        return REDIRECT_FALLBACK
    return target
