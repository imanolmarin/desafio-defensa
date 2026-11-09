"""Encoders de salida contextuales. El encoder correcto depende de dónde cae el valor."""

import json
from urllib.parse import quote

from markupsafe import escape


def html(value: str) -> str:
    """Cuerpo HTML y valores de atributos entre comillas: escapa & < > " '."""
    return str(escape(value))


def js_string(value: str) -> str:
    """Literal string de JS dentro de un bloque <script> (misma idea que |tojson de Jinja)."""
    encoded = json.dumps(value)
    for char, replacement in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("'", "\\u0027")):
        encoded = encoded.replace(char, replacement)
    return encoded


def url_component(value: str) -> str:
    """Un segmento de path o un valor de query string de una URL."""
    return quote(value, safe="")


def log_value(value: str) -> str:
    """Neutraliza CR/LF para que la entrada no pueda falsificar líneas de log."""
    return value.replace("\r", "\\r").replace("\n", "\\n")


def all_contexts(value: str) -> dict[str, str]:
    return {
        "raw": value,
        "html": html(value),
        "js_string": js_string(value),
        "url_component": url_component(value),
        "log": log_value(value),
    }
