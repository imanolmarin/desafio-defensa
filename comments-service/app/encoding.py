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


# Caracteres con los que una planilla (Excel, LibreOffice, Google Sheets) interpreta
# la celda como fórmula. Tab y CR se incluyen porque algunas planillas los descartan
# al importar y la celda termina empezando con el carácter siguiente.
FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def spreadsheet_cell(value: str) -> str:
    """Celda de planilla (CSV que se abre en Excel): neutraliza fórmulas (CWE-1236).

    Antepone una comilla simple, que la planilla toma como "esto es texto". Solo
    resuelve el contexto fórmula; comas, comillas y saltos de línea son el contexto
    estructura del CSV y los resuelve csv.writer.
    """
    if value.startswith(FORMULA_TRIGGERS):
        return "'" + value
    return value


def all_contexts(value: str) -> dict[str, str]:
    return {
        "raw": value,
        "html": html(value),
        "js_string": js_string(value),
        "url_component": url_component(value),
        "log": log_value(value),
        "spreadsheet_cell": spreadsheet_cell(value),
    }
