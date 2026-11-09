"""Sanitizador HTML para campos de texto enriquecido: allowlist de tags y atributos."""

import nh3

ALLOWED_TAGS = {"b", "i", "em", "strong", "p", "br", "ul", "ol", "li", "a", "code"}
ALLOWED_ATTRIBUTES = {"a": {"href", "title"}}


def sanitize_html(value: str) -> str:
    return nh3.clean(
        value,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes={"https", "mailto"},
        link_rel="noopener noreferrer nofollow",
    )
