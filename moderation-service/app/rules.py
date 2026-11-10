"""Reglas de moderación. Simples a propósito: el foco del desafío es el canal y la validación."""

import re

BANNED_WORDS = ("spam", "estafa", "casino", "phishing")
MAX_LINKS = 2
_LINK = re.compile(r"https?://", re.IGNORECASE)
_WORD = re.compile(r"[a-záéíóúñü]+", re.IGNORECASE)


def moderate(body: str) -> tuple[str, str]:
    words = {w.lower() for w in _WORD.findall(body)}
    banned = sorted(words.intersection(BANNED_WORDS))
    if banned:
        return "rejected", f"contiene palabras no permitidas: {', '.join(banned)}"
    links = len(_LINK.findall(body))
    if links > MAX_LINKS:
        return "rejected", f"demasiados links ({links}, máximo {MAX_LINKS})"
    return "approved", "ok"
