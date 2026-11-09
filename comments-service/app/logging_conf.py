"""Logging estructurado (JSON): un evento por línea, la entrada nunca puede cortar la línea."""

import json
import logging

from .encoding import log_value

logger = logging.getLogger("comments")
logging.basicConfig(level=logging.INFO, format="%(message)s")


def log_event(event: str, **fields: str) -> str:
    # json.dumps ya escapa \n; log_value es defensa en profundidad para destinos de texto plano.
    line = json.dumps({"event": event, **{k: log_value(str(v)) for k, v in fields.items()}})
    logger.info(line)
    return line
