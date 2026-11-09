"""DTOs estrictos de entrada. extra="forbid" rechaza campos desconocidos (bloquea mass assignment)."""

from typing import Annotated

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints

from .validation import canonicalize

USERNAME_PATTERN = r"^[a-z0-9_]{3,20}$"

Username = Annotated[
    str,
    BeforeValidator(canonicalize),
    StringConstraints(strip_whitespace=True, pattern=USERNAME_PATTERN),
]
Email = Annotated[
    str,
    BeforeValidator(canonicalize),
    StringConstraints(strip_whitespace=True, to_lower=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$"),
]


def _not_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CommentIn(StrictModel):
    author: Username
    # Acá se permite texto enriquecido; se sanitiza en la salida (ver sanitize.py).
    body: Annotated[str, BeforeValidator(canonicalize), Field(max_length=2000), AfterValidator(_not_blank)]


class UserCreate(StrictModel):
    username: Username
    email: Email
    # No hay campo is_admin: el privilegio nunca se toma del input del cliente.


class AvatarFetch(StrictModel):
    url: Annotated[str, Field(max_length=2048)]


class LoginIn(StrictModel):
    # Validación laxa a propósito: muestra que el encoder de logs igual neutraliza CR/LF.
    username: Annotated[str, Field(max_length=64)]
