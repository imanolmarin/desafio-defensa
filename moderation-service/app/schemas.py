"""Contrato de moderation-service. Se valida aunque el que llama tenga un certificado válido."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class StrictModel(BaseModel):
    # extra="forbid": campos desconocidos -> 422. strict: sin coerción ("12" no es 12).
    model_config = ConfigDict(extra="forbid", strict=True)


class ModerationRequest(StrictModel):
    comment_id: Annotated[int, Field(ge=1, le=2**31 - 1)]
    author: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{3,20}$")]
    body: Annotated[str, StringConstraints(min_length=1, max_length=2000)]


class ModerationVerdict(StrictModel):
    status: Literal["approved", "rejected"]
    reason: Annotated[str, StringConstraints(max_length=200)]
