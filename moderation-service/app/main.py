from fastapi import FastAPI

from .rules import moderate
from .schemas import ModerationRequest, ModerationVerdict

app = FastAPI(title="moderation-service", docs_url=None, redoc_url=None, openapi_url=None)


@app.post("/moderate", response_model=ModerationVerdict)
def moderate_comment(request: ModerationRequest) -> ModerationVerdict:
    # mTLS ya autenticó al cliente; igual el body pasa por ModerationRequest (422 si no cumple).
    status, reason = moderate(request.body)
    return ModerationVerdict(status=status, reason=reason)


@app.get("/health")
def health():
    return {"status": "ok"}
