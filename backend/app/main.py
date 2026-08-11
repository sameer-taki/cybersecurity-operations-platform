from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from app.deps import tenant_session
from app.event_contract import event_json_schema
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    totp_code: str | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    yield


app = FastAPI(title="Fiji & Pacific Cyber Operations Platform", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/events/schema")
async def event_schema() -> dict[str, object]:
    return event_json_schema()


@app.get("/api/v1/tenant-context")
async def tenant_context(
    _session_and_principal: tuple[object, object] = Depends(tenant_session),
) -> dict[str, str]:
    return {"status": "tenant-scoped"}


@app.post("/api/v1/auth/login")
async def login(_request: LoginRequest) -> dict[str, str]:
    raise HTTPException(status_code=501, detail="authentication service wiring is pending migration integration")
