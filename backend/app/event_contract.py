import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

type Severity = Literal["low", "medium", "high", "critical"]
type Outcome = Literal["success", "failure", "unknown"]


class Source(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: str
    vendor: str
    product: str
    asset_id: str | None = None


class Actor(BaseModel):
    model_config = ConfigDict(extra="allow")
    user_id: str | None = None
    username: str | None = None
    ip: str | None = None


class Target(BaseModel):
    model_config = ConfigDict(extra="allow")
    asset_id: str | None = None
    hostname: str | None = None
    ip: str | None = None


class ProcessingStep(BaseModel):
    stage: str
    version: str
    status: str
    at: datetime


class CommonEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: str
    tenant_id: UUID
    observed_at: datetime
    ingested_at: datetime
    source: Source
    actor: Actor
    target: Target
    event_type: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    action: str | None = None
    outcome: Outcome
    raw_event_ref: str
    parser_name: str
    parser_version: str
    raw_event_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retention_class: str = "security_event"
    retention_until: datetime | None = None
    legal_hold: bool = False
    processing_history: list[ProcessingStep] = Field(default_factory=list)

    @field_validator("observed_at", "ingested_at", "retention_until")
    @classmethod
    def require_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamps must include timezone")
        return value.astimezone(UTC) if value is not None else None


def canonical_raw_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def dedup_key(
    tenant_id: UUID,
    connector_id: str,
    raw: bytes,
    source_event_id: str | None,
    observed_at: datetime,
) -> str:
    if source_event_id:
        return f"{tenant_id}:{connector_id}:{source_event_id}"
    bucket = observed_at.astimezone(UTC).replace(second=0, microsecond=0).isoformat()
    digest = canonical_raw_hash(raw)
    return f"{tenant_id}:{connector_id}:{digest}:{bucket}"


_URI = re.compile(r"^object://raw/([^/]+)/(\d{4})/(\d{2})/(\d{2})/([^/]+)$")


def raw_object_uri(tenant_id: UUID, observed_at: datetime, event_id: str) -> str:
    value = observed_at.astimezone(UTC)
    return f"object://raw/{tenant_id}/{value:%Y/%m/%d}/{event_id}"


def validate_raw_object_uri(uri: str, tenant_id: UUID) -> bool:
    match = _URI.fullmatch(uri)
    return match is not None and match.group(1) == str(tenant_id)


def event_json_schema() -> dict[str, object]:
    return CommonEvent.model_json_schema()


def canonical_json(value: CommonEvent) -> bytes:
    return json.dumps(value.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
