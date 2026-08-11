from datetime import datetime
from pathlib import Path
from typing import Protocol
from uuid import UUID

from app.event_contract import raw_object_uri, validate_raw_object_uri


class RawObjectStore(Protocol):
    async def put(self, tenant_id: UUID, observed_at: datetime, event_id: str, content: bytes) -> str: ...

    async def get(self, tenant_id: UUID, uri: str) -> bytes: ...


class LocalRawObjectStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    async def put(self, tenant_id: UUID, observed_at: datetime, event_id: str, content: bytes) -> str:
        uri = raw_object_uri(tenant_id, observed_at, event_id)
        path = self.root / str(tenant_id) / observed_at.strftime("%Y/%m/%d") / event_id
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return uri

    async def get(self, tenant_id: UUID, uri: str) -> bytes:
        if not validate_raw_object_uri(uri, tenant_id):
            raise PermissionError("raw object tenant mismatch")
        parts = uri.removeprefix("object://raw/").split("/")
        path = self.root.joinpath(*parts)
        return path.read_bytes()
