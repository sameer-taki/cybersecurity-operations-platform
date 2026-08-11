from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from app.raw_store import LocalRawObjectStore


@pytest.mark.asyncio
async def test_raw_store_round_trip_and_tenant_boundary(tmp_path: Path) -> None:
    tenant = uuid4()
    other = uuid4()
    store = LocalRawObjectStore(tmp_path)
    uri = await store.put(tenant, datetime(2026, 8, 11, tzinfo=UTC), "evt", b"raw")
    assert await store.get(tenant, uri) == b"raw"
    with pytest.raises(PermissionError):
        await store.get(other, uri)
