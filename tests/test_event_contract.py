from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.event_contract import CommonEvent, canonical_raw_hash
from pydantic import ValidationError


def test_event_requires_hash_and_timezone() -> None:
    with pytest.raises(ValidationError):
        CommonEvent(
            event_id="evt",
            tenant_id=uuid4(),
            observed_at=datetime.now(),
            ingested_at=datetime.now(UTC),
            source={"type": "syslog", "vendor": "generic", "product": "test"},
            actor={},
            target={},
            event_type="test",
            severity="low",
            confidence=0.5,
            outcome="unknown",
            raw_event_ref="object://raw/a/2026/08/11/evt",
            parser_name="test",
            parser_version="1",
            raw_event_sha256="not-a-hash",
        )
    assert len(canonical_raw_hash(b"event")) == 64
