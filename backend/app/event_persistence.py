from datetime import datetime
from pathlib import Path

from app.event_contract import CommonEvent, canonical_raw_hash, raw_object_uri, validate_raw_object_uri
from app.raw_store import RawObjectStore, observed_at_is_in_window, quarantine_raw_object
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def persist_raw_event(
    session: AsyncSession,
    store: RawObjectStore,
    event: CommonEvent,
    raw: bytes,
    quarantine_root: Path,
    now: datetime | None = None,
) -> bool:
    if event.tenant_id is None:
        raise ValueError("event tenant is required")
    if not validate_raw_object_uri(raw_object_uri(event.tenant_id, event.observed_at, event.event_id), event.tenant_id):
        raise ValueError("invalid raw event identifier")
    digest = canonical_raw_hash(raw)
    if digest != event.raw_event_sha256:
        raise ValueError("raw event hash mismatch")
    existing = await session.execute(
        text(
            "SELECT sha256, object_uri, quarantine_uri, byte_length FROM raw_event_refs "
            "WHERE tenant_id = :tenant AND event_id = :event"
        ),
        {"tenant": event.tenant_id, "event": event.event_id},
    )
    existing_row = existing.mappings().first()
    if existing_row is not None:
        if str(existing_row["sha256"]) != digest or int(existing_row["byte_length"]) != len(raw):
            raise ValueError("raw event reference conflict")
        return existing_row["quarantine_uri"] is not None
    quarantined = not observed_at_is_in_window(event.observed_at, now=now)
    uri: str | None = None
    quarantine_uri: str | None = None
    if quarantined:
        quarantine_path = quarantine_raw_object(quarantine_root, event.tenant_id, event.event_id, raw)
        quarantine_uri = quarantine_path.resolve().as_uri()
    else:
        uri = await store.put(event.tenant_id, event.observed_at, event.event_id, raw)
    await session.execute(
        text(
            "INSERT INTO raw_event_refs "
            "(tenant_id,event_id,object_uri,quarantine_uri,sha256,byte_length,quarantined_at) "
            "VALUES (:tenant,:event,:uri,:quarantine_uri,:sha256,:length,:quarantined_at) "
            "ON CONFLICT (tenant_id,event_id) DO NOTHING"
        ),
        {
            "tenant": event.tenant_id,
            "event": event.event_id,
            "uri": uri,
            "quarantine_uri": quarantine_uri,
            "sha256": digest,
            "length": len(raw),
            "quarantined_at": datetime.now(event.observed_at.tzinfo) if quarantined else None,
        },
    )
    if quarantined:
        return True
    else:
        await session.execute(
            text(
                "INSERT INTO events "
                "(tenant_id,event_id,observed_at,ingested_at,source,actor,target,event_type,severity,"
                "confidence,outcome,raw_event_ref,parser_name,parser_version,raw_event_sha256) "
                "VALUES (:tenant,:event,:observed,:ingested,CAST(:source AS jsonb),CAST(:actor AS jsonb),"
                "CAST(:target AS jsonb),:event_type,:severity,"
                ":confidence,:outcome,:raw_ref,:parser,:version,:sha256)"
            ),
            {
                "tenant": event.tenant_id,
                "event": event.event_id,
                "observed": event.observed_at,
                "ingested": event.ingested_at,
                "source": event.source.model_dump_json(),
                "actor": event.actor.model_dump_json(),
                "target": event.target.model_dump_json(),
                "event_type": event.event_type,
                "severity": event.severity,
                "confidence": event.confidence,
                "outcome": event.outcome,
                "raw_ref": uri,
                "parser": event.parser_name,
                "version": event.parser_version,
                "sha256": digest,
            },
        )
    return quarantined
