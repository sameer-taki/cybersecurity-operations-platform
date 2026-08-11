from datetime import datetime
from pathlib import Path

from app.event_contract import CommonEvent, canonical_raw_hash
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
    digest = canonical_raw_hash(raw)
    if digest != event.raw_event_sha256:
        raise ValueError("raw event hash mismatch")
    uri = await store.put(event.tenant_id, event.observed_at, event.event_id, raw)
    await session.execute(
        text(
            "INSERT INTO raw_event_refs "
            "(tenant_id,event_id,object_uri,sha256,byte_length,legal_hold) "
            "VALUES (:tenant,:event,:uri,:sha256,:length,:hold) "
            "ON CONFLICT (tenant_id,event_id) DO UPDATE SET object_uri = EXCLUDED.object_uri, "
            "sha256 = EXCLUDED.sha256, byte_length = EXCLUDED.byte_length"
        ),
        {
            "tenant": event.tenant_id,
            "event": event.event_id,
            "uri": uri,
            "sha256": digest,
            "length": len(raw),
            "hold": not observed_at_is_in_window(event.observed_at, now=now),
        },
    )
    quarantined = not observed_at_is_in_window(event.observed_at, now=now)
    if quarantined:
        quarantine_raw_object(quarantine_root, event.tenant_id, event.event_id, raw)
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
