import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def append_audit(
    session: AsyncSession,
    tenant_id: UUID,
    actor_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    metadata: dict[str, object],
) -> str:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:tenant, 0))"),
        {"tenant": str(tenant_id)},
    )
    previous = await session.execute(
        text(
            "SELECT entry_hash FROM audit_log a WHERE tenant_id = :tenant "
            "AND NOT EXISTS (SELECT 1 FROM audit_log successor "
            "WHERE successor.tenant_id = a.tenant_id AND successor.prev_hash = a.entry_hash) "
            "LIMIT 1"
        ),
        {"tenant": tenant_id},
    )
    prev_hash = previous.scalar_one_or_none()
    created_at = datetime.now(UTC)
    canonical = json.dumps(
        {
            "tenant_id": str(tenant_id),
            "actor_id": str(actor_id) if actor_id else None,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "metadata": metadata,
            "prev_hash": prev_hash,
            "created_at": created_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    entry_hash = hashlib.sha256(canonical.encode()).hexdigest()
    await session.execute(
        text(
            "INSERT INTO audit_log "
            "(id, tenant_id, actor_id, action, resource_type, resource_id, "
            "metadata, prev_hash, entry_hash, created_at) "
            "VALUES (gen_random_uuid(), :tenant, :actor, :action, :resource_type, :resource_id, "
            "CAST(:metadata AS jsonb), :prev_hash, :entry_hash, :created_at)"
        ),
        {
            "tenant": tenant_id,
            "actor": actor_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "metadata": json.dumps(metadata),
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "created_at": created_at,
        },
    )
    return entry_hash


async def verify_audit_chain(session: AsyncSession, tenant_id: UUID) -> bool:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:tenant, 0))"),
        {"tenant": str(tenant_id)},
    )
    rows = await session.execute(
        text(
            "SELECT id, actor_id, action, resource_type, resource_id, metadata, prev_hash, entry_hash, created_at "
            "FROM audit_log WHERE tenant_id = :tenant"
        ),
        {"tenant": tenant_id},
    )
    entries = {str(row[0]): row[1:] for row in rows}
    if not entries:
        return True
    roots = [entry_id for entry_id, row in entries.items() if row[5] is None]
    if len(roots) != 1:
        return False
    current_id = roots[0]
    previous: str | None = None
    visited: set[str] = set()
    while current_id not in visited:
        visited.add(current_id)
        (
            actor_id,
            action,
            resource_type,
            resource_id,
            metadata,
            prev_hash,
            entry_hash,
            created_at,
        ) = entries[current_id]
        if prev_hash != previous:
            return False
        canonical = json.dumps(
            {
                "tenant_id": str(tenant_id),
                "actor_id": str(actor_id) if actor_id else None,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "metadata": metadata,
                "prev_hash": prev_hash,
                "created_at": created_at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if hashlib.sha256(canonical.encode()).hexdigest() != entry_hash:
            return False
        previous = entry_hash
        successors = [entry_id for entry_id, row in entries.items() if row[5] == previous]
        if len(successors) > 1:
            return False
        if not successors:
            break
        current_id = successors[0]
    return len(visited) == len(entries)
