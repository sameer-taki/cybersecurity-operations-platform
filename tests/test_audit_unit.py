import hashlib
import json
from datetime import UTC, datetime


def test_audit_hash_changes_when_canonical_row_changes() -> None:
    row = {"action": "login", "created_at": datetime.now(UTC).isoformat(), "prev_hash": None}
    first = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    row["action"] = "delete"
    second = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
    assert first != second
