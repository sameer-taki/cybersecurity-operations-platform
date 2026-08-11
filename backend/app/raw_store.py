import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
from uuid import UUID

import boto3
from app.config import get_settings
from app.event_contract import raw_object_uri, validate_raw_object_uri
from botocore.exceptions import ClientError


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


class S3RawObjectStore:
    def __init__(
        self,
        endpoint: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        bucket: str | None = None,
    ) -> None:
        settings = get_settings()
        self.bucket = bucket or settings.s3_bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint or settings.s3_endpoint,
            aws_access_key_id=access_key or settings.s3_access_key,
            aws_secret_access_key=secret_key or settings.s3_secret_key,
        )

    async def put(self, tenant_id: UUID, observed_at: datetime, event_id: str, content: bytes) -> str:
        uri = raw_object_uri(tenant_id, observed_at, event_id)
        key = uri.removeprefix("object://raw/")

        def upload() -> None:
            try:
                self.client.head_bucket(Bucket=self.bucket)
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") not in {"404", "NoSuchBucket"}:
                    raise
                self.client.create_bucket(Bucket=self.bucket)
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content,
                ContentType="application/octet-stream",
                Metadata={"sha256": hashlib.sha256(content).hexdigest()},
            )

        await asyncio.to_thread(upload)
        return uri

    async def get(self, tenant_id: UUID, uri: str) -> bytes:
        if not validate_raw_object_uri(uri, tenant_id):
            raise PermissionError("raw object tenant mismatch")
        key = uri.removeprefix("object://raw/")
        response = await asyncio.to_thread(self.client.get_object, Bucket=self.bucket, Key=key)
        body = response["Body"]
        return await asyncio.to_thread(body.read)


def observed_at_is_in_window(
    observed_at: datetime,
    now: datetime | None = None,
    back_window: timedelta = timedelta(days=62),
    forward_window: timedelta = timedelta(days=124),
) -> bool:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    value = observed_at.astimezone(UTC)
    return current - back_window <= value <= current + forward_window


def quarantine_raw_object(root: Path, tenant_id: UUID, event_id: str, content: bytes) -> Path:
    path = root / "quarantine" / str(tenant_id) / event_id
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path
