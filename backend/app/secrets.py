import os
from typing import Protocol


class SecretProvider(Protocol):
    def get(self, secret_ref: str) -> str: ...


class LocalSecretProvider:
    def get(self, secret_ref: str) -> str:
        value = os.environ.get(secret_ref)
        if value is None:
            raise RuntimeError("secret is not configured")
        return value


class ExternalAIEgressDisabled:
    def request(self, _provider: str, _payload: str) -> str:
        raise RuntimeError("external AI egress is disabled")
