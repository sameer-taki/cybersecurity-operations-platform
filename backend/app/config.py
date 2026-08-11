from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="", extra="ignore")

    app_env: str = "development"
    database_url: str = Field(alias="DATABASE_URL")
    platform_database_url: str | None = Field(default=None, alias="PLATFORM_DATABASE_URL")
    ddl_database_url: str = Field(alias="DDL_DATABASE_URL")
    jwt_secret: str = Field(alias="JWT_SECRET")
    jwt_issuer: str = Field(default="cyberops", alias="JWT_ISSUER")
    jwt_access_minutes: int = Field(default=10, alias="JWT_ACCESS_MINUTES")
    jwt_refresh_days: int = Field(default=14, alias="JWT_REFRESH_DAYS")
    totp_encryption_key: str = Field(alias="TOTP_ENCRYPTION_KEY")
    external_ai_egress_enabled: bool = Field(default=False, alias="EXTERNAL_AI_EGRESS_ENABLED")
    s3_endpoint: str = Field(alias="S3_ENDPOINT")
    s3_access_key: str = Field(alias="S3_ACCESS_KEY")
    s3_secret_key: str = Field(alias="S3_SECRET_KEY")
    s3_bucket: str = Field(alias="S3_BUCKET")
    redis_url: str = Field(alias="REDIS_URL")


@lru_cache
def get_settings() -> Settings:
    return Settings()
