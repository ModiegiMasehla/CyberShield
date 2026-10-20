from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SECRET = "development-only-change-me"
Environment = Literal["development", "test", "staging", "production"]
# Only these two may run with the default secret, demo accounts, API docs and permissive CORS.
LOCAL_ENVIRONMENTS = {"development", "test"}


class Settings(BaseSettings):
    database_url: str = "sqlite:///./cybershield.db"
    secret_key: str = DEFAULT_SECRET
    access_token_expire_minutes: int = 60
    environment: Environment = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173"
    rate_limit_per_minute: int = 60
    login_rate_limit_per_minute: int = 10
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    seed_demo_data: bool | None = None
    auto_create_schema: bool = True
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)

    @field_validator("environment", mode="before")
    @classmethod
    def normalise_environment(cls, value):
        # A typo such as ENVIRONMENT=prod must fail loudly instead of silently behaving like development.
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL.")
        return level

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_local(self) -> bool:
        return self.environment in LOCAL_ENVIRONMENTS

    @property
    def cors_origin_list(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]

    @property
    def should_seed(self) -> bool:
        if self.seed_demo_data is not None:
            return self.seed_demo_data
        return self.is_local

    @model_validator(mode="after")
    def refuse_unsafe_non_local_settings(self):
        if not self.is_local:
            if self.secret_key == DEFAULT_SECRET or len(self.secret_key) < 32:
                raise ValueError(
                    "SECRET_KEY must be a random value of at least 32 characters outside development."
                )
            if "*" in self.cors_origin_list:
                raise ValueError("CORS_ORIGINS must list explicit origins outside development (no '*').")
        return self


settings = Settings()
