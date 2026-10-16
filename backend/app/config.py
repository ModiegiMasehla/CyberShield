from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_SECRET = "development-only-change-me"


class Settings(BaseSettings):
    database_url: str = "sqlite:///./cybershield.db"
    secret_key: str = DEFAULT_SECRET
    access_token_expire_minutes: int = 60
    environment: str = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173"
    rate_limit_per_minute: int = 60
    login_rate_limit_per_minute: int = 10
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    seed_demo_data: bool | None = None
    auto_create_schema: bool = True
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def should_seed(self) -> bool:
        if self.seed_demo_data is not None:
            return self.seed_demo_data
        return not self.is_production

    @model_validator(mode="after")
    def refuse_weak_secret_in_production(self):
        if self.is_production and (self.secret_key == DEFAULT_SECRET or len(self.secret_key) < 32):
            raise ValueError("SECRET_KEY must be a random value of at least 32 characters in production.")
        return self


settings = Settings()
