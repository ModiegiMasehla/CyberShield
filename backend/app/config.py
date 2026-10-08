from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "sqlite:///./cybershield.db"
    secret_key: str = "development-only-change-me"
    access_token_expire_minutes: int = 60
    environment: str = "development"
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:5173"
    rate_limit_per_minute: int = 60
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
