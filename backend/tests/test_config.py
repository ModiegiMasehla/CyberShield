import pytest
from pydantic import ValidationError

from app.config import Settings


def test_production_rejects_default_secret():
    with pytest.raises(ValidationError):
        Settings(environment="production", secret_key="development-only-change-me")


def test_production_rejects_short_secret():
    with pytest.raises(ValidationError):
        Settings(environment="production", secret_key="short")


def test_production_accepts_strong_secret_and_skips_demo_seed():
    s = Settings(environment="production", secret_key="x" * 40)
    assert s.should_seed is False


def test_development_seeds_by_default():
    assert Settings(environment="development").should_seed is True


def test_empty_environment_values_fall_back_to_defaults(monkeypatch):
    """docker-compose passes unset optional variables as empty strings; they must not break start-up."""
    monkeypatch.setenv("SEED_DEMO_DATA", "")
    monkeypatch.setenv("LOG_LEVEL", "")
    s = Settings()
    assert s.seed_demo_data is None and s.log_level == "INFO"
