"""Validated configuration for the active delivery phase."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator


def utc(value: datetime) -> datetime:
    """Normalize a timestamp to UTC; naive fixture timestamps are interpreted as UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class RegistryConfig(BaseModel):
    """Registry identification without credentials."""

    type: str = "acr"
    name: str = Field(min_length=1)
    resource_group: str | None = None


class LLMConfig(BaseModel):
    """Provider settings contain environment variable names, never secret values."""

    provider: str = "openai"
    model: str = "fixture"
    api_key_env: str = "LLM_API_KEY"
    base_url: str | None = None
    api_version: str | None = None
    temperature: float = 0
    fallback: list[dict[str, Any]] = Field(default_factory=list)


class Config(BaseModel):
    """Phase 1 settings; future-phase fields are retained without validation."""

    model_config = ConfigDict(extra="allow", allow_inf_nan=False)
    registry: RegistryConfig
    stale_days: float = Field(default=90, ge=0)
    max_high: StrictInt = Field(default=5, ge=0)
    keep_last_n: StrictInt = Field(default=3, ge=0)
    protected_tags: list[str] = Field(default_factory=lambda: ["latest", "prod", "release*"])
    untagged_days: float = Field(default=7, ge=0)
    scan_max_age_days: float = Field(default=7, ge=0)
    dry_run: StrictBool = True
    approval_ttl_hours: float = Field(default=72, ge=0)
    grace_period_hours: float = Field(default=72, ge=0)
    usage_sources: dict[str, Any] = Field(default_factory=dict)
    log_analytics_workspace_id: str | None = None
    pull_logs_enabled_on: datetime | None = None
    audit_path: Path = Path("./out/audit.jsonl")
    report_dir: Path = Path("./out/reports")
    state_path: Path = Path("./out/state.sqlite")
    llm: LLMConfig = Field(default_factory=LLMConfig)

    @field_validator("pull_logs_enabled_on")
    @classmethod
    def normalize_date(cls, value: datetime | None) -> datetime | None:
        """Keep stored configuration timestamps UTC."""
        return utc(value) if value else None

    @field_validator(
        "stale_days",
        "untagged_days",
        "scan_max_age_days",
        "approval_ttl_hours",
        "grace_period_hours",
        mode="before",
    )
    @classmethod
    def reject_boolean_duration(cls, value: Any) -> Any:
        """Booleans are not durations."""
        if isinstance(value, bool):
            raise ValueError("duration must be a number")
        return value


def load_config(path: Path = Path("./config.yaml")) -> Config:
    """Load a YAML mapping and validate active configuration fields."""
    data = yaml.safe_load(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("config must be a YAML mapping")
    return Config.model_validate(data)
