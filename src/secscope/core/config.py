"""Application settings and per-scan configuration."""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

import platformdirs
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secscope.__about__ import __app_id__
from secscope.core.models import Language

SETTINGS_FILE = "settings.json"

# The only ranges the advanced "my LAN" option may ever add (RFC 1918, RFC 4193).
LAN_RANGES: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


def default_data_dir() -> Path:
    return Path(platformdirs.user_data_dir(__app_id__, appauthor=False))


def default_config_dir() -> Path:
    return Path(platformdirs.user_config_dir(__app_id__, appauthor=False))


def default_log_dir() -> Path:
    return Path(platformdirs.user_log_dir(__app_id__, appauthor=False))


class ScoreWeights(_Model):
    """Weights of the overall score (SPEC §9). Must sum to 1."""

    security: float = Field(default=0.45, ge=0, le=1)
    seo: float = Field(default=0.20, ge=0, le=1)
    resilience: float = Field(default=0.20, ge=0, le=1)
    quality: float = Field(default=0.10, ge=0, le=1)
    dependencies: float = Field(default=0.05, ge=0, le=1)

    @model_validator(mode="after")
    def _sum_to_one(self) -> Self:
        total = self.security + self.seo + self.resilience + self.quality + self.dependencies
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"score weights must sum to 1.0, got {total:.4f}")
        return self


class Slo(_Model):
    p95_ms: float = Field(default=500, gt=0)
    error_rate: float = Field(default=0.01, ge=0, le=1)


class RateLimits(_Model):
    dast_rps: float = Field(default=20, gt=0, le=1000)
    # Slow down automatically once this fraction of responses are 5xx (SPEC §6.3).
    circuit_breaker_5xx_ratio: float = Field(default=0.20, gt=0, le=1)


class Retention(_Model):
    days: int = Field(default=90, ge=1)
    max_scans: int = Field(default=50, ge=1)


class Settings(_Model):
    """Persistent user settings (Settings screen, SPEC §11.2.6)."""

    language: Language = "tr"
    theme: Literal["system", "dark", "light"] = "system"
    data_dir: Path = Field(default_factory=default_data_dir)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    slo: Slo = Field(default_factory=Slo)
    weights: ScoreWeights = Field(default_factory=ScoreWeights)
    retention: Retention = Field(default_factory=Retention)
    # Advanced, off by default: private LAN ranges the user owns (SPEC §4.2).
    # Enabling requires a double confirmation in the UI; public ranges are rejected.
    allowed_lan_networks: list[str] = Field(default_factory=list[str])

    @field_validator("allowed_lan_networks")
    @classmethod
    def _private_only(cls, v: list[str]) -> list[str]:
        for item in v:
            net = ipaddress.ip_network(item, strict=True)
            if not any(net.subnet_of(lan) for lan in LAN_RANGES if lan.version == net.version):  # pyright: ignore[reportArgumentType]
                raise ValueError(f"{item} is not inside a private LAN range")
        return v

    @classmethod
    def load(cls, config_dir: Path | None = None) -> Settings:
        path = (config_dir or default_config_dir()) / SETTINGS_FILE
        if not path.exists():
            return cls()
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, config_dir: Path | None = None) -> Path:
        directory = config_dir or default_config_dir()
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / SETTINGS_FILE
        # Atomic replace so a crash never leaves a half-written settings file.
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".settings-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.model_dump(mode="json"), fh, indent=2, ensure_ascii=False)
            Path(tmp).replace(path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return path


class ScanProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    CUSTOM = "custom"


class TargetKind(StrEnum):
    FOLDER = "folder"
    ARCHIVE = "archive"
    URL = "url"


class Target(_Model):
    kind: TargetKind
    # Folder/archive path, or a loopback URL for an already running app.
    value: str


class RunConfig(_Model):
    """How to start the target app (editable in the wizard, SPEC §6.1)."""

    # None = use the detected command (fingerprint). Placeholders: {port} {host} {python}.
    command: list[str] | None = None
    # Install dependencies first (npm ci / pip install -r ...). Runs the project's own
    # install scripts and needs network access to package registries.
    install: bool = False
    install_command: list[str] | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    workdir: str | None = None
    env: dict[str, str] = Field(default_factory=dict[str, str])
    ready_path: str = "/"
    startup_timeout_s: float = Field(default=60, gt=0, le=600)


class ScanConfig(_Model):
    """Everything a single scan needs; produced by the wizard or the CLI."""

    target: Target
    profile: ScanProfile = ScanProfile.STANDARD
    modules: list[str] = Field(default_factory=list[str])
    run: RunConfig = Field(default_factory=RunConfig)
    # SPEC §4.5: dynamic modules refuse to run unless this is true.
    scope_statement_accepted: bool = False
    snapshot_sqlite: bool = True
