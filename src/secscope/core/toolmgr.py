"""Tool Manager: find external tools, report versions, install pinned binaries (SPEC §2, §13).

Detection order for a tool: the managed copy (``<tools_dir>/<name>/<version>/``,
installed and SHA-256-verified by us) first, then ``PATH``. A tool that is
missing or older than ``min_version`` is *unavailable*; modules that need it
are reported as SKIPPED with the localized install hint — never a crash.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from secscope.core.models import LocalizedStr
from secscope.core.process import decode_output
from secscope.core.resources import data_path

ToolKind = Literal["binary", "pip", "system"]
VERSION_TIMEOUT_S = 20


def platform_key() -> str:
    """e.g. ``windows-amd64``, ``linux-arm64``, ``darwin-arm64``."""
    system = {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        machine, machine
    )
    return f"{system}-{arch}"


def parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", text)[:4])


@dataclass(frozen=True, slots=True)
class Download:
    url: str
    sha256: str
    archive: Literal["zip", "tar.gz", "none"]
    binary: str  # path of the executable inside the archive (POSIX separators)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    kind: ToolKind
    commands: tuple[str, ...]
    version_args: tuple[str, ...]
    version_regex: str
    min_version: str
    install_hint: LocalizedStr
    homepage: str = ""
    version: str | None = None  # pinned version for managed binaries
    downloads: dict[str, Download] = field(default_factory=dict[str, Download])


@dataclass(frozen=True, slots=True)
class Manifest:
    tools: dict[str, ToolSpec]
    download_hosts: frozenset[str]

    @classmethod
    def load(cls, path: Path | None = None) -> Manifest:
        path = path or default_manifest_path()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Manifest:
        if data.get("schema") != 1:
            raise ValueError("unsupported tool manifest schema")
        tools: dict[str, ToolSpec] = {}
        for name, raw in data.get("tools", {}).items():
            downloads = {
                key: Download(
                    url=d["url"],
                    sha256=d["sha256"].lower(),
                    archive=d["archive"],
                    binary=d["binary"],
                )
                for key, d in raw.get("downloads", {}).items()
            }
            tools[name] = ToolSpec(
                name=name,
                kind=raw["kind"],
                commands=tuple(raw["commands"]),
                version_args=tuple(raw["version_args"]),
                version_regex=raw["version_regex"],
                min_version=raw["min_version"],
                install_hint=LocalizedStr.model_validate(raw["install_hint"]),
                homepage=raw.get("homepage", ""),
                version=raw.get("version"),
                downloads=downloads,
            )
        hosts = frozenset(data.get("download_hosts", {}).get("allowed", []))
        return cls(tools=tools, download_hosts=hosts)


def default_manifest_path() -> Path:
    return data_path("tools") / "manifest.toml"


@dataclass(frozen=True, slots=True)
class ToolStatus:
    name: str
    available: bool
    path: Path | None = None
    version: str | None = None
    source: Literal["managed", "path", "none"] = "none"
    problem: str | None = None
    install_hint: LocalizedStr | None = None


VersionRunner = Callable[[Sequence[str]], str]


def run_version_command(argv: Sequence[str]) -> str:
    """Run a version command and return stdout+stderr (java prints to stderr)."""
    out = subprocess.run(  # noqa: S603 - argv comes from our own manifest
        list(argv),
        capture_output=True,
        timeout=VERSION_TIMEOUT_S,
        check=False,
        stdin=subprocess.DEVNULL,
    )
    return decode_output(out.stdout) + "\n" + decode_output(out.stderr)


class ToolManager:
    def __init__(
        self,
        manifest: Manifest,
        tools_dir: Path,
        *,
        version_runner: VersionRunner = run_version_command,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self.manifest = manifest
        self.tools_dir = tools_dir
        self._run = version_runner
        self._which = which
        self._cache: dict[str, ToolStatus] = {}

    def spec(self, name: str) -> ToolSpec:
        try:
            return self.manifest.tools[name]
        except KeyError:
            raise KeyError(f"unknown tool {name!r}; add it to tools/manifest.toml") from None

    def managed_path(self, spec: ToolSpec) -> Path | None:
        download = spec.downloads.get(platform_key())
        if spec.version is None or download is None:
            return None
        return self.tools_dir / spec.name / spec.version / Path(*download.binary.split("/"))

    def status(self, name: str) -> ToolStatus:
        if name not in self._cache:
            self._cache[name] = self._detect(self.spec(name))
        return self._cache[name]

    def statuses(self) -> list[ToolStatus]:
        return [self.status(name) for name in sorted(self.manifest.tools)]

    def refresh(self) -> None:
        self._cache.clear()

    def path(self, name: str) -> Path:
        status = self.status(name)
        if not status.available or status.path is None:
            raise FileNotFoundError(f"{name} is not available: {status.problem}")
        return status.path

    def _detect(self, spec: ToolSpec) -> ToolStatus:
        candidates: list[tuple[Path, Literal["managed", "path"]]] = []
        managed = self.managed_path(spec)
        if managed is not None and managed.exists():
            candidates.append((managed, "managed"))
        for command in spec.commands:
            found = self._which(command)
            if found:
                candidates.append((Path(found), "path"))
        if not candidates:
            return ToolStatus(
                spec.name, False, problem="not installed", install_hint=spec.install_hint
            )
        problems: list[str] = []
        for path, source in candidates:
            try:
                output = self._run([str(path), *spec.version_args])
            except (OSError, subprocess.SubprocessError) as exc:
                problems.append(f"{path}: {exc}")
                continue
            match = re.search(spec.version_regex, output)
            if match is None:
                problems.append(f"{path}: could not read version")
                continue
            version = match.group(1)
            if parse_version(version) < parse_version(spec.min_version):
                problems.append(f"{path}: version {version} < required {spec.min_version}")
                continue
            return ToolStatus(spec.name, True, path, version, source)
        return ToolStatus(
            spec.name, False, problem="; ".join(problems), install_hint=spec.install_hint
        )
