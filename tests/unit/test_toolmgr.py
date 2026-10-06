from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from secscope.core.toolmgr import (
    Manifest,
    ToolManager,
    VersionRunner,
    parse_version,
    platform_key,
)


def manifest(**overrides: object) -> Manifest:
    tool: dict[str, object] = {
        "kind": "system",
        "commands": ["fake-tool"],
        "version_args": ["--version"],
        "version_regex": r"fake (\d+\.\d+\.\d+)",
        "min_version": "1.2.0",
        "install_hint": {"tr": "kur", "en": "install"},
    }
    tool.update(overrides)
    return Manifest.from_dict({"schema": 1, "tools": {"fake": tool}})


def runner(output: str) -> VersionRunner:
    def run(_argv: Sequence[str]) -> str:
        return output

    return run


def test_real_manifest_loads() -> None:
    m = Manifest.load()
    assert {"node", "semgrep", "gitleaks"} <= set(m.tools)
    # Only tools a module of this build uses are offered (ADR-009).
    assert not {"java", "nuclei"} & set(m.tools)
    for spec in m.tools.values():
        assert spec.install_hint.tr
        assert spec.install_hint.en


def test_detects_version(tmp_path: Path) -> None:
    mgr = ToolManager(
        manifest(),
        tmp_path,
        version_runner=runner("fake 1.4.2\n"),
        which=lambda _c: "/usr/bin/fake-tool",
    )
    status = mgr.status("fake")
    assert status.available
    assert status.version == "1.4.2"
    assert status.source == "path"


def test_missing_tool(tmp_path: Path) -> None:
    mgr = ToolManager(manifest(), tmp_path, which=lambda _c: None)
    status = mgr.status("fake")
    assert not status.available
    assert status.problem == "not installed"
    assert status.install_hint is not None
    with pytest.raises(FileNotFoundError):
        mgr.path("fake")


def test_too_old(tmp_path: Path) -> None:
    mgr = ToolManager(
        manifest(), tmp_path, version_runner=runner("fake 1.1.9"), which=lambda _c: "/x/fake"
    )
    status = mgr.status("fake")
    assert not status.available
    assert status.problem is not None
    assert "< required 1.2.0" in status.problem


def test_unreadable_version(tmp_path: Path) -> None:
    mgr = ToolManager(manifest(), tmp_path, version_runner=runner("???"), which=lambda _c: "/x/f")
    assert not mgr.status("fake").available


def test_runner_errors_are_reported(tmp_path: Path) -> None:
    def boom(_argv: Sequence[str]) -> str:
        raise OSError("exec format error")

    mgr = ToolManager(manifest(), tmp_path, version_runner=boom, which=lambda _c: "/x/f")
    status = mgr.status("fake")
    assert not status.available
    assert "exec format error" in (status.problem or "")


def test_managed_copy_preferred(tmp_path: Path) -> None:
    m = manifest(
        version="1.5.0",
        downloads={
            platform_key(): {
                "url": "https://github.com/x/y.zip",
                "sha256": "AB" * 32,
                "archive": "zip",
                "binary": "bin/fake-tool",
            }
        },
    )
    binary = tmp_path / "fake" / "1.5.0" / "bin" / "fake-tool"
    binary.parent.mkdir(parents=True)
    binary.write_text("")
    mgr = ToolManager(m, tmp_path, version_runner=runner("fake 1.5.0"), which=lambda _c: "/x/f")
    status = mgr.status("fake")
    assert status.source == "managed"
    assert status.path == binary
    assert m.tools["fake"].downloads[platform_key()].sha256 == "ab" * 32


def test_unknown_tool(tmp_path: Path) -> None:
    with pytest.raises(KeyError, match="manifest"):
        ToolManager(manifest(), tmp_path).status("nope")


def test_bad_schema() -> None:
    with pytest.raises(ValueError, match="schema"):
        Manifest.from_dict({"schema": 99})


@pytest.mark.parametrize(
    ("text", "expected"),
    [("1.2.3", (1, 2, 3)), ("17", (17,)), ("v24.18.0", (24, 18, 0)), ("1.8.0_391", (1, 8, 0, 391))],
)
def test_parse_version(text: str, expected: tuple[int, ...]) -> None:
    assert parse_version(text) == expected


def test_real_detection_smoke(tmp_path: Path) -> None:
    """Python itself is always present; the real runner must work end to end."""
    import sys  # noqa: PLC0415

    m = manifest(
        commands=[sys.executable], version_regex=r"Python (\d+\.\d+\.\d+)", min_version="3.12.0"
    )
    status = ToolManager(m, tmp_path).status("fake")
    assert status.available, status.problem
