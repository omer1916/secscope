from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from secscope.core.config import ScanConfig, ScoreWeights, Settings, Target, TargetKind


def test_default_weights() -> None:
    w = ScoreWeights()
    assert (w.security, w.seo, w.resilience, w.quality, w.dependencies) == (
        0.45,
        0.2,
        0.2,
        0.1,
        0.05,
    )


def test_weights_must_sum_to_one() -> None:
    with pytest.raises(ValidationError):
        ScoreWeights(security=0.9)


@pytest.mark.parametrize("net", ["192.168.1.0/24", "10.0.0.0/8", "172.16.5.0/24", "fd00::/64"])
def test_lan_ranges_accepted(net: str) -> None:
    assert Settings(allowed_lan_networks=[net]).allowed_lan_networks == [net]


@pytest.mark.parametrize(
    "net",
    [
        "0.0.0.0/0",
        "8.8.8.0/24",
        "127.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "::/0",
        "192.168.1.5/24",  # host bits set
    ],
)
def test_lan_ranges_rejected(net: str) -> None:
    with pytest.raises(ValidationError):
        Settings(allowed_lan_networks=[net])


def test_settings_roundtrip_in_path_with_spaces(tmp_path: Path) -> None:
    directory = tmp_path / "dir with spaces ü"
    settings = Settings(language="en", data_dir=tmp_path / "data")
    path = settings.save(directory)
    assert Settings.load(directory) == settings
    assert list(directory.iterdir()) == [path]  # no temp files left behind


def test_settings_missing_file_gives_defaults(tmp_path: Path) -> None:
    assert Settings.load(tmp_path).language == "tr"


def test_scope_statement_defaults_to_false() -> None:
    cfg = ScanConfig(target=Target(kind=TargetKind.URL, value="http://localhost:3000"))
    assert cfg.scope_statement_accepted is False
