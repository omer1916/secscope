from __future__ import annotations

import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secscope.core.archive import (
    ExtractLimits,
    UnsafeArchiveError,
    safe_extract,
    safe_member_path,
)


def make_zip(path: Path, entries: dict[str, bytes], *, symlink: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink is not None:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    return path


def make_tar(path: Path, members: list[tarfile.TarInfo], data: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for m in members:
            payload = data.get(m.name)
            tf.addfile(m, io.BytesIO(payload) if payload is not None else None)
    return path


def test_extracts_normal_zip(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "ok.zip", {"app/main.py": b"print(1)", "README.md": b"hi"})
    report = safe_extract(archive, tmp_path / "out")
    assert report.files == 2
    assert (tmp_path / "out" / "app" / "main.py").read_bytes() == b"print(1)"


def test_extracts_normal_tar(tmp_path: Path) -> None:
    info = tarfile.TarInfo("pkg/index.html")
    info.size = 5
    archive = make_tar(tmp_path / "ok.tar.gz", [info], {"pkg/index.html": b"hello"})
    safe_extract(archive, tmp_path / "out")
    assert (tmp_path / "out" / "pkg" / "index.html").read_text() == "hello"


@pytest.mark.parametrize(
    "name",
    [
        "../evil.txt",
        "a/../../evil.txt",
        "..\\evil.txt",
        "/etc/passwd",
        "\\\\server\\share\\x",
        "C:/Windows/evil.dll",
        "c:evil.txt",
        "ok/file.txt:stream",
        "CON",
        "dir/nul.txt",
        "trailing. ",
    ],
)
def test_zip_slip_and_hostile_names_rejected(tmp_path: Path, name: str) -> None:
    archive = make_zip(tmp_path / "bad.zip", {"fine.txt": b"x", name: b"pwned"})
    with pytest.raises(UnsafeArchiveError):
        safe_extract(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()  # partial output removed
    assert not (tmp_path / "evil.txt").exists()


@pytest.mark.parametrize("name", ["bad\x00name", "tab\tname", "", "./", "a/./../b"])
def test_member_name_validation(name: str) -> None:
    # zipfile truncates names at NUL when writing, so test the validator directly.
    with pytest.raises(UnsafeArchiveError):
        safe_member_path(name)


def test_zip_symlink_rejected(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "link.zip", {"a.txt": b"x"}, symlink="link")
    with pytest.raises(UnsafeArchiveError, match="special"):
        safe_extract(archive, tmp_path / "out")


@pytest.mark.parametrize(
    "kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE]
)
def test_tar_links_and_devices_rejected(tmp_path: Path, kind: bytes) -> None:
    info = tarfile.TarInfo("thing")
    info.type = kind
    info.linkname = "/etc/passwd"
    archive = make_tar(tmp_path / "bad.tgz", [info], {})
    with pytest.raises(UnsafeArchiveError):
        safe_extract(archive, tmp_path / "out")


def test_zip_bomb_ratio_rejected(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "bomb.zip", {"zeros.bin": b"\0" * (20 * 1024 * 1024)})
    with pytest.raises(UnsafeArchiveError, match="ratio"):
        safe_extract(archive, tmp_path / "out")


def test_total_size_limit(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "big.zip", {"r.bin": os.urandom(300_000)})
    with pytest.raises(UnsafeArchiveError, match="size"):
        safe_extract(archive, tmp_path / "out", ExtractLimits(max_total_bytes=100_000))


def test_file_count_limit(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "many.zip", {f"f{i}.txt": b"x" for i in range(20)})
    with pytest.raises(UnsafeArchiveError, match="files"):
        safe_extract(archive, tmp_path / "out", ExtractLimits(max_files=10))


def test_lying_header_size_enforced_on_written_bytes(tmp_path: Path) -> None:
    """Even if declared sizes are small, actual bytes are counted."""
    archive = make_zip(tmp_path / "x.zip", {"a.bin": os.urandom(50_000)})
    with pytest.raises(UnsafeArchiveError):
        safe_extract(archive, tmp_path / "out", ExtractLimits(max_total_bytes=10_000))


def test_duplicate_entries_rejected(tmp_path: Path) -> None:
    path = tmp_path / "dup.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"1")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zf.writestr("a.txt", b"2")
    with pytest.raises(UnsafeArchiveError, match="duplicate"):
        safe_extract(path, tmp_path / "out")


def test_not_an_archive(tmp_path: Path) -> None:
    path = tmp_path / "x.zip"
    path.write_bytes(b"not a zip")
    with pytest.raises(UnsafeArchiveError):
        safe_extract(path, tmp_path / "out")


def test_destination_must_be_empty(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "ok.zip", {"a": b"1"})
    out = tmp_path / "out"
    out.mkdir()
    (out / "existing").write_text("x")
    with pytest.raises(ValueError, match="not empty"):
        safe_extract(archive, out)


@settings(max_examples=300)
@given(st.text(min_size=1, max_size=40))
def test_member_path_never_escapes(name: str) -> None:
    try:
        rel = safe_member_path(name)
    except UnsafeArchiveError:
        return
    assert not rel.is_absolute()
    assert ".." not in rel.parts
    assert all(":" not in p and "\\" not in p for p in rel.parts)
