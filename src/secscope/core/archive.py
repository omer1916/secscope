"""Safe extraction of untrusted .zip / .tar(.gz|.bz2|.xz) archives (SPEC §6.1).

Rejected outright (the whole archive, not just the entry):
absolute paths, drive letters, ``..`` components, NUL/control characters,
Windows-reserved names and alternate data streams, symlinks, hard links,
device/FIFO entries, and archives exceeding the size, file-count or
compression-ratio limits. Sizes are enforced on the bytes actually written,
because headers can lie.
"""

from __future__ import annotations

import re
import shutil
import stat
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO

CHUNK = 1024 * 1024
_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class UnsafeArchiveError(ValueError):
    """The archive is malicious or exceeds limits; nothing should be trusted."""


@dataclass(frozen=True, slots=True)
class ExtractLimits:
    max_total_bytes: int = 2 * 1024**3
    max_files: int = 200_000
    max_ratio: float = 100.0
    # Ratio checks only make sense once an entry is big enough to matter.
    ratio_min_bytes: int = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ExtractReport:
    files: int
    bytes: int


def is_archive(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(
        (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
    )


def safe_member_path(name: str) -> PurePosixPath:
    """Validate an archive member name and return it as a relative POSIX path."""
    if not name or _CONTROL.search(name):
        raise UnsafeArchiveError(f"illegal characters in entry name: {name!r}")
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or re.match(r"^[A-Za-z]:", normalised):
        raise UnsafeArchiveError(f"absolute path in archive: {name!r}")
    parts = [p for p in normalised.split("/") if p not in ("", ".")]
    if not parts:
        raise UnsafeArchiveError(f"empty entry name: {name!r}")
    for part in parts:
        if part == "..":
            raise UnsafeArchiveError(f"path traversal in archive: {name!r}")
        if ":" in part:
            raise UnsafeArchiveError(f"drive or alternate data stream in entry: {name!r}")
        if _WINDOWS_RESERVED.match(part) or part.endswith((" ", ".")):
            raise UnsafeArchiveError(f"name not portable to Windows: {name!r}")
    return PurePosixPath(*parts)


class _Budget:
    def __init__(self, limits: ExtractLimits, archive_size: int) -> None:
        self.limits = limits
        self.archive_size = max(archive_size, 1)
        self.files = 0
        self.bytes = 0

    def add_file(self) -> None:
        self.files += 1
        if self.files > self.limits.max_files:
            raise UnsafeArchiveError(f"more than {self.limits.max_files} files")

    def add_bytes(self, n: int) -> None:
        self.bytes += n
        if self.bytes > self.limits.max_total_bytes:
            raise UnsafeArchiveError(f"extracted size exceeds {self.limits.max_total_bytes} bytes")
        if (
            self.bytes >= self.limits.ratio_min_bytes
            and self.bytes / self.archive_size > self.limits.max_ratio
        ):
            raise UnsafeArchiveError(f"compression ratio above 1:{self.limits.max_ratio:g}")


def _copy_limited(src: IO[bytes], dst: IO[bytes], budget: _Budget) -> None:
    while chunk := src.read(CHUNK):
        budget.add_bytes(len(chunk))
        dst.write(chunk)


def _target(dest: Path, rel: PurePosixPath) -> Path:
    target = dest.joinpath(*rel.parts)
    resolved = target.resolve()
    if not resolved.is_relative_to(dest.resolve()):
        raise UnsafeArchiveError(f"entry escapes destination: {rel}")
    return target


def _zip_entries(zf: zipfile.ZipFile) -> Iterator[tuple[zipfile.ZipInfo, PurePosixPath]]:
    for info in zf.infolist():
        rel = safe_member_path(info.filename)
        mode = info.external_attr >> 16
        if mode and (
            stat.S_ISLNK(mode)
            or stat.S_ISCHR(mode)
            or stat.S_ISBLK(mode)
            or stat.S_ISFIFO(mode)
            or stat.S_ISSOCK(mode)
        ):
            raise UnsafeArchiveError(f"special file (symlink/device) in archive: {info.filename!r}")
        if info.flag_bits & 0x1:
            raise UnsafeArchiveError(f"encrypted entry: {info.filename!r}")
        yield info, rel


def _extract_zip(archive: Path, dest: Path, budget: _Budget) -> None:
    with zipfile.ZipFile(archive) as zf:
        entries = list(_zip_entries(zf))  # validate everything before writing anything
        declared = sum(i.file_size for i, _ in entries)
        if declared > budget.limits.max_total_bytes:
            raise UnsafeArchiveError("declared uncompressed size exceeds limit")
        for info, rel in entries:
            budget.add_file()
            target = _target(dest, rel)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("xb") as dst:
                _copy_limited(src, dst, budget)


def _extract_tar(archive: Path, dest: Path, budget: _Budget) -> None:
    with tarfile.open(archive, mode="r:*") as tf:
        members = tf.getmembers()
        checked: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        for member in members:
            rel = safe_member_path(member.name)
            if not (member.isfile() or member.isdir()):
                raise UnsafeArchiveError(f"special file (link/device) in archive: {member.name!r}")
            checked.append((member, rel))
        for member, rel in checked:
            budget.add_file()
            target = _target(dest, rel)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                raise UnsafeArchiveError(f"unreadable entry: {member.name!r}")
            with src, target.open("xb") as dst:
                _copy_limited(src, dst, budget)


def safe_extract(archive: Path, dest: Path, limits: ExtractLimits | None = None) -> ExtractReport:
    """Extract ``archive`` into the (new or empty) directory ``dest``.

    On any violation the partially extracted directory is removed and
    :class:`UnsafeArchiveError` is raised.
    """
    limits = limits or ExtractLimits()
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise ValueError(f"destination is not empty: {dest}")
    budget = _Budget(limits, archive.stat().st_size)
    try:
        if zipfile.is_zipfile(archive):
            _extract_zip(archive, dest, budget)
        elif tarfile.is_tarfile(archive):
            _extract_tar(archive, dest, budget)
        else:
            raise UnsafeArchiveError(f"unsupported archive format: {archive.name}")
    except (UnsafeArchiveError, zipfile.BadZipFile, tarfile.TarError, FileExistsError) as exc:
        shutil.rmtree(dest, ignore_errors=True)
        if isinstance(exc, UnsafeArchiveError):
            raise
        if isinstance(exc, FileExistsError):
            raise UnsafeArchiveError(f"duplicate entry in archive: {exc.filename}") from exc
        raise UnsafeArchiveError(f"corrupt archive: {exc}") from exc
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return ExtractReport(files=budget.files, bytes=budget.bytes)
