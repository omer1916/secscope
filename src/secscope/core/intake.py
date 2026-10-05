"""Project intake: copy or extract the user's project into the scan's work dir (SPEC §6.1).

* The user's original files are never modified: everything happens on copies.
* ``work/<scan>/src`` is a read-only copy used by static analysis.
* ``work/<scan>/run`` is a writable copy the target app runs in, created only when needed.
* Symbolic links are never followed or copied (a link to ``~/.ssh`` must not be scanned
  or served); they are listed in the intake report instead.
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from secscope.core.archive import ExtractLimits, UnsafeArchiveError, is_archive, safe_extract
from secscope.core.fingerprint import DEPENDENCY_DIRS


class IntakeError(ValueError):
    pass


@dataclass
class IntakeReport:
    root: Path  # project root inside the src copy
    files: int = 0
    bytes: int = 0
    skipped_links: list[str] = field(default_factory=list[str])


def _on_rm_error(func: Callable[..., object], path: str, _exc: BaseException) -> None:
    # Read-only files (our own src copy) cannot be deleted on Windows until made writable.
    Path(path).chmod(stat.S_IWRITE | stat.S_IREAD)
    func(path)


def remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, onexc=_on_rm_error)


def make_read_only(root: Path) -> None:
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            p.chmod(stat.S_IREAD | (p.stat().st_mode & 0o555))


def _copy_folder(source: Path, dest: Path, limits: ExtractLimits, report: IntakeReport) -> None:
    dest.mkdir(parents=True)
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        current = Path(dirpath)
        rel_dir = current.relative_to(source)
        keep: list[str] = []
        for d in dirnames:
            if (current / d).is_symlink() or _is_junction(current / d):
                report.skipped_links.append((rel_dir / d).as_posix())
            else:
                keep.append(d)
                (dest / rel_dir / d).mkdir()
        dirnames[:] = keep
        for name in filenames:
            src_file = current / name
            rel = (rel_dir / name).as_posix()
            if src_file.is_symlink():
                report.skipped_links.append(rel)
                continue
            if not src_file.is_file():
                continue  # sockets, devices
            report.files += 1
            if report.files > limits.max_files:
                raise IntakeError(f"project has more than {limits.max_files} files")
            size = src_file.stat().st_size
            report.bytes += size
            if report.bytes > limits.max_total_bytes:
                raise IntakeError(f"project is larger than {limits.max_total_bytes} bytes")
            shutil.copy2(src_file, dest / rel_dir / name, follow_symlinks=False)


def _is_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction()) if is_junction is not None else False


def _single_top_dir(root: Path) -> Path:
    """Archives often wrap the project in one folder (``myapp-main/``); use it as root."""
    entries = [p for p in root.iterdir() if p.name not in {"__MACOSX", ".DS_Store"}]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return root


def prepare_source(
    target: Path, work_dir: Path, limits: ExtractLimits | None = None
) -> IntakeReport:
    """Create ``work_dir/src`` from a folder or archive and return the project root in it."""
    limits = limits or ExtractLimits()
    dest = work_dir / "src"
    if dest.exists():
        raise IntakeError(f"{dest} already exists")
    if target.is_dir():
        report = IntakeReport(root=dest)
        try:
            _copy_folder(target.resolve(), dest, limits, report)
        except BaseException:
            remove_tree(dest)
            raise
    elif target.is_file() and is_archive(target):
        try:
            result = safe_extract(target, dest, limits)
        except UnsafeArchiveError as exc:
            raise IntakeError(f"unsafe archive rejected: {exc}") from exc
        report = IntakeReport(root=_single_top_dir(dest), files=result.files, bytes=result.bytes)
    else:
        raise IntakeError(f"not a folder or supported archive: {target}")
    make_read_only(dest)
    return report


def make_run_copy(project_root: Path, work_dir: Path) -> Path:
    """A writable copy of the project for running the target (``work_dir/run``)."""
    run_dir = work_dir / "run"
    if run_dir.exists():
        return run_dir
    shutil.copytree(project_root, run_dir, symlinks=False, copy_function=shutil.copy2)
    for dirpath, _dirs, files in os.walk(run_dir):
        for name in files:
            p = Path(dirpath) / name
            p.chmod(p.stat().st_mode | stat.S_IWRITE)
    return run_dir


def iter_source_files(root: Path, *, include_dependencies: bool = False) -> Iterator[Path]:
    """Project files for static analysis, skipping dependency/VCS/build folders by default."""
    for dirpath, dirnames, filenames in os.walk(root):
        if not include_dependencies:
            dirnames[:] = sorted(d for d in dirnames if d not in DEPENDENCY_DIRS)
        else:
            dirnames.sort()
        for name in sorted(filenames):
            yield Path(dirpath) / name
