"""Read-only git facts about the scanned folder: the revision a report describes, and the
files changed since a reference (``--changed-since``). Never writes to the repository."""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from secscope.core.process import run_capture

# Branch, tag, SHA or rev expressions like main~3 / origin/main / HEAD^; never an option.
_SAFE_REF = re.compile(r"^(?!-)[A-Za-z0-9._/~^@{}-]{1,200}$")


class GitError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Revision:
    commit: str
    branch: str | None
    dirty: bool

    def as_dict(self) -> dict[str, object]:
        return {"commit": self.commit, "branch": self.branch, "dirty": self.dirty}


def _git() -> str | None:
    return shutil.which("git")


async def _run(folder: Path, *args: str) -> str | None:
    git = _git()
    if git is None:
        return None
    result = await run_capture([git, "-C", str(folder), *args], timeout=60)
    return result.stdout if result.returncode == 0 else None


async def revision(folder: Path) -> Revision | None:
    """The commit of ``folder`` (None when it is not a git work tree or git is missing)."""
    commit = await _run(folder, "rev-parse", "--verify", "HEAD")
    if commit is None:
        return None
    branch = await _run(folder, "rev-parse", "--abbrev-ref", "HEAD")
    status = await _run(folder, "status", "--porcelain", "--untracked-files=normal", "--", ".")
    name = (branch or "").strip()
    return Revision(
        commit=commit.strip(),
        branch=None if name in {"", "HEAD"} else name,
        dirty=bool(status and status.strip()),
    )


def check_ref(ref: str) -> str:
    if not _SAFE_REF.match(ref):
        raise GitError(f"not a valid git reference: {ref!r}")
    return ref


async def changed_files(folder: Path, ref: str) -> set[str]:
    """Paths (relative to ``folder``, posix) changed since ``ref``: committed, staged,
    unstaged and untracked files. Raises GitError when ``ref`` cannot be resolved."""
    check_ref(ref)
    if _git() is None:
        raise GitError("git is not installed")
    if await _run(folder, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}") is None:
        raise GitError(f"unknown git reference {ref!r} in {folder}")
    diff = await _run(folder, "diff", "--name-only", "--relative", ref, "--")
    untracked = await _run(folder, "ls-files", "--others", "--exclude-standard")
    if diff is None or untracked is None:
        raise GitError(f"could not list changes since {ref!r}")
    return {line.strip() for line in (diff + "\n" + untracked).splitlines() if line.strip()}
