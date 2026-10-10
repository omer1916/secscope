"""What a scan looked at, and what it set aside and why (report "Coverage" section).

A clean result must say what was examined: user exclusions, dependency folders, symbolic
links and test/fixture code are all accounted for here instead of disappearing silently.
"""

from __future__ import annotations

import fnmatch
import os
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

# Folders whose code is tests, fixtures, mocks or examples rather than the application.
BACKGROUND_DIRS: dict[str, str] = {
    "test": "test",
    "tests": "test",
    "__tests__": "test",
    "spec": "test",
    "specs": "test",
    "e2e": "test",
    "cypress": "test",
    "fixture": "fixture",
    "fixtures": "fixture",
    "testdata": "fixture",
    "test-data": "fixture",
    "__mocks__": "fixture",
    "mocks": "fixture",
    "example": "example",
    "examples": "example",
}
BACKGROUND_FILES: tuple[tuple[str, str], ...] = (
    ("test_*.py", "test"),
    ("*_test.py", "test"),
    ("conftest.py", "test"),
    ("*_test.go", "test"),
    ("*.test.[jt]s", "test"),
    ("*.test.[jt]sx", "test"),
    ("*.spec.[jt]s", "test"),
    ("*.spec.[jt]sx", "test"),
    ("*Test.php", "test"),
    ("*.min.js", "generated"),
)
MAX_LISTED = 50
# Tool caches and VCS metadata: skipped too, but not worth listing in the report.
QUIET_DIRS = frozenset(
    {
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".cache",
    }
)


def normalise_pattern(pattern: str) -> str:
    return pattern.strip().replace("\\", "/").strip("/")


def matches_exclude(rel: str, patterns: Sequence[str]) -> bool:
    """gitignore-like: ``tests`` matches that name at any depth, ``docs/*.md`` matches from
    the project root, ``build/`` (trailing slash) matches the folder and everything in it."""
    name = PurePosixPath(rel).name
    for raw in patterns:
        p = normalise_pattern(raw)
        if not p:
            continue
        if "/" not in p:
            if fnmatch.fnmatchcase(name, p) or any(
                fnmatch.fnmatchcase(part, p) for part in PurePosixPath(rel).parts[:-1]
            ):
                return True
        elif fnmatch.fnmatchcase(rel, p) or rel.startswith(p + "/"):
            return True
    return False


def background_reason(rel: str) -> str | None:
    """ "test", "fixture", "example" or "generated" for non-application code, else None."""
    path = PurePosixPath(rel)
    for part in path.parts[:-1]:
        reason = BACKGROUND_DIRS.get(part.lower())
        if reason is not None:
            return reason
    for pattern, reason in BACKGROUND_FILES:
        if fnmatch.fnmatchcase(path.name, pattern):
            return reason
    return None


def build_coverage(
    root: Path,
    *,
    files: int,
    total_bytes: int,
    excluded: Iterable[str] = (),
    exclude_patterns: Sequence[str] = (),
    skipped_links: Iterable[str] = (),
    dependency_dirs: Iterable[str] = (),
) -> dict[str, Any]:
    from secscope.analysis.source import language_of  # noqa: PLC0415 - avoid import cycle

    languages: Counter[str] = Counter()
    background: Counter[str] = Counter()
    # Dependency dirs are not in the copied tree (intake skips them); the list comes from the
    # intake report. Tool caches / VCS metadata are not worth listing.
    deps = sorted(d for d in dependency_dirs if PurePosixPath(d).name not in QUIET_DIRS)
    for dirpath, _dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        for name in filenames:
            path = here / name
            lang = language_of(path)
            if lang is None:
                continue
            languages[lang] += 1
            reason = background_reason(path.relative_to(root).as_posix())
            if reason is not None:
                background[reason] += 1
    excluded_list = sorted(excluded)
    links = sorted(skipped_links)
    return {
        "files": files,
        "bytes": total_bytes,
        "code_files_by_language": dict(languages.most_common()),
        "background_files": dict(background),
        "exclude_patterns": [normalise_pattern(p) for p in exclude_patterns if p.strip()],
        "excluded_count": len(excluded_list),
        "excluded": excluded_list[:MAX_LISTED],
        "dependency_dirs": deps[:MAX_LISTED],
        "skipped_links": links[:MAX_LISTED],
    }
