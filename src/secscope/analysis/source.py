"""Source files of the project under analysis: language detection, reading, line mapping."""

from __future__ import annotations

import bisect
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from secscope.core.intake import iter_source_files

MAX_FILE_BYTES = 1_000_000
# Lines longer than this on average mark minified/generated code: regex rules skip it.
MINIFIED_AVG_LINE = 300

EXTENSIONS: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".mts": "javascript", ".cts": "javascript",
    ".vue": "javascript", ".svelte": "javascript",
    ".php": "php", ".phtml": "php", ".inc": "php",
    ".html": "html", ".htm": "html",
    ".j2": "template", ".jinja": "template", ".jinja2": "template", ".ejs": "template",
    ".hbs": "template", ".handlebars": "template", ".twig": "template", ".njk": "template",
    ".mustache": "template", ".erb": "template",
}  # fmt: skip

# Text files worth scanning for secrets even when they are not code.
TEXT_SUFFIXES = frozenset(
    {".env", ".ini", ".cfg", ".conf", ".config", ".toml", ".yaml", ".yml", ".json", ".xml",
     ".properties", ".txt", ".md", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".sql",
     ".tf", ".tfvars", ".gradle", ".rb", ".go", ".java", ".kt", ".cs", ".rs", ".swift",
     ".pem", ".key", ".crt", ".bak", ".old", ".orig", ".save", ".example", ".sample"}
)  # fmt: skip
TEXT_NAMES = frozenset(
    {"dockerfile", "makefile", "procfile", ".htaccess", ".npmrc", ".pypirc", ".netrc",
     ".dockerenv", ".gitconfig", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".git-credentials"}
)  # fmt: skip


def language_of(path: Path) -> str | None:
    lang = EXTENSIONS.get(path.suffix.lower())
    if lang == "html" and any(p in ("templates", "views") for p in path.parts):
        return "template"
    return lang


def is_text_candidate(path: Path) -> bool:
    name = path.name.lower()
    return (
        language_of(path) is not None
        or path.suffix.lower() in TEXT_SUFFIXES
        or name in TEXT_NAMES
        or name.startswith(".env")
        or name.endswith((".env", "~"))
    )


@dataclass
class SourceFile:
    root: Path
    path: Path
    text: str
    language: str | None
    _line_starts: list[int] = field(default_factory=list[int], repr=False)

    @property
    def rel(self) -> str:
        return self.path.relative_to(self.root).as_posix()

    @property
    def minified(self) -> bool:
        lines = self.text.count("\n") + 1
        return len(self.text) / lines > MINIFIED_AVG_LINE

    def line_of(self, offset: int) -> int:
        if not self._line_starts:
            self._line_starts = [0]
            self._line_starts += [i + 1 for i, ch in enumerate(self.text) if ch == "\n"]
        return bisect.bisect_right(self._line_starts, offset)

    def line_text(self, line: int) -> str:
        lines = self.text.splitlines()
        return lines[line - 1] if 0 < line <= len(lines) else ""


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8000]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def iter_project(root: Path, *, include_text: bool = False) -> Iterator[SourceFile]:
    """Readable code files (plus config/text files with include_text); dependency dirs skipped."""
    for path in iter_source_files(root):
        lang = language_of(path)
        if lang is None and not (include_text and is_text_candidate(path)):
            continue
        text = read_text(path)
        if text is not None:
            yield SourceFile(root=root, path=path, text=text, language=lang)
