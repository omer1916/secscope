"""Configuration / infrastructure checks (SPEC §6.2 "Yapılandırma / altyapı").

Dockerfile, docker-compose, nginx, .htaccess, GitHub Actions, .gitignore coverage,
shipped source maps and leftover backup files.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from secscope.analysis.regex_rules import suppressed
from secscope.core.intake import iter_source_files
from secscope.core.jsonutil import jdict, jlist
from secscope.core.models import Confidence, Severity

PUBLIC_DIRS = frozenset(
    {"public", "static", "dist", "build", "www", "assets", "out", "_site", "htdocs", "wwwroot"}
)
SECRET_ENV = re.compile(r"(?i)(passw|secret|token|api_?key|private_?key|credential)")
BACKUP_SUFFIXES = (".bak", ".old", ".orig", ".swp", ".swo", ".tmp", "~", ".save", ".backup")


@dataclass(frozen=True, slots=True)
class ConfigIssue:
    rule_id: str
    path: str
    line: int | None
    confidence: Confidence
    snippet: str = ""
    severity: Severity | None = None


def _lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _issue(
    rule_id: str,
    root: Path,
    path: Path,
    line: int | None,
    lines: list[str],
    confidence: Confidence = "high",
    severity: Severity | None = None,
) -> ConfigIssue | None:
    text = lines[line - 1] if line and 0 < line <= len(lines) else ""
    if text and suppressed(text, rule_id):
        return None
    return ConfigIssue(
        rule_id, path.relative_to(root).as_posix(), line, confidence, text.strip(), severity
    )


def _dockerfile(root: Path, path: Path) -> Iterator[ConfigIssue | None]:
    lines = _lines(path)
    instructions = [
        (i + 1, ln.strip())
        for i, ln in enumerate(lines)
        if ln.strip() and not ln.strip().startswith("#")
    ]
    from_lines = [(n, t) for n, t in instructions if t.upper().startswith("FROM ")]
    users = [
        (n, t.split(None, 1)[1].strip() if len(t.split()) > 1 else "")
        for n, t in instructions
        if t.upper().startswith("USER ")
    ]
    if from_lines and (not users or users[-1][1].split(":")[0] in {"root", "0"}):
        yield _issue(
            "CONF-DOCKER-ROOT-001",
            root,
            path,
            (users[-1][0] if users else from_lines[-1][0]),
            lines,
        )
    for n, t in from_lines:
        image = t.split()[1]
        if image.lower() == "scratch" or image.startswith("$") or "@sha256:" in image:
            continue
        name = image.rsplit("/", 1)[-1]
        if ":" not in name or name.endswith(":latest"):
            yield _issue("CONF-DOCKER-LATEST-001", root, path, n, lines)
    for n, t in instructions:
        upper = t.upper()
        if upper.startswith("ADD ") and re.search(r"\bhttps?://", t):
            yield _issue("CONF-DOCKER-ADD-001", root, path, n, lines)
        if upper.startswith(("ENV ", "ARG ")):
            body = t.split(None, 1)[1] if len(t.split()) > 1 else ""
            for key, _sep, value in re.findall(
                r"([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*|\s+)([^\s]+)", body
            ):
                if SECRET_ENV.search(key) and value and not value.startswith("$"):
                    yield _issue("CONF-DOCKER-SECRET-001", root, path, n, lines)
                    break


def _line_of(lines: list[str], needle: str) -> int | None:
    for i, ln in enumerate(lines, start=1):
        if needle in ln:
            return i
    return None


def _compose(root: Path, path: Path) -> Iterator[ConfigIssue | None]:
    lines = _lines(path)
    try:
        data: Any = yaml.safe_load("\n".join(lines)) or {}
    except yaml.YAMLError:
        return
    services = jdict(jdict(data).get("services"))
    all_interfaces = {"0.0.0.0", "", "::"}  # noqa: S104 - detecting, not binding
    for name, raw_svc in services.items():
        svc = jdict(raw_svc)
        if svc.get("privileged") is True or svc.get("network_mode") == "host":
            yield _issue(
                "CONF-COMPOSE-PRIV-001",
                root,
                path,
                _line_of(lines, "privileged") or _line_of(lines, "network_mode"),
                lines,
            )
        for vol in jlist(svc.get("volumes")):
            if isinstance(vol, str) and "docker.sock" in vol:
                yield _issue(
                    "CONF-COMPOSE-PRIV-001", root, path, _line_of(lines, "docker.sock"), lines
                )
        for port in jlist(svc.get("ports")):
            spec = str(port)
            parts = spec.split(":")
            if len(parts) == 2 or (len(parts) == 3 and parts[0] in all_interfaces):
                yield _issue(
                    "CONF-COMPOSE-PORT-001",
                    root,
                    path,
                    _line_of(lines, spec) or _line_of(lines, str(name)),
                    lines,
                    "medium",
                )
                break


def _nginx(root: Path, path: Path) -> Iterator[ConfigIssue | None]:
    lines = _lines(path)
    text = "\n".join(lines)
    if not re.search(r"\b(server|http|location)\s*\{", text):
        return
    n = _line_of(lines, "autoindex on")
    if n:
        yield _issue("CONF-NGINX-AUTOINDEX-001", root, path, n, lines)
    if not re.search(r"^\s*server_tokens\s+off\s*;", text, re.M):
        yield _issue(
            "CONF-NGINX-TOKENS-001", root, path, _line_of(lines, "server {") or 1, lines, "medium"
        )
    wanted = ("x-content-type-options", "content-security-policy", "x-frame-options")
    present = [h for h in wanted if re.search(rf"add_header\s+{h}\b", text, re.I)]
    if len(present) < len(wanted):
        yield _issue(
            "CONF-NGINX-HDR-001", root, path, _line_of(lines, "server {") or 1, lines, "medium"
        )


def _htaccess(root: Path, path: Path) -> Iterator[ConfigIssue | None]:
    lines = _lines(path)
    for i, ln in enumerate(lines, start=1):
        if re.match(r"\s*Options\s+.*(?<![-\w])\+?Indexes\b", ln, re.I) and "-Indexes" not in ln:
            yield _issue("CONF-HTACCESS-INDEXES-001", root, path, i, lines)


# GitHub Actions (threat model: an outside attacker who can open fork PRs, issues and comments
# but cannot push). Check classes follow getsentry/skills "gha-security-review" (Apache-2.0)
# and GitHub Security Lab's "untrusted input" list; the implementation is SecScope's own.

# Triggers an outsider can fire *with* the base repository's token and secrets.
GHA_EXTERNAL_TRIGGERS = frozenset(
    {
        "pull_request_target",
        "issue_comment",
        "issues",
        "discussion",
        "discussion_comment",
        "workflow_run",
    }
)
# Triggers that need write access (or run with a read-only fork token): not an outsider's way in.
GHA_INTERNAL_TRIGGERS = frozenset(
    {"push", "workflow_dispatch", "schedule", "workflow_call", "release", "pull_request",
     "pull_request_review", "pull_request_review_comment", "merge_group", "create", "delete"}
)  # fmt: skip
# Expressions whose value an outsider chooses (titles, bodies, branch names, commit text...).
GHA_UNTRUSTED = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.head_ref"
    r"|github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|pages\.[^.\s}]+)"
    r"\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch|page_name)"
    r"|github\.event\.(?:head_commit|commits\[[^\]]*\]|commits\.\*)\.(?:message|author\.(?:email|name))"
    r"|github\.event\.workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:email|name))"
    r"|pull_requests\[[^\]]*\]\.head\.ref)"
    r")"
)
_SHA_PIN = re.compile(r"@[0-9a-f]{40}$")
_RUN_BLOCK = frozenset({"|", ">", "|-", ">-", "|+", ">+"})


def _yaml(text: str) -> dict[Any, Any] | None:
    try:
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return jdict(data) if isinstance(data, dict) else None


def _triggers(data: dict[Any, Any] | None) -> set[str] | None:
    """Event names of a workflow, or None when unknown. YAML 1.1 reads the key `on` as True."""
    if data is None:
        return None
    on: Any = data.get("on", data.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}  # pyright: ignore[reportUnknownVariableType,reportUnknownArgumentType]
    if isinstance(on, dict):
        return {str(k) for k in on}  # pyright: ignore[reportUnknownVariableType,reportUnknownArgumentType]
    return None


def _jobs(data: dict[Any, Any] | None) -> dict[str, dict[str, Any]]:
    jobs = jdict(data.get("jobs")) if data else {}
    return {str(k): jdict(v) for k, v in jobs.items()}


def _privileged(data: dict[Any, Any], job: dict[str, Any], triggers: set[str] | None) -> bool:
    """Job with something worth stealing: secrets, write/OIDC permissions or an external trigger."""
    text = yaml.safe_dump(job)
    perms = [data.get("permissions"), job.get("permissions")]
    writes = any(
        p == "write-all" or any(str(v) == "write" for v in jdict(p).values()) for p in perms
    )
    return (
        "secrets." in text
        or writes
        or bool(triggers and triggers & {"pull_request_target", "workflow_run", "release"})
    )


def _workflow(root: Path, path: Path) -> Iterator[ConfigIssue | None]:
    lines = _lines(path)
    text = "\n".join(lines)
    data = _yaml(text)
    triggers = _triggers(data)
    external = triggers is None or bool(triggers & GHA_EXTERNAL_TRIGGERS)
    if "pull_request_target" in text and re.search(
        r"github\.event\.pull_request\.head\.(?:sha|ref)|refs/pull/|github\.head_ref", text
    ):
        yield _issue("CONF-CI-PRT-001", root, path, _line_of(lines, "pull_request_target"), lines)

    # 1. Expression injection: only `run:` scripts are injectable (`env:` / `with:` / `if:` are
    #    passed as data), and only in workflows an outsider can trigger.
    if external or (triggers is not None and not triggers <= GHA_INTERNAL_TRIGGERS):
        block_indent: int | None = None
        for i, ln in enumerate(lines, start=1):
            indent = len(ln) - len(ln.lstrip())
            if block_indent is not None and ln.strip() and indent <= block_indent:
                block_indent = None
            run_line = re.match(r"^(\s*)(?:-\s*)?run:\s*(.*)$", ln)
            in_script = block_indent is not None or (
                run_line is not None and run_line.group(2) not in _RUN_BLOCK
            )
            if run_line is not None and run_line.group(2) in _RUN_BLOCK:
                block_indent = indent
            if in_script and GHA_UNTRUSTED.search(ln) and not ln.strip().startswith("#"):
                yield _issue("CONF-CI-INJECT-001", root, path, i, lines)

    if data is None:
        return
    jobs = _jobs(data)

    # 2. Comment-triggered commands without an authorisation check: anyone can comment.
    if triggers and "issue_comment" in triggers:
        guarded = re.search(
            r"author_association|getCollaboratorPermissionLevel|collaborators/.+/permission"
            r"|github\.actor\s*==|permission-level|check-permission",
            text,
        )
        runs_code = any(
            "run" in jdict(step) or "uses" in jdict(step)
            for job in jobs.values()
            for step in jlist(job.get("steps"))
        )
        if runs_code and not guarded:
            yield _issue("CONF-CI-COMMENT-001", root, path, _line_of(lines, "issue_comment"), lines)

    # 3. Token permissions: outsider-triggered workflows must declare least privilege.
    if external and triggers is not None:
        top = data.get("permissions")
        if top == "write-all":
            yield _issue("CONF-CI-PERM-001", root, path, _line_of(lines, "permissions"), lines)
        elif top is None and any("permissions" not in job for job in jobs.values()):
            line = _line_of(lines, "jobs:")
            yield _issue("CONF-CI-PERM-001", root, path, line, lines, confidence="medium")

    # 4. Supply chain: third-party actions in privileged jobs must be pinned to a full SHA.
    #    First-party actions/* and github/* on tags and local ./ actions are fine.
    for job in jobs.values():
        if not _privileged(data, job, triggers):
            continue
        for step in jlist(job.get("steps")):
            uses = str(jdict(step).get("uses") or "")
            owner = uses.split("/", 1)[0].lower()
            if (
                not uses
                or uses.startswith(("./", "docker://"))
                or owner in {"actions", "github"}
                or _SHA_PIN.search(uses)
            ):
                continue
            yield _issue("CONF-CI-PIN-001", root, path, _line_of(lines, uses), lines)


def _gitignore_patterns(root: Path) -> list[str] | None:
    path = root / ".gitignore"
    if not path.is_file():
        return None
    return [ln.strip() for ln in _lines(path) if ln.strip() and not ln.strip().startswith("#")]


def is_ignored(rel: str, patterns: list[str]) -> bool:
    ignored = False
    name = rel.rsplit("/", 1)[-1]
    for raw in patterns:
        negate = raw.startswith("!")
        pat = raw[1:] if negate else raw
        pat = pat.rstrip("/")
        anchored = pat.startswith("/")
        pat = pat.lstrip("/")
        hit = (
            fnmatch.fnmatch(rel, pat)
            or fnmatch.fnmatch(rel, pat + "/*")
            or (not anchored and "/" not in pat and fnmatch.fnmatch(name, pat))
        )
        if not hit and not anchored and "/" not in pat:
            hit = any(fnmatch.fnmatch(part, pat) for part in rel.split("/")[:-1])
        if hit:
            ignored = not negate
    return ignored


def check_config(root: Path) -> Iterator[ConfigIssue]:
    files = list(iter_source_files(root))
    patterns = _gitignore_patterns(root)
    for path in files:
        rel = path.relative_to(root).as_posix()
        name = path.name.lower()
        parts = set(rel.lower().split("/")[:-1])
        found: Iterator[ConfigIssue | None] = iter(())
        if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
            found = _dockerfile(root, path)
        elif re.match(r"^(docker-)?compose[\w.-]*\.ya?ml$", name):
            found = _compose(root, path)
        elif name.endswith(".conf") and (
            "nginx" in name or "nginx" in parts or "sites-available" in parts or "conf.d" in parts
        ):
            found = _nginx(root, path)
        elif name == ".htaccess":
            found = _htaccess(root, path)
        elif ".github/workflows/" in rel.lower() and name.endswith((".yml", ".yaml")):
            found = _workflow(root, path)
        for issue in found:
            if issue is not None:
                yield issue
        # Shipped source maps
        if name.endswith(".js.map") or name.endswith(".css.map"):
            if parts & PUBLIC_DIRS or (root / "index.html").is_file():
                yield ConfigIssue("CONF-SOURCEMAP-001", rel, None, "high")
        # Leftover backup / editor files
        if (
            name.endswith(BACKUP_SUFFIXES)
            or name in {".ds_store", "thumbs.db"}
            or (re.search(r"\.(?:sql|dump)$", name) and parts & PUBLIC_DIRS)
        ):
            yield ConfigIssue("CONF-BACKUP-001", rel, None, "high")
        # Secrets files that are not git-ignored
        is_secret_file = (name == ".env" or name.startswith(".env.")) and not re.search(
            r"\.(example|sample|template|dist)$", name
        )
        is_secret_file = (
            is_secret_file
            or name in {"id_rsa", "id_dsa", "id_ed25519", "id_ecdsa"}
            or name.endswith((".pem", ".key", ".p12", ".pfx"))
        )
        if is_secret_file and (patterns is None or not is_ignored(rel, patterns)):
            yield ConfigIssue("CONF-GITIGNORE-001", rel, None, "high")
