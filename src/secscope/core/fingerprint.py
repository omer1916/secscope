"""Guess a project's stack and how to run it (SPEC §6.1). The wizard shows the result editable.

Commands may contain ``{port}`` and ``{host}`` placeholders, filled in by the runner.
``{python}`` is the interpreter of the per-scan virtualenv.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

StackKind = Literal["static", "server", "unknown"]

DEPENDENCY_DIRS = frozenset(
    {"node_modules", ".venv", "venv", "env", "vendor", "bower_components", "__pycache__", ".git",
     ".hg", ".svn", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next", ".nuxt",
     "dist", "build", ".cache"}
)  # fmt: skip


@dataclass
class Fingerprint:
    kind: StackKind
    stack: str  # "static", "express", "next", "flask", "django", "fastapi", "php", "laravel", ...
    languages: list[str] = field(default_factory=list[str])
    frameworks: list[str] = field(default_factory=list[str])
    run_command: list[str] | None = None
    install_command: list[str] | None = None
    ready_path: str = "/"
    env: dict[str, str] = field(default_factory=dict[str, str])
    files: list[str] = field(default_factory=list[str])
    notes: list[str] = field(default_factory=list[str])
    # True when the start command is a development server (load-test warning, SPEC §8.3).
    dev_server: bool = False
    static_root: str | None = None  # relative directory served by the built-in server

    @property
    def stack_family(self) -> str:
        """Key into remediation snippets: express | flask | django | php | nginx | static ..."""
        mapping = {"next": "express", "nuxt": "express", "vite": "static", "fastify": "express",
                   "koa": "express", "node": "express", "fastapi": "flask", "python": "flask",
                   "laravel": "php"}  # fmt: skip
        return mapping.get(self.stack, self.stack)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}  # pyright: ignore[reportUnknownVariableType]


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")


def _python_dependencies(root: Path) -> set[str]:
    """Normalised names of declared Python dependencies."""
    names: list[str] = []
    for name in ("requirements.txt", "requirements-prod.txt"):
        p = root / name
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip().startswith(("#", "-")):
                    continue
                if m := _REQ_NAME.match(line):
                    names.append(m.group(1))
    pipfile = root / "Pipfile"
    if pipfile.is_file():
        try:
            data = tomllib.loads(pipfile.read_text(encoding="utf-8"))
            names += list(data.get("packages", {}))
        except (OSError, ValueError):
            pass
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            for dep in data.get("project", {}).get("dependencies", []):
                if m := _REQ_NAME.match(str(dep)):
                    names.append(m.group(1))
            names += list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}))
        except (OSError, ValueError):
            pass
    return {re.sub(r"[-_.]+", "-", n).lower() for n in names}


def _find_flask_entry(root: Path) -> str | None:
    for name in ("app.py", "wsgi.py", "main.py", "server.py", "run.py", "application.py"):
        p = root / name
        if p.is_file() and "flask" in p.read_text(encoding="utf-8", errors="replace").lower():
            return name
    return None


def _find_fastapi_entry(root: Path) -> str | None:
    for name in ("main.py", "app.py", "api.py", "server.py"):
        p = root / name
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            if "FastAPI(" in text:
                m = re.search(r"^(\w+)\s*=\s*FastAPI\(", text, re.MULTILINE)
                return f"{name[:-3]}:{m.group(1) if m else 'app'}"
    return None


def _node(root: Path, fp: Fingerprint) -> None:
    pkg = _read_json(root / "package.json")
    deps: dict[str, Any] = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    scripts: dict[str, str] = pkg.get("scripts", {})
    fp.languages.append("javascript")
    if (root / "tsconfig.json").exists() or "typescript" in deps:
        fp.languages.append("typescript")
    lock = (root / "package-lock.json").exists()
    fp.install_command = ["npm", "ci"] if lock else ["npm", "install"]
    if (root / "yarn.lock").exists():
        fp.install_command = ["yarn", "install", "--frozen-lockfile"]
    elif (root / "pnpm-lock.yaml").exists():
        fp.install_command = ["pnpm", "install", "--frozen-lockfile"]
    fp.env.update({"PORT": "{port}", "HOST": "{host}", "HOSTNAME": "{host}"})

    # Most specific framework first: a Next.js app also depends on React, etc.
    for name in ("next", "nuxt", "fastify", "koa", "express", "vite"):
        if name in deps:
            fp.frameworks.append(name)
    fp.stack = fp.frameworks[0] if fp.frameworks else "node"

    if fp.stack == "next":
        fp.run_command = ["npm", "run", "dev", "--", "-H", "{host}", "-p", "{port}"]
        fp.dev_server = True
        if "start" in scripts and (root / ".next").exists():
            fp.run_command = ["npm", "start", "--", "-H", "{host}", "-p", "{port}"]
            fp.dev_server = False
    elif fp.stack == "vite":
        fp.run_command = [
            "npm",
            "run",
            "dev",
            "--",
            "--host",
            "{host}",
            "--port",
            "{port}",
            "--strictPort",
        ]
        fp.dev_server = True
    elif "start" in scripts:
        fp.run_command = ["npm", "start"]
    elif "dev" in scripts:
        fp.run_command = ["npm", "run", "dev"]
        fp.dev_server = True
    else:
        main = pkg.get("main") or next(
            (n for n in ("server.js", "app.js", "index.js") if (root / n).exists()), None
        )
        if main:
            fp.run_command = ["node", str(main)]
    if "nodemon" in " ".join(scripts.values()):
        fp.dev_server = True
    fp.kind = "server" if fp.run_command else "unknown"


def _python(root: Path, fp: Fingerprint) -> None:
    deps = _python_dependencies(root)
    fp.languages.append("python")
    req_file = next(
        (n for n in ("requirements.txt", "requirements-prod.txt") if (root / n).is_file()), None
    )
    if req_file:
        fp.install_command = ["{python}", "-m", "pip", "install", "-r", req_file]
    elif (root / "pyproject.toml").is_file():
        fp.install_command = ["{python}", "-m", "pip", "install", "."]

    if (root / "manage.py").is_file() or "django" in deps:
        fp.frameworks.append("django")
        fp.stack = "django"
        fp.run_command = ["{python}", "manage.py", "runserver", "{host}:{port}", "--noreload"]
        fp.dev_server = True
        fp.notes.append("django runserver is a development server")
    elif "fastapi" in deps or _find_fastapi_entry(root):
        fp.frameworks.append("fastapi")
        fp.stack = "fastapi"
        entry = _find_fastapi_entry(root) or "main:app"
        fp.run_command = [
            "{python}",
            "-m",
            "uvicorn",
            entry,
            "--host",
            "{host}",
            "--port",
            "{port}",
        ]
    elif "flask" in deps or _find_flask_entry(root):
        fp.frameworks.append("flask")
        fp.stack = "flask"
        entry = _find_flask_entry(root) or "app.py"
        fp.run_command = [
            "{python}",
            "-m",
            "flask",
            "--app",
            entry,
            "run",
            "--host",
            "{host}",
            "--port",
            "{port}",
        ]
        fp.env.update({"FLASK_RUN_HOST": "{host}", "FLASK_RUN_PORT": "{port}"})
        fp.dev_server = True
        if deps & {"gunicorn", "waitress", "uwsgi"}:
            fp.notes.append(
                "a production WSGI server is declared; consider using it for load tests"
            )
    else:
        fp.stack = "python"
        entry = next((n for n in ("app.py", "main.py", "server.py") if (root / n).is_file()), None)
        if entry:
            fp.run_command = ["{python}", entry]
    fp.env.update({"PORT": "{port}", "HOST": "{host}", "PYTHONUNBUFFERED": "1"})
    fp.kind = "server" if fp.run_command else "unknown"


def _php(root: Path, fp: Fingerprint) -> None:
    fp.languages.append("php")
    if (root / "composer.json").is_file():
        fp.install_command = ["composer", "install", "--no-interaction"]
    if (root / "artisan").is_file():
        fp.frameworks.append("laravel")
        fp.stack = "laravel"
        fp.run_command = ["php", "artisan", "serve", "--host={host}", "--port={port}"]
    else:
        fp.stack = "php"
        docroot = "public" if (root / "public" / "index.php").is_file() else "."
        fp.run_command = ["php", "-S", "{host}:{port}", "-t", docroot]
        if (root / "wp-config.php").is_file():
            fp.frameworks.append("wordpress")
    fp.dev_server = True
    fp.notes.append("php -S / artisan serve are development servers")
    fp.kind = "server"


def _static_root(root: Path) -> str | None:
    for candidate in (".", "public", "dist", "build", "site", "docs", "_site", "out"):
        if (root / candidate / "index.html").is_file():
            return candidate
    return None


def fingerprint(root: Path) -> Fingerprint:
    fp = Fingerprint(kind="unknown", stack="unknown")
    markers = ("package.json", "requirements.txt", "pyproject.toml", "Pipfile", "composer.json",
               "index.html", "Dockerfile", "docker-compose.yml", "compose.yaml", "manage.py",
               "app.py", "artisan", "wp-config.php", "next.config.js", "next.config.mjs",
               "vite.config.js", "vite.config.ts", ".env", "nginx.conf", ".htaccess")  # fmt: skip
    fp.files = [m for m in markers if (root / m).exists()]
    fp.files += sorted(p.name for p in root.glob(".env.*") if p.is_file())

    plain_python = any(
        (root / n).is_file()
        and "__main__" in (root / n).read_text(encoding="utf-8", errors="replace")
        for n in ("app.py", "main.py", "server.py")
    )
    if (root / "package.json").is_file():
        _node(root, fp)
    elif (
        (plain_python and not (root / "index.html").is_file())
        or any(
            (root / n).is_file()
            for n in ("requirements.txt", "pyproject.toml", "Pipfile", "manage.py")
        )
        or (_find_flask_entry(root) or _find_fastapi_entry(root))
    ):
        _python(root, fp)
    elif (
        (root / "composer.json").is_file()
        or any(root.glob("*.php"))
        or (root / "public" / "index.php").is_file()
    ):
        _php(root, fp)

    if fp.kind == "unknown":
        static = _static_root(root)
        if static is not None:
            fp.kind, fp.stack, fp.static_root = "static", "static", static
            fp.run_command = None
            fp.languages.append("html")
            # A JS bundler project without a server is served from its build output.

    if (root / "Dockerfile").is_file():
        fp.notes.append("Dockerfile present")
    return fp
