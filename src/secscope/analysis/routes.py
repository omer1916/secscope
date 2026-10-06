"""Attack-surface inventory: the HTTP endpoints a project declares and whether an
authentication/authorisation guard is visible on each (report section, not findings).

Static and heuristic by nature: a guard applied elsewhere (global middleware, a reverse
proxy) shows as "unknown" or "none". The list is for review — which state-changing
endpoints can anyone call? — not a verdict.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from typing import Any, Literal

from secscope.analysis.source import SourceFile

Guard = Literal["yes", "no", "unknown"]
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
MAX_ROUTES = 500
# Names that usually mean "caller must be authenticated / authorised".
GUARD_NAME = re.compile(
    r"(?i)(login_required|auth|jwt|token_required|permission|roles?_required|admin_required"
    r"|requires?_|protect|ensure|verify|is_?authenticated|passport|current_user|session_required)"
)
# Endpoints that must be reachable without a session (sign-in, sign-up, webhooks...).
PUBLIC_BY_DESIGN = re.compile(
    r"(?i)(login|log-in|signin|sign-in|signup|sign-up|register|logout|token|oauth|callback"
    r"|password|forgot|reset|verify|webhook|health|status)"
)
_PY_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_EXPRESS = re.compile(
    r"\b(?P<obj>app|router|\w+Router|api)\.(?P<method>get|post|put|patch|delete|all)\(\s*"
    r"(?P<q>['\"`])(?P<path>[^'\"`]+)(?P=q)\s*,(?P<rest>.*)$"
)
_EXPRESS_GLOBAL_GUARD = re.compile(
    r"\b(?:app|router)\.use\(\s*(?:['\"`][^'\"`]*['\"`]\s*,\s*)?(\w+)"
)
_DJANGO = re.compile(r"\b(?:re_)?path\(\s*r?(['\"])(?P<path>[^'\"]*)\1")


@dataclass(frozen=True, slots=True)
class Route:
    method: str
    path: str
    file: str
    line: int
    framework: str
    guard: Guard
    guard_name: str = ""

    @property
    def state_changing(self) -> bool:
        return self.method in STATE_CHANGING or self.method == "ANY"

    @property
    def public_by_design(self) -> bool:
        return bool(PUBLIC_BY_DESIGN.search(self.path))

    @property
    def needs_review(self) -> bool:
        """State-changing, no visible guard, and not a sign-in style endpoint."""
        return self.state_changing and self.guard == "no" and not self.public_by_design

    def as_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "state_changing": self.state_changing,
            "public_by_design": self.public_by_design,
            "needs_review": self.needs_review,
        }


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _python_routes(file: SourceFile) -> Iterator[Route]:
    try:
        tree = ast.parse(file.text)
    except (SyntaxError, ValueError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        routes: list[tuple[list[str], str, int]] = []
        guards: list[str] = []
        for dec in node.decorator_list:
            name = _dotted(dec)
            last = name.rsplit(".", 1)[-1]
            if isinstance(dec, ast.Call) and (last == "route" or last in _PY_ROUTE_METHODS):
                first = dec.args[0] if dec.args else None
                if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                    continue
                methods = [last.upper()] if last != "route" else ["GET"]
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, ast.List | ast.Tuple):
                        methods = [
                            str(e.value).upper()
                            for e in kw.value.elts
                            if isinstance(e, ast.Constant) and isinstance(e.value, str)
                        ] or methods
                routes.append((methods, first.value, dec.lineno))
            elif GUARD_NAME.search(name):
                guards.append(name)
        if not routes:
            continue
        # FastAPI: Depends(get_current_user) in the parameters is a guard too.
        for default in [*node.args.defaults, *node.args.kw_defaults]:
            if isinstance(default, ast.Call) and _dotted(default).endswith("Depends"):
                dep = _dotted(default.args[0]) if default.args else ""
                if GUARD_NAME.search(dep):
                    guards.append(f"Depends({dep})")
        for methods, path, line in routes:
            for method in methods:
                yield Route(
                    method=method,
                    path=path,
                    file=file.rel,
                    line=line,
                    framework="python",
                    guard="yes" if guards else "no",
                    guard_name=", ".join(guards),
                )


def _express_routes(file: SourceFile) -> Iterator[Route]:
    global_guard = ""
    for line in file.text.splitlines():
        m = _EXPRESS_GLOBAL_GUARD.search(line)
        if m and GUARD_NAME.search(m.group(1)):
            global_guard = m.group(1)
    for i, line in enumerate(file.text.splitlines(), start=1):
        m = _EXPRESS.search(line)
        if m is None:
            continue
        # Everything between the path and the final handler is middleware.
        middleware = re.split(r"\(\s*req\b|async\s*\(|function\s*\(", m.group("rest"))[0]
        names = [n for n in re.findall(r"[A-Za-z_$][\w$.]*", middleware) if GUARD_NAME.search(n)]
        guard: Guard = "yes" if names else ("unknown" if global_guard else "no")
        yield Route(
            method="ANY" if m.group("method") == "all" else m.group("method").upper(),
            path=m.group("path"),
            file=file.rel,
            line=i,
            framework="express",
            guard=guard,
            guard_name=", ".join(names) or (f"app.use({global_guard})" if global_guard else ""),
        )


def _django_routes(file: SourceFile) -> Iterator[Route]:
    for i, line in enumerate(file.text.splitlines(), start=1):
        m = _DJANGO.search(line)
        if m is None:
            continue
        guard: Guard = "yes" if GUARD_NAME.search(line) else "unknown"
        yield Route(
            method="ANY",
            path="/" + m.group("path").lstrip("^/"),
            file=file.rel,
            line=i,
            framework="django",
            guard=guard,
            guard_name="" if guard == "unknown" else "decorator in urls.py",
        )


def extract_routes(files: Iterable[SourceFile]) -> list[Route]:
    found: list[Route] = []
    for file in files:
        if file.language == "python":
            if file.path.name == "urls.py":
                found.extend(_django_routes(file))
            else:
                found.extend(_python_routes(file))
        elif file.language == "javascript":
            found.extend(_express_routes(file))
        if len(found) >= MAX_ROUTES:
            break
    return sorted(found[:MAX_ROUTES], key=lambda r: (r.path, r.method, r.file, r.line))


def summarise(routes: list[Route]) -> dict[str, int]:
    return {
        "total": len(routes),
        "state_changing": sum(r.state_changing for r in routes),
        "needs_review": sum(r.needs_review for r in routes),
    }
