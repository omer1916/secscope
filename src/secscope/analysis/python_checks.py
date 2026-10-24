"""Python AST checks with function-local taint tracking (native SAST for Python).

Sources: ``request.<args|form|values|json|data|files|cookies|headers|GET|POST|body|...>``,
``request.get_json()``, ``input()`` and parameters of route handlers (functions decorated
with ``@app.route`` / ``@router.get`` ...). Taint propagates through assignments,
string building, calls and attribute/subscript access within a function.

Each issue carries a confidence: a sink reached by tainted data is ``high``; a sink
fed by a dynamically built string without proven taint is ``medium`` or ``low``.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from secscope.analysis.regex_rules import suppressed
from secscope.analysis.source import SourceFile
from secscope.core.models import Confidence, Severity

REQUEST_ATTRS = frozenset(
    {"args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST",
     "body", "query_params", "path_params", "get_json", "query_string", "stream", "environ",
     "COOKIES", "META", "FILES"}
)  # fmt: skip
ROUTE_DECORATORS = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "api_route",
        "websocket",
        "api_view",
        "view_config",
    }
)
SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|WHERE|FROM)\b", re.I)
SECRET_NAME = re.compile(
    r"(?i)(?:^|_|\b)(secret(?:_?key)?|passw(?:or)?d|pwd|api_?key|apikey|auth_?token|access_?key|"
    r"private_?key|client_?secret|jwt_?secret|signing_?key|token_?secret)$"
)
PLACEHOLDER = re.compile(
    r"(?i)^(?:|x+|\*+|changeme|change[-_ ]?me|your[-_].*|<.*>|\$\{.*\}|%\(.*\)s|todo|none|null|example.*|dummy|test)$"
)
SENSITIVE_LOG_NAME = re.compile(r"(?i)(password|passwd|secret|token|api_?key|credential)")
RANDOM_FUNCS = frozenset(
    {"random", "randint", "choice", "choices", "getrandbits", "randrange", "sample", "uniform"}
)
# Calls whose result is safe whatever the input (escaping, type coercion, path sanitising),
# matched on the full dotted name or its last component (markupsafe.escape -> escape).
SANITIZERS = frozenset(
    {"escape", "html.escape", "quote", "quote_plus", "secure_filename", "int", "float", "bool",
     "len", "clean", "bleach.clean", "conditional_escape", "urlencode", "safe_join", "uuid4"}
)  # fmt: skip
DB_RESULT_METHODS = frozenset(
    {
        "execute",
        "executemany",
        "fetchall",
        "fetchone",
        "fetchmany",
        "scalars",
        "scalar",
        "first",
        "all",
    }
)
# Environment variables (insecure-default checks): a secret, a debug switch, an origin list, a
# security switch. NEGATED names flip the meaning: DISABLE_AUTH=true is the insecure value.
ENV_SECRET_NAME = re.compile(
    r"(?i)(secret|passw(?:or)?d|pwd|api_?key|private_?key|signing_?key|jwt|token|salt|session_?key)"
)
ENV_DEBUG_NAME = re.compile(r"(?i)debug")
ENV_ORIGIN_NAME = re.compile(r"(?i)(origin|cors|allowed_?hosts)")
ENV_SWITCH_NAME = re.compile(
    r"(?i)(auth|csrf|verify|ssl|tls|https|secure|login|protect|rate_?limit|encrypt|signature)"
)
ENV_NEGATED_NAME = re.compile(r"(?i)(disable|skip|insecure|bypass|allow_?all|no_)")
ENV_GETTERS = frozenset({"os.environ.get", "os.getenv", "environ.get", "getenv"})
TRUTHY = frozenset({"1", "true", "yes", "on", "y", "t"})
FALSY = frozenset({"0", "false", "no", "off", "n", "f", ""})
# stat constants that grant write access to "others".
WORLD_WRITE_FLAGS = frozenset({"S_IWOTH", "S_IRWXO"})
TOKENISH = re.compile(r"(?i)(token|secret|passw|otp|nonce|salt|session|api_?key|reset|verif)")


@dataclass(frozen=True, slots=True)
class PyIssue:
    rule_id: str
    line: int
    column: int
    confidence: Confidence
    severity: Severity | None = None
    note: str = ""
    end_line: int | None = None


def _dotted(node: ast.AST) -> str:
    """'requests.get' for Attribute(Name('requests'), 'get'); '' if not a simple chain."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):
        inner = _dotted(node.func)
        return (inner + "()." + ".".join(reversed(parts))).rstrip(".") if inner else ""
    return ""


def _call_name(call: ast.Call) -> str:
    return _dotted(call.func)


def _last(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value in (False, 0)


def _const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _string_parts(node: ast.AST) -> list[str]:
    """Constant string fragments inside a string-building expression."""
    return [
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _target_names(elt)]
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return []


def _assigned_name(target: ast.expr) -> str:
    """Name used for secret-name heuristics: x, self.x, cfg['X'], app.config['X']."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript):
        return _const_str(target.slice) or ""
    return ""


class _Function:
    def __init__(self, tainted: set[str]) -> None:
        self.tainted = set(tainted)
        self.dynamic: set[str] = set()  # names holding dynamically built strings
        self.html: set[str] = set()  # names holding dynamic strings with HTML markup
        # True when `request` is a parameter/local here (e.g. an httpx.Request), not flask.request.
        self.request_shadowed = False


class _Checker(ast.NodeVisitor):
    def __init__(self, file: SourceFile) -> None:
        self.file = file
        self.issues: list[PyIssue] = []
        self.scope = _Function(set())
        # Module-level names bound exactly once to a constant string ("SELECT ... " fragments):
        # concatenating them is not dynamic SQL/HTML.
        self.str_constants: set[str] = set()
        self.is_settings = file.path.name in {
            "settings.py",
            "config.py",
            "base.py",
            "production.py",
        }

    # ------------------------------------------------------------- helpers

    def report(
        self,
        rule_id: str,
        node: ast.AST,
        confidence: Confidence,
        severity: Severity | None = None,
        note: str = "",
    ) -> None:
        line = getattr(node, "lineno", 1)
        if suppressed(self.file.line_text(line), rule_id):
            return
        self.issues.append(
            PyIssue(
                rule_id,
                line,
                getattr(node, "col_offset", 0) + 1,
                confidence,
                severity,
                note,
                getattr(node, "end_lineno", None),
            )
        )

    def tainted(self, node: ast.AST | None) -> bool:
        """True if request-controlled data reaches ``node`` without passing a sanitizer."""
        if node is None:
            return False
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in SANITIZERS or _last(name) in SANITIZERS:
                return False
            if name in {"input", "request.get_json"}:
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr in DB_RESULT_METHODS:
                # Rows returned by a (parameterised) query are stored data, not request data.
                return self.tainted(node.func.value)
        if isinstance(node, ast.Name):
            return node.id in self.scope.tainted
        if isinstance(node, ast.Attribute):
            root: ast.AST = node
            attrs: list[str] = []
            while isinstance(root, ast.Attribute):
                attrs.append(root.attr)
                root = root.value
            if (
                isinstance(root, ast.Name)
                and root.id == "request"
                and not self.scope.request_shadowed
                and REQUEST_ATTRS & set(attrs)
            ):
                return True
        return any(self.tainted(child) for child in ast.iter_child_nodes(node))

    def is_constant_str(self, node: ast.AST) -> bool:
        """A string built only from literals and module-level string constants."""
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str)
        if isinstance(node, ast.Name):
            return node.id in self.str_constants
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.is_constant_str(node.left) and self.is_constant_str(node.right)
        if isinstance(node, ast.JoinedStr):
            return not any(isinstance(v, ast.FormattedValue) for v in node.values)
        return False

    def dynamic_string(self, node: ast.AST | None) -> bool:
        """f-strings, concatenation, % formatting or .format() — or a name holding one."""
        if node is None:
            return False
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            sides = (node.left, node.right)
            has_str = any(
                isinstance(s, (ast.Constant, ast.JoinedStr))
                and not isinstance(getattr(s, "value", ""), (int, float))
                for s in sides
            ) or any(self.dynamic_string(s) for s in sides)
            has_var = any(
                not isinstance(s, ast.Constant) and not self.is_constant_str(s) for s in sides
            )
            return has_str and has_var
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            return bool(node.args or node.keywords)
        if isinstance(node, ast.Name):
            return node.id in self.scope.dynamic
        return False

    def _html_string(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.scope.html
        return self.dynamic_string(node) and any("<" in s and ">" in s for s in _string_parts(node))

    # ----------------------------------------------------------- scoping

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        params: set[str] = set()
        is_route = any(
            isinstance(d, ast.Call) and _last(_call_name(d)) in ROUTE_DECORATORS
            for d in node.decorator_list
        )
        if is_route:
            params = {
                a.arg
                for a in [*node.args.args, *node.args.kwonlyargs]
                if a.arg not in {"self", "cls", "request"}
            }
        for d in node.decorator_list:
            if _last(_dotted(d.func if isinstance(d, ast.Call) else d)) == "csrf_exempt":
                self.report("SAST-CSRF-001", d, "high")
        outer = self.scope
        self.scope = _Function(params)
        all_params = {
            a.arg for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        }
        assigned = {
            n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
        }
        self.scope.request_shadowed = "request" in all_params | assigned
        self._propagate(node.body)
        self.generic_visit(node)
        self.scope = outer

    visit_FunctionDef = _visit_function  # noqa: N815
    visit_AsyncFunctionDef = _visit_function  # noqa: N815

    def _propagate(self, body: Iterable[ast.stmt]) -> None:
        """Fixed point of taint / dynamic-string facts over assignments in a function."""
        assigns: list[tuple[list[str], ast.expr]] = []
        for stmt in body:
            for n in ast.walk(stmt):
                if isinstance(n, ast.Assign):
                    assigns.append(([x for t in n.targets for x in _target_names(t)], n.value))
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    assigns.append((_target_names(n.target), n.value))
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    assigns.append((_target_names(n.target), n.iter))
                elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                    assigns.append((_target_names(n.optional_vars), n.context_expr))
                elif isinstance(n, ast.NamedExpr):
                    assigns.append((_target_names(n.target), n.value))
        changed = True
        while changed:
            changed = False
            for names, value in assigns:
                facts = (
                    (self.scope.tainted, self.tainted(value)),
                    (self.scope.dynamic, self.dynamic_string(value)),
                    (self.scope.html, self._html_string(value)),
                )
                for bucket, holds in facts:
                    if holds and not set(names) <= bucket:
                        bucket.update(names)
                        changed = True

    # -------------------------------------------------------------- visits

    def visit_Module(self, node: ast.Module) -> None:
        self._collect_str_constants(node)
        self._propagate(node.body)
        self.generic_visit(node)

    def _collect_str_constants(self, node: ast.Module) -> None:
        bound: dict[str, int] = {}
        candidates: set[str] = set()
        for stmt in node.body:
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(stmt, ast.Assign):
                targets, value = stmt.targets, stmt.value
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                targets, value = [stmt.target], stmt.value
            elif isinstance(stmt, ast.AugAssign):
                targets = [stmt.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    bound[target.id] = bound.get(target.id, 0) + 1
                    if value is not None and self.is_constant_str(value):
                        candidates.add(target.id)
                        self.str_constants.add(target.id)  # later constants may build on it
        # Any other binding anywhere in the module (a function assigning it via `global`, a loop
        # target, a second module-level assignment) makes the name variable again.
        stores = dict.fromkeys(candidates, 0)
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id in stores:
                stores[n.id] += 1
        self.str_constants = {
            name for name in candidates if bound.get(name) == 1 and stores[name] == 1
        }

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        broad = node.type is None or (
            isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
        )
        silent = all(
            isinstance(s, (ast.Pass, ast.Continue))
            or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
            for s in node.body
        )
        if broad and silent:
            self.report("QUAL-EXCEPT-001", node, "high")
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        if any(a.name in {"pdb", "ipdb", "pudb"} for a in node.names):
            self.report("QUAL-DEBUGCODE-001", node, "medium")
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self._check_response_body(node.value, node)
        self.generic_visit(node)

    def _check_response_body(self, value: ast.expr, node: ast.AST) -> None:
        body = value.elts[0] if isinstance(value, ast.Tuple) and value.elts else value
        if self._html_string(body) and self.tainted(body):
            self.report("SAST-XSS-004", node, "high")
        if any(
            isinstance(n, ast.Call) and _call_name(n).startswith("traceback.format_")
            for n in ast.walk(body)
        ):
            self.report("SAST-ERRLEAK-001", node, "high")

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_assignment(target, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_assignment(node.target, node.value, node)
        self.generic_visit(node)

    def _check_assignment(self, target: ast.expr, value: ast.expr, node: ast.AST) -> None:
        name = _assigned_name(target)
        upper = name.upper()
        # Debug / insecure framework settings
        if (
            upper == "DEBUG"
            and _is_true(value)
            and (self.is_settings or isinstance(target, (ast.Attribute, ast.Subscript)))
        ):
            self.report("SAST-DEBUG-001", node, "high")
        if upper in {"WTF_CSRF_ENABLED", "CSRF_ENABLED"} and _is_false(value):
            self.report("SAST-CSRF-001", node, "high")
        if upper in {"CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL"} and _is_true(value):
            self.report("SAST-CORS-001", node, "medium")
        if upper in {
            "SESSION_COOKIE_SECURE",
            "CSRF_COOKIE_SECURE",
            "SESSION_COOKIE_HTTPONLY",
        } and _is_false(value):
            self.report("SAST-COOKIE-001", node, "high")
        # CORS reflection: resp.headers["Access-Control-Allow-Origin"] = request origin
        if name.lower() == "access-control-allow-origin" and (
            self.tainted(value) or "origin" in ast.unparse(value).lower()
        ):
            self.report("SAST-CORS-001", node, "high")
        # Hardcoded secrets
        literal = _const_str(value)
        if (
            literal is not None
            and SECRET_NAME.search(name)
            and not PLACEHOLDER.match(literal.strip())
        ):
            if " " not in literal.strip() or len(literal) < 40:
                rule = (
                    "SAST-JWT-001"
                    if "jwt" in name.lower() or "token_secret" in name.lower()
                    else "SAST-HARDCODED-001"
                )
                self.report(rule, node, "high" if len(literal) >= 6 else "medium")
        # Insecure randomness for security tokens
        if (
            isinstance(value, ast.Call)
            and _call_name(value).startswith("random.")
            and _last(_call_name(value)) in RANDOM_FUNCS
        ):
            if TOKENISH.search(name):
                self.report("SAST-RAND-001", node, "high")

    def _check_env_default(self, node: ast.Call) -> None:
        """``os.environ.get("NAME", default)``: is the unconfigured state the insecure one?"""
        var = _const_str(node.args[0])
        default = _const_str(node.args[1])
        if var is None or default is None:
            return
        value = default.strip().lower()
        negated = bool(ENV_NEGATED_NAME.search(var))
        if ENV_SECRET_NAME.search(var) and not negated and value:
            self.report("SAST-FALLBACK-001", node, "high")
        elif (ENV_DEBUG_NAME.search(var) and not negated and value in TRUTHY) or (
            ENV_ORIGIN_NAME.search(var) and value == "*"
        ):
            self.report("SAST-FAILOPEN-001", node, "high")
        elif ENV_SWITCH_NAME.search(var) and (
            (negated and value in TRUTHY) or (not negated and value in FALSY and value)
        ):
            self.report("SAST-FAILOPEN-001", node, "medium")

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        last = _last(name)
        first = node.args[0] if node.args else None
        tainted_any = any(self.tainted(a) for a in node.args) or any(
            self.tainted(k.value) for k in node.keywords
        )

        # SQL injection
        if last in {"execute", "executemany", "executescript", "raw", "mogrify"} or name in {
            "text",
            "sqlalchemy.text",
        }:
            if first is not None and self.dynamic_string(first):
                parts = (
                    " ".join(_string_parts(first)) if not isinstance(first, ast.Name) else "SELECT"
                )
                if SQL_KEYWORDS.search(parts):
                    self.report("SAST-SQLI-001", node, "high" if self.tainted(first) else "medium")
        # Command injection
        if name in {
            "os.system",
            "os.popen",
            "commands.getoutput",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        } or (name.startswith("subprocess.") and _is_true(_kw(node, "shell"))):
            if first is not None and not isinstance(first, ast.Constant):
                self.report("SAST-CMDI-001", node, "high" if self.tainted(first) else "medium")
        # Code evaluation / template injection
        if name in {"eval", "exec"} and first is not None and not isinstance(first, ast.Constant):
            self.report("SAST-EVAL-001", node, "high" if self.tainted(first) else "medium")
        if (
            last == "render_template_string"
            and first is not None
            and not isinstance(first, ast.Constant)
        ):
            self.report("SAST-SSTI-001", node, "high" if self.tainted(first) else "medium")
        if name in {"jinja2.Template", "Template"} and first is not None and self.tainted(first):
            self.report("SAST-SSTI-001", node, "high")
        # Insecure deserialization
        if name in {
            "pickle.loads",
            "pickle.load",
            "cPickle.loads",
            "dill.loads",
            "marshal.loads",
            "jsonpickle.decode",
            "shelve.open",
            "yaml.unsafe_load",
        }:
            self.report("SAST-DESER-001", node, "high" if tainted_any else "medium")
        if name == "yaml.load":
            loader = _kw(node, "Loader") or (node.args[1] if len(node.args) > 1 else None)
            if loader is None or _last(_dotted(loader)) in {"Loader", "UnsafeLoader", "FullLoader"}:
                self.report("SAST-DESER-001", node, "high" if tainted_any else "medium")
        # Path traversal
        if (
            name
            in {
                "open",
                "io.open",
                "codecs.open",
                "send_file",
                "flask.send_file",
                "os.remove",
                "os.unlink",
                "shutil.rmtree",
                "FileResponse",
                "Path",
                "pathlib.Path",
            }
            and first is not None
            and self.tainted(first)
        ):
            self.report("SAST-PATH-001", node, "high")
        # Open redirect
        if (
            last in {"redirect", "HttpResponseRedirect", "RedirectResponse"}
            and first is not None
            and self.tainted(first)
        ):
            self.report("SAST-REDIRECT-001", node, "high")
        # SSRF
        if (
            name.startswith(("requests.", "httpx."))
            and last in {"get", "post", "put", "patch", "delete", "head", "request", "options"}
        ) or name in {"urllib.request.urlopen", "urlopen"}:
            target = first if last != "request" else (node.args[1] if len(node.args) > 1 else None)
            if target is not None and self.tainted(target):
                self.report("SAST-SSRF-001", node, "high")
        # XSS helpers that mark strings safe; responses built from HTML strings
        if (
            last in {"Markup", "mark_safe"}
            and first is not None
            and not isinstance(first, ast.Constant)
        ):
            self.report("SAST-XSS-003", node, "high" if self.tainted(first) else "medium")
        if (
            last in {"make_response", "HttpResponse", "Response", "HTMLResponse"}
            and first is not None
        ):
            self._check_response_body(first, node)
        # Insecure defaults: the value used when the environment variable is missing
        if name in ENV_GETTERS and len(node.args) >= 2:
            self._check_env_default(node)
        # World-writable file permissions
        if last in {"chmod", "fchmod", "lchmod"}:
            mode = node.args[1] if name.startswith("os.") and len(node.args) > 1 else None
            if mode is None and not name.startswith("os."):
                mode = node.args[0] if node.args else _kw(node, "mode")
            if mode is not None and _world_writable(mode):
                self.report("SAST-PERM-001", node, "high")
        # Debug mode
        if last == "run" and _is_true(_kw(node, "debug")):
            self.report("SAST-DEBUG-001", node, "high")
        # TLS verification disabled
        if _is_false(_kw(node, "verify")) and (
            name.startswith(("requests", "httpx", "session", "self.session", "client"))
            or last
            in {"get", "post", "put", "delete", "request", "Client", "AsyncClient", "Session"}
        ):
            self.report("SAST-TLS-001", node, "high")
        if name in {"ssl._create_unverified_context"}:
            self.report("SAST-TLS-001", node, "high")
        # JWT
        if name in {"jwt.encode", "jwt.decode"}:
            key = node.args[1] if len(node.args) > 1 else _kw(node, "key")
            if _const_str(key) is not None:
                self.report("SAST-JWT-001", node, "high")
            algs = _kw(node, "algorithms")
            if algs is not None and any(_const_str(e) == "none" for e in ast.walk(algs)):
                self.report("SAST-JWT-002", node, "high")
            options = _kw(node, "options")
            if (
                options is not None
                and "verify_signature" in ast.unparse(options)
                and "False" in ast.unparse(options)
            ):
                self.report("SAST-JWT-002", node, "high")
        # Weak crypto
        if name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"} and not _is_false(
            _kw(node, "usedforsecurity")
        ):
            ctx = self.file.line_text(node.lineno).lower()
            self.report("SAST-CRYPTO-001", node, "high" if "pass" in ctx else "low")
        if name == "hashlib.new" and _const_str(first) in {"md5", "sha1", "md4"}:
            self.report("SAST-CRYPTO-001", node, "low")
        if any(
            isinstance(a, ast.Attribute) and a.attr == "MODE_ECB" for a in node.args
        ) or name.endswith("modes.ECB"):
            self.report("SAST-CRYPTO-002", node, "high")
        # CORS
        if last == "CORS" and _is_true(_kw(node, "supports_credentials")):
            origins = _kw(node, "origins") or _kw(node, "resources")
            if origins is None or "*" in ast.unparse(origins):
                self.report("SAST-CORS-001", node, "medium")
        # Cookies without flags
        if last == "set_cookie":
            missing = [
                flag
                for flag in ("httponly", "secure", "samesite")
                if _kw(node, flag) is None or _is_false(_kw(node, flag))
            ]
            if missing:
                self.report("SAST-COOKIE-001", node, "high", note=",".join(missing))
        # Mass assignment
        for kw in node.keywords:
            if kw.arg is None and self.tainted(kw.value):
                self.report("SAST-MASSASSIGN-001", node, "high")
        if name.endswith("__dict__.update") and tainted_any:
            self.report("SAST-MASSASSIGN-001", node, "high")
        # XXE
        if last == "XMLParser" and (
            _is_true(_kw(node, "resolve_entities")) or _is_false(_kw(node, "no_network"))
        ):
            self.report("SAST-XXE-001", node, "high")
        if (
            last == "setFeature"
            and first is not None
            and "external" in ast.unparse(first).lower()
            and len(node.args) > 1
            and _is_true(node.args[1])
        ):
            self.report("SAST-XXE-001", node, "high")
        # File upload saved under the client-supplied name
        if (
            last == "save"
            and first is not None
            and "filename" in ast.unparse(first)
            and "secure_filename" not in ast.unparse(first)
        ):
            self.report("SAST-UPLOAD-001", node, "medium")
        # Serving the project root as static files
        if last in {"Flask", "Quart"}:
            folder = _const_str(_kw(node, "static_folder"))
            if folder is not None and folder.strip("/") in {"", ".", ".."}:
                self.report("SAST-EXPOSE-001", node, "high")
        # Sensitive data in logs
        if name == "print" or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr
            in {"debug", "info", "warning", "error", "critical", "exception", "log"}
            and _dotted(node.func.value).split(".")[-1]
            in {"logging", "logger", "log", "LOGGER", "app.logger"}
        ):
            for arg in node.args:
                names = [n.id for n in ast.walk(arg) if isinstance(n, ast.Name)] + [
                    n.attr for n in ast.walk(arg) if isinstance(n, ast.Attribute)
                ]
                if any(SENSITIVE_LOG_NAME.search(x) for x in names):
                    self.report("SAST-LOG-001", node, "medium")
                    break
        # Debug code
        if name in {"pdb.set_trace", "ipdb.set_trace", "breakpoint"}:
            self.report("QUAL-DEBUGCODE-001", node, "high")
        self.generic_visit(node)


def _world_writable(mode: ast.expr) -> bool:
    if (
        isinstance(mode, ast.Constant)
        and isinstance(mode.value, int)
        and not isinstance(mode.value, bool)
    ):
        return bool(mode.value & 0o002)
    names = {
        n.attr if isinstance(n, ast.Attribute) else n.id
        for n in ast.walk(mode)
        if isinstance(n, (ast.Attribute, ast.Name))
    }
    return bool(names & WORLD_WRITE_FLAGS)


def check_python(file: SourceFile) -> Iterator[PyIssue]:
    try:
        tree = ast.parse(file.text, filename=file.rel)
    except (SyntaxError, ValueError):
        return
    checker = _Checker(file)
    checker.visit(tree)
    seen: set[tuple[str, int]] = set()
    for issue in checker.issues:
        key = (issue.rule_id, issue.line)
        if key not in seen:
            seen.add(key)
            yield issue
