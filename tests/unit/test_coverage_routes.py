"""Coverage accounting, exclusions, test/fixture background, git facts and the attack-surface
inventory."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from secscope.analysis.kb import default_kb
from secscope.analysis.routes import extract_routes, summarise
from secscope.analysis.source import SourceFile
from secscope.core.config import ScanConfig, Target, TargetKind
from secscope.core.coverage import background_reason, build_coverage, matches_exclude
from secscope.core.gitinfo import GitError, changed_files, check_ref, revision
from secscope.core.intake import prepare_source
from secscope.core.models import CodeLocation, Evidence, Finding
from secscope.core.scan import background_code, only_changed
from secscope.reporting.writer import write_outputs

# ------------------------------------------------------------------ exclusions


@pytest.mark.parametrize(
    ("rel", "patterns", "expected"),
    [
        ("tests/test_app.py", ["tests"], True),
        ("pkg/tests/x.py", ["tests"], True),
        ("src/app.py", ["tests"], False),
        ("docs/guide.md", ["docs/*.md"], True),
        ("docs/sub/guide.md", ["docs/*.md"], True),  # fnmatch '*' crosses '/'
        ("legacy/old.py", ["legacy/"], True),
        ("src/legacy.py", ["legacy/"], False),
        ("a/b.min.js", ["*.min.js"], True),
        ("app.py", [" ", ""], False),
    ],
)
def test_matches_exclude(rel: str, patterns: list[str], expected: bool) -> None:
    assert matches_exclude(rel, patterns) is expected


def test_folder_intake_skips_excluded_paths(tmp_path: Path) -> None:
    project = tmp_path / "p"
    (project / "tests").mkdir(parents=True)
    (project / "legacy").mkdir()
    (project / "app.py").write_text("x = 1\n")
    (project / "tests" / "test_app.py").write_text("x = 2\n")
    (project / "legacy" / "old.py").write_text("x = 3\n")
    report = prepare_source(project, tmp_path / "work", exclude=["tests", "legacy/"])
    assert (report.root / "app.py").is_file()
    assert not (report.root / "tests").exists()
    assert not (report.root / "legacy").exists()
    assert sorted(report.excluded) == ["legacy/", "tests/"]
    cov = build_coverage(
        report.root,
        files=report.files,
        total_bytes=report.bytes,
        excluded=report.excluded,
        exclude_patterns=["tests", "legacy/"],
    )
    assert cov["excluded_count"] == 2
    assert cov["code_files_by_language"] == {"python": 1}


def test_exclusion_patterns_cannot_climb_out() -> None:
    with pytest.raises(ValidationError):
        ScanConfig(target=Target(kind=TargetKind.FOLDER, value="."), exclude=["../secret"])


# ------------------------------------------------------------------ background


@pytest.mark.parametrize(
    ("rel", "reason"),
    [
        ("tests/test_x.py", "test"),
        ("test_api.py", "test"),
        ("src/api_test.go", "test"),
        ("web/app.spec.ts", "test"),
        ("fixtures/vuln/app.py", "fixture"),
        ("examples/demo.js", "example"),
        ("static/vendor.min.js", "generated"),
        ("src/app.py", None),
        ("src/latest.py", None),
    ],
)
def test_background_reason(rel: str, reason: str | None) -> None:
    assert background_reason(rel) == reason


def _finding(rule: str, path: str, module: str, severity: str = "high") -> Finding:
    return default_kb().finding(
        rule,
        module=module,
        location=CodeLocation(path=path, line=1),
        evidence=Evidence(snippet=f"code in {path}"),
        severity=severity,  # type: ignore[arg-type]
    )


def test_code_findings_in_tests_are_info_but_secrets_are_not() -> None:
    out = background_code(
        [
            _finding("SAST-SQLI-001", "tests/test_db.py", "sast"),
            _finding("SAST-SQLI-001", "app/db.py", "sast"),
            _finding("SECRET-CLOUD-001", "tests/fixtures/keys.py", "secrets", "critical"),
        ]
    )
    by_path = {f.location.path: f for f in out}  # type: ignore[union-attr]
    demoted = by_path["tests/test_db.py"]
    assert demoted.severity == "info"
    assert demoted.evidence.extra["background"] == "test"
    assert demoted.evidence.extra["original_severity"] == "high"
    assert by_path["app/db.py"].severity == "high"
    assert by_path["tests/fixtures/keys.py"].severity == "critical"
    # the id does not change: suppressions keep working
    assert demoted.id == _finding("SAST-SQLI-001", "tests/test_db.py", "sast").id


def test_only_changed_keeps_code_findings_in_changed_files() -> None:
    findings = [
        _finding("SAST-SQLI-001", "a.py", "sast"),
        _finding("SAST-SQLI-001", "b.py", "sast"),
    ]
    assert [f.location.path for f in only_changed(findings, {"b.py"})] == ["b.py"]  # type: ignore[union-attr]
    assert len(only_changed(findings, None)) == 2


# ------------------------------------------------------------------ git


@pytest.mark.parametrize("ref", ["-x", "--upload-pack=evil", "main;rm -rf /", "a b", "x" * 300, ""])
def test_unsafe_git_refs_are_rejected(ref: str) -> None:
    with pytest.raises(GitError):
        check_ref(ref)
    with pytest.raises(ValidationError):
        ScanConfig(target=Target(kind=TargetKind.FOLDER, value="."), changed_since=ref or "-")


@pytest.mark.parametrize("ref", ["main", "origin/main", "HEAD~3", "v1.2.0", "a1b2c3d", "HEAD^"])
def test_ordinary_git_refs_are_accepted(ref: str) -> None:
    assert check_ref(ref) == ref


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_revision_and_changed_files(tmp_path: Path) -> None:
    def git(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(tmp_path), "-c", "user.name=t", "-c", "user.email=t@example.test",
             "-c", "commit.gpgsign=false", *args],
            check=True, capture_output=True,
        )  # fmt: skip

    git("init", "-q")
    (tmp_path / "a.py").write_text("a = 1\n")
    (tmp_path / "b.py").write_text("b = 1\n")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    rev = asyncio.run(revision(tmp_path))
    assert rev is not None
    assert len(rev.commit) == 40
    assert rev.dirty is False
    (tmp_path / "b.py").write_text("b = 2\n")
    (tmp_path / "c.py").write_text("c = 1\n")
    assert asyncio.run(changed_files(tmp_path, "HEAD")) == {"b.py", "c.py"}
    rev = asyncio.run(revision(tmp_path))
    assert rev is not None
    assert rev.dirty is True
    with pytest.raises(GitError):
        asyncio.run(changed_files(tmp_path, "no-such-branch"))


def test_revision_of_a_plain_folder_is_none(tmp_path: Path) -> None:
    assert asyncio.run(revision(tmp_path)) is None


# ------------------------------------------------------------------ report folder


def test_report_folder_created_by_us_is_git_ignored(tmp_path: Path) -> None:
    report: dict[str, object] = {"scan_id": "x", "language": "en", "findings": []}
    new_dir = tmp_path / "reports"
    write_outputs(report, new_dir, ["json"])
    assert (new_dir / ".gitignore").read_text(encoding="utf-8").splitlines()[-1] == "*"
    existing = tmp_path / "project"
    existing.mkdir()
    write_outputs(report, existing, ["json"])
    assert not (existing / ".gitignore").exists()  # never touch a folder we did not create


# ------------------------------------------------------------------ attack surface


def _src(name: str, text: str, language: str) -> SourceFile:
    return SourceFile(root=Path(), path=Path(name), text=text, language=language)


def test_flask_and_fastapi_routes() -> None:
    code = """
from flask import Flask
app = Flask(__name__)

@app.route("/admin/users", methods=["POST", "DELETE"])
@login_required
def users(): ...

@app.post("/api/settings")
def settings(): ...

@app.route("/login", methods=["POST"])
def login(): ...

@router.put("/items/{id}")
async def put_item(id: int, user = Depends(get_current_user)): ...
"""
    routes = extract_routes([_src("app.py", code, "python")])
    got = {(r.method, r.path): (r.guard, r.needs_review) for r in routes}
    assert got[("POST", "/admin/users")] == ("yes", False)
    assert got[("DELETE", "/admin/users")] == ("yes", False)
    assert got[("POST", "/api/settings")] == ("no", True)
    assert got[("POST", "/login")] == ("no", False)  # public by design
    assert got[("PUT", "/items/{id}")] == ("yes", False)
    assert summarise(routes) == {"total": 5, "state_changing": 5, "needs_review": 1}


def test_express_routes() -> None:
    code = """
router.get('/public', (req, res) => res.send('ok'));
router.post('/orders', requireAuth, async (req, res) => {});
app.delete("/orders/:id", (req, res) => {});
"""
    routes = {
        (r.method, r.path): r.guard for r in extract_routes([_src("r.js", code, "javascript")])
    }
    assert routes == {
        ("GET", "/public"): "no",
        ("POST", "/orders"): "yes",
        ("DELETE", "/orders/:id"): "no",
    }
    guarded_globally = "app.use(authMiddleware);\n" + code
    routes2 = extract_routes([_src("r.js", guarded_globally, "javascript")])
    assert {r.guard for r in routes2 if r.path == "/public"} == {"unknown"}


def test_django_urls() -> None:
    code = 'urlpatterns = [\n    path("api/orders/", views.orders),\n    path("admin/", login_required(views.admin)),\n]\n'
    routes = {r.path: r.guard for r in extract_routes([_src("urls.py", code, "python")])}
    assert routes == {"/api/orders/": "unknown", "/admin/": "yes"}


# ------------------------------------------------------------------ example keys


def _secret_hits(rel: str, text: str) -> list[tuple[str, str | None, str, bool]]:
    from secscope.analysis.secret_scan import scan_secrets  # noqa: PLC0415

    file = SourceFile(root=Path(), path=Path(rel), text=text, language="python")
    return [(h.rule_id, h.severity, h.confidence, h.example) for h in scan_secrets(file)]


def test_documented_example_key_in_tests_is_information() -> None:
    hits = _secret_hits("tests/test_aws.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert hits == [("SECRET-CLOUD-001", "info", "low", True)]


def test_example_key_in_app_code_is_reported_with_low_confidence() -> None:
    hits = _secret_hits("app/settings.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert [(r, c, e) for r, _s, c, e in hits] == [("SECRET-CLOUD-001", "low", True)]
    assert hits[0][1] == "low"


def test_real_looking_key_in_a_fixture_keeps_its_severity() -> None:
    hits = _secret_hits("fixtures/app/config.py", 'KEY = "AKIA\x5a5YQ7Q3XJ2KQ7W4P"\n')
    assert [(r, s, e) for r, s, _c, e in hits] == [("SECRET-CLOUD-001", None, False)]


# ------------------------------------------------------------------ dependency dirs


def test_intake_skips_dependency_dirs(tmp_path: Path) -> None:
    # .venv/node_modules etc. must never reach the copied tree: external tools (gitleaks,
    # Semgrep) would otherwise scan installed third-party code and flood the report.
    project = tmp_path / "p"
    (project / "app").mkdir(parents=True)
    (project / "app" / "main.py").write_text("x = 1\n")
    for dep in (".venv", "node_modules", ".git", "__pycache__"):
        (project / dep).mkdir()
        (project / dep / "secret.py").write_text("API_KEY = 'AKIA\x5a5YQ7Q3XJ2KQ7W4P'\n")
    (project / "node_modules" / "left-pad").mkdir()
    (project / "node_modules" / "left-pad" / "index.js").write_text("x\n")

    report = prepare_source(project, tmp_path / "work")

    assert (report.root / "app" / "main.py").is_file()
    for dep in (".venv", "node_modules", ".git", "__pycache__"):
        assert not (report.root / dep).exists(), f"{dep} should not be copied"
    assert ".venv" in report.dependency_dirs
    assert "node_modules" in report.dependency_dirs
    # the fake key inside node_modules is never seen, so it is never a finding
    assert report.files == 1


# ------------------------------------------------------------------ dependencies (pyproject, venv)


def test_legit_near_neighbours_are_not_typosquats() -> None:
    from secscope.analysis.deps import Inventory, Package, typosquat_candidates  # noqa: PLC0415

    inv = Inventory(
        packages=[
            Package("PyPI", "psycopg", "3.3.6", "pyproject.toml"),
            Package("PyPI", "httpx2", "2.13.1", "pyproject.toml"),
            Package("PyPI", "reqeusts", "1.0", "pyproject.toml"),  # a real-looking typo
        ]
    )
    flagged = {p.name for p, _ in typosquat_candidates(inv)}
    assert flagged == {"reqeusts"}


def test_pyproject_dependencies_are_read(tmp_path: Path) -> None:
    from secscope.analysis.deps import build_inventory  # noqa: PLC0415

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["fastapi>=0.115", "pyjwt==2.4.0",'
        " \"psycopg[binary]>=3.2; python_version>'3.8'\"]\n"
        '[dependency-groups]\ndev = ["pytest>=8"]\n',
        encoding="utf-8",
    )
    inv = build_inventory(tmp_path)
    assert inv.manifests == ["pyproject.toml"]
    assert [(p.name, p.version) for p in inv.packages] == [("pyjwt", "2.4.0")]  # only exact pins
    assert {"fastapi", "pyjwt", "psycopg", "pytest"} <= set(inv.declared)
    assert inv.project_name == "demo"


def test_tool_only_pyproject_is_not_a_manifest(tmp_path: Path) -> None:
    from secscope.analysis.deps import build_inventory  # noqa: PLC0415

    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 100\n", encoding="utf-8")
    assert build_inventory(tmp_path).manifests == []


def test_uv_lock_versions_skip_the_project_itself(tmp_path: Path) -> None:
    from secscope.analysis.deps import build_inventory  # noqa: PLC0415

    (tmp_path / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "demo"\nversion = "0.1.0"\nsource = { editable = "." }\n'
        '[[package]]\nname = "flask"\nversion = "2.2.2"\nsource = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    inv = build_inventory(tmp_path)
    assert [(p.name, p.version) for p in inv.packages] == [("flask", "2.2.2")]


def _fake_venv(project: Path, packages: dict[str, str]) -> None:
    site = project / ".venv" / "Lib" / "site-packages"
    site.mkdir(parents=True)
    (project / ".venv" / "pyvenv.cfg").write_text("home = x\n", encoding="utf-8")
    for name, version in packages.items():
        dist = site / f"{name}-{version}.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nlong description\n",
            encoding="utf-8",
        )


def test_unpinned_dependencies_take_the_installed_version(tmp_path: Path) -> None:
    from secscope.analysis.deps import add_installed, build_inventory  # noqa: PLC0415

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["fastapi>=0.115"]\n', encoding="utf-8"
    )
    _fake_venv(tmp_path, {"fastapi": "0.115.6", "starlette": "0.41.3", "demo": "0.1.0"})
    inv = build_inventory(tmp_path)
    assert inv.packages == []
    assert add_installed(inv, tmp_path) == ".venv"
    got = {p.name: (p.version, p.direct, p.installed) for p in inv.packages}
    assert got == {
        "fastapi": ("0.115.6", True, True),  # declared -> direct
        "starlette": ("0.41.3", False, True),  # transitive
    }  # the project itself ("demo") is not a dependency
    assert inv.unpinned == []  # resolved


def test_no_venv_leaves_unpinned_dependencies_unresolved(tmp_path: Path) -> None:
    from secscope.analysis.deps import add_installed, build_inventory  # noqa: PLC0415

    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["fastapi>=0.115"]\n', encoding="utf-8"
    )
    inv = build_inventory(tmp_path)
    assert add_installed(inv, tmp_path) is None
    assert inv.packages == []
    assert inv.unpinned == ["pyproject.toml: fastapi>=0.115"]


# ------------------------------------------------------------------ git-ignored secrets


def test_secrets_in_gitignored_files_are_info_but_history_is_not(tmp_path: Path) -> None:
    from secscope.core.scan import gitignored_secrets  # noqa: PLC0415

    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    local = _finding("SECRET-DBURL-001", path=".env", module="secrets")
    committed = _finding("SECRET-DBURL-001", path="config.py", module="secrets")
    history = _finding("SECRET-HISTORY-001", path=".env", module="secrets")
    out = {
        (f.rule_id, f.location.path): f
        for f in gitignored_secrets([local, committed, history], tmp_path)
        if isinstance(f.location, CodeLocation)
    }
    assert out[("SECRET-DBURL-001", ".env")].severity == "info"
    assert out[("SECRET-DBURL-001", ".env")].evidence.extra["gitignored"] == "yes"
    assert out[("SECRET-DBURL-001", "config.py")].severity == "high"
    assert out[("SECRET-HISTORY-001", ".env")].severity != "info"


def test_without_gitignore_nothing_is_demoted(tmp_path: Path) -> None:
    from secscope.core.scan import gitignored_secrets  # noqa: PLC0415

    f = _finding("SECRET-DBURL-001", path=".env", module="secrets")
    assert gitignored_secrets([f], tmp_path)[0].severity == "high"
