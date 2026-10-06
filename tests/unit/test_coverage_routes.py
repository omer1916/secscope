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
