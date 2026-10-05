from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path

import pytest

from secscope.core.archive import ExtractLimits
from secscope.core.fingerprint import fingerprint
from secscope.core.intake import (
    IntakeError,
    iter_source_files,
    make_run_copy,
    prepare_source,
    remove_tree,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.mark.parametrize(
    ("fixture", "kind", "stack", "dev"),
    [
        ("vuln-flask", "server", "flask", True),
        ("clean-flask", "server", "flask", True),
        ("vuln-express", "server", "express", False),
        ("clean-express", "server", "express", False),
        ("vuln-php", "server", "php", True),
        ("static-seo-bad", "static", "static", False),
        ("static-seo-good", "static", "static", False),
        ("slow-app", "server", "python", False),
    ],
)
def test_fixture_fingerprints(fixture: str, kind: str, stack: str, dev: bool) -> None:
    fp = fingerprint(FIXTURES / fixture)
    assert (fp.kind, fp.stack, fp.dev_server) == (kind, stack, dev)
    if kind == "server":
        assert fp.run_command


def test_flask_details() -> None:
    fp = fingerprint(FIXTURES / "vuln-flask")
    assert fp.install_command == ["{python}", "-m", "pip", "install", "-r", "requirements.txt"]
    assert "{port}" in fp.run_command  # type: ignore[operator]
    assert ".env" in fp.files
    assert fp.stack_family == "flask"


def test_express_details() -> None:
    fp = fingerprint(FIXTURES / "vuln-express")
    assert fp.install_command == ["npm", "ci"]
    assert fp.run_command == ["npm", "start"]
    assert fp.env["PORT"] == "{port}"


def test_static_root_detection(tmp_path: Path) -> None:
    (tmp_path / "public").mkdir()
    (tmp_path / "public" / "index.html").write_text("<html></html>")
    fp = fingerprint(tmp_path)
    assert (fp.kind, fp.static_root) == ("static", "public")


def test_unknown_project(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hi")
    assert fingerprint(tmp_path).kind == "unknown"


@pytest.mark.parametrize(
    ("files", "stack"),
    [
        ({"manage.py": "", "requirements.txt": "Django==5.0\n"}, "django"),
        (
            {
                "main.py": "from fastapi import FastAPI\napi = FastAPI()\n",
                "requirements.txt": "fastapi\n",
            },
            "fastapi",
        ),
        (
            {"package.json": '{"dependencies": {"next": "15"}, "scripts": {"dev": "next dev"}}'},
            "next",
        ),
        (
            {"package.json": '{"devDependencies": {"vite": "5"}, "scripts": {"dev": "vite"}}'},
            "vite",
        ),
        ({"artisan": "", "composer.json": "{}"}, "laravel"),
        (
            {"pyproject.toml": '[project]\nname="x"\ndependencies=["Flask>=3"]\n', "app.py": ""},
            "flask",
        ),
    ],
)
def test_framework_detection(tmp_path: Path, files: dict[str, str], stack: str) -> None:
    for name, content in files.items():
        (tmp_path / name).write_text(content)
    assert fingerprint(tmp_path).stack == stack


def test_fastapi_entry_point(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napi = FastAPI()\n")
    (tmp_path / "requirements.txt").write_text("fastapi\nuvicorn\n")
    fp = fingerprint(tmp_path)
    assert fp.run_command is not None
    assert "main:api" in fp.run_command


# ------------------------------------------------------------------ intake


def test_folder_copy_is_read_only_and_original_untouched(tmp_path: Path) -> None:
    project = tmp_path / "my project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "app.py").write_text("print(1)")
    before = (project / "src" / "app.py").stat().st_mtime_ns
    report = prepare_source(project, tmp_path / "work")
    copied = report.root / "src" / "app.py"
    assert copied.read_text() == "print(1)"
    assert not os.access(copied, os.W_OK)
    assert (project / "src" / "app.py").stat().st_mtime_ns == before
    remove_tree(tmp_path / "work")  # read-only files must still be removable
    assert not (tmp_path / "work").exists()


def test_symlinks_are_skipped(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "a.txt").write_text("a")
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET")
    try:
        (project / "link.txt").symlink_to(secret)
    except OSError:
        pytest.skip("symlinks need extra privileges on this platform")
    report = prepare_source(project, tmp_path / "work")
    assert report.skipped_links == ["link.txt"]
    assert not (report.root / "link.txt").exists()


def test_folder_limits(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    for i in range(5):
        (project / f"f{i}").write_text("x")
    with pytest.raises(IntakeError, match="files"):
        prepare_source(project, tmp_path / "work", ExtractLimits(max_files=3))
    assert not (tmp_path / "work" / "src").exists()


def test_archive_with_single_top_folder(tmp_path: Path) -> None:
    archive = tmp_path / "proj.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("myapp-main/index.html", "<html></html>")
        zf.writestr("myapp-main/css/site.css", "body{}")
    report = prepare_source(archive, tmp_path / "work")
    assert report.root.name == "myapp-main"
    assert fingerprint(report.root).kind == "static"


def test_unsafe_archive_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../evil.txt", "x")
    with pytest.raises(IntakeError, match="unsafe"):
        prepare_source(archive, tmp_path / "work")


def test_not_a_project(tmp_path: Path) -> None:
    f = tmp_path / "file.txt"
    f.write_text("x")
    with pytest.raises(IntakeError):
        prepare_source(f, tmp_path / "work")


def test_run_copy_is_writable(tmp_path: Path) -> None:
    project = tmp_path / "p"
    project.mkdir()
    (project / "db.sqlite").write_bytes(b"x")
    report = prepare_source(project, tmp_path / "work")
    run_dir = make_run_copy(report.root, tmp_path / "work")
    target = run_dir / "db.sqlite"
    assert target.stat().st_mode & stat.S_IWRITE
    target.write_bytes(b"changed")
    assert (report.root / "db.sqlite").read_bytes() == b"x"
    remove_tree(tmp_path / "work")


def test_iter_source_files_skips_dependencies(tmp_path: Path) -> None:
    for rel in ("app.js", "node_modules/x/index.js", ".git/config", "lib/util.js", ".venv/a.py"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    names = {p.relative_to(tmp_path).as_posix() for p in iter_source_files(tmp_path)}
    assert names == {"app.js", "lib/util.js"}
    all_names = {
        p.relative_to(tmp_path).as_posix()
        for p in iter_source_files(tmp_path, include_dependencies=True)
    }
    assert "node_modules/x/index.js" in all_names
