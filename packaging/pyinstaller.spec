# PyInstaller one-folder build (SPEC §13). Build with:
#   uv run pyinstaller packaging/pyinstaller.spec --noconfirm
# Output: dist/SecScope/ with secscope(.exe) (CLI + internal sub-programs) and
# SecScopeApp(.exe) (desktop UI). Large external tools (Trivy, gitleaks, ...) are NOT bundled;
# the Tool Manager downloads them with SHA-256 verification on first use.
# Qt stays as separate shared libraries (one-folder) so users can replace them (LGPL).

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - provided by PyInstaller

datas = [
    *collect_data_files("secscope"),  # i18n catalogs, report template, SQL migrations
    (str(ROOT / "rules"), "secscope/_data/rules"),
    (str(ROOT / "remediation"), "secscope/_data/remediation"),
    (str(ROOT / "tools"), "secscope/_data/tools"),
    (str(ROOT / "LICENSE"), "."),
]
hiddenimports = [
    *collect_submodules("secscope"),
    *collect_submodules("bandit"),  # run in-process via "run-python-tool bandit"
    "pyqtgraph",
]

a = Analysis(  # noqa: F821
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT / "src")],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "matplotlib", "IPython", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821

cli = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="secscope",
    console=True,
    upx=False,
)
app = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SecScopeApp",
    console=False,
    upx=False,
)
coll = COLLECT(  # noqa: F821
    cli,
    app,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="SecScope",
)
