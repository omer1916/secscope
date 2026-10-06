# PyInstaller one-folder build (SPEC §13). Build with:
#   uv run pyinstaller packaging/pyinstaller.spec --noconfirm
# Output: dist/SecScope/ with secscope(.exe) (CLI + internal sub-programs) and
# SecScopeApp(.exe) (desktop UI). Large external tools (Trivy, gitleaks, ...) are NOT bundled;
# the Tool Manager downloads them with SHA-256 verification on first use.
# Qt stays as separate shared libraries (one-folder) so users can replace them (LGPL).

import re
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules
from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - provided by PyInstaller
ICON = ROOT / "src" / "secscope" / "ui" / "assets" / "secscope.ico"
ABOUT = (ROOT / "src" / "secscope" / "__about__.py").read_text(encoding="utf-8")
VERSION = re.search(r'__version__ = "([^"]+)"', ABOUT).group(1)
NUMBERS = tuple(int(x) for x in re.findall(r"\d+", VERSION)[:3]) + (0,) * 4
FILEVERS = NUMBERS[:4]


def version_info(description: str, filename: str) -> VSVersionInfo:
    """Shown in Explorer > Properties > Details."""
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=FILEVERS, prodvers=FILEVERS),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",
                        [
                            StringStruct("CompanyName", "SecScope"),
                            StringStruct("FileDescription", description),
                            StringStruct("FileVersion", VERSION),
                            StringStruct("InternalName", filename),
                            StringStruct("LegalCopyright", "Apache-2.0"),
                            StringStruct("OriginalFilename", f"{filename}.exe"),
                            StringStruct("ProductName", "SecScope"),
                            StringStruct("ProductVersion", VERSION),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )


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
    icon=str(ICON),
    version=version_info("SecScope command line", "secscope"),
)
app = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SecScopeApp",
    console=False,
    upx=False,
    icon=str(ICON),
    version=version_info("SecScope - local security and SEO checks", "SecScopeApp"),
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
