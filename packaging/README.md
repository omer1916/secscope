# Packaging

## Build (one-folder)

```bash
uv sync
uv run pyinstaller packaging/pyinstaller.spec --noconfirm
```

Output `dist/SecScope/`:

| File | Purpose |
|---|---|
| `SecScopeApp(.exe)` | desktop UI (windowed) |
| `secscope(.exe)` | CLI; also the internal sub-programs the UI starts: `worker`, `static-server`, `run-python-tool <module>` |
| `_internal/` | Python runtime, Qt (as replaceable shared libraries — LGPL), `secscope/_data/{rules,remediation,tools}` |

Both executables carry the app icon (`src/secscope/ui/assets/secscope.ico`, drawn by
`scripts/make_icon.py`) and Windows version information (Explorer > Properties > Details) taken
from `src/secscope/__about__.py`.

## Smoke test of a build

```bash
uv run python scripts/frozen_smoke.py dist/SecScope
```

Starts `secscope.exe worker` exactly like the desktop app does, runs a static scan of
`fixtures/vuln-flask` and an SEO scan of `fixtures/static-seo-good` (bundled static server) and
fails unless both finish. Verified on Windows 10 (2026-10-06, 0.1.0): smoke test passed,
`SecScopeApp.exe` starts with its own taskbar icon (~140 MB RAM), the window fits a 125 %-scaled
1920×1080 screen.

Large external tools (Trivy, gitleaks, osv-scanner, Semgrep, Chromium) are **not** bundled; the
Tool Manager downloads them with SHA-256 verification.

## Signing and installers

- **Windows:** sign both executables with Authenticode (`signtool sign /fd SHA256 /tr <TSA> /td SHA256`).
  Without a certificate the build is unsigned and SmartScreen will warn — say so in the release notes.
  An Inno Setup script can wrap `dist/SecScope/` (not included: needs the publisher's details).
- **macOS:** codesign with a Developer ID and notarize (`xcrun notarytool`); package as `.dmg`.
- **Linux:** AppImage via `appimagetool` around `dist/SecScope/`.
- Antivirus false positives on PyInstaller builds are common: prefer signing, keep the
  one-folder layout (no self-extracting one-file exe), and check the build on VirusTotal before
  publishing.

## Offline tool bundle

Copy `%LOCALAPPDATA%\secscope\tools` (or `~/.local/share/secscope/tools`) from a connected
machine to the same place on the offline machine; the Tool Manager detects managed tools there.
The advisory databases (`trivy-cache`, `osv-db`) can be copied the same way.
