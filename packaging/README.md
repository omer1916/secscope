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

Verified on Windows 10 (2026-10-06): `secscope.exe --version`, `modules`, `tools list`, a static
scan with Bandit running in-process, an SEO scan using the bundled static server, and
`SecScopeApp.exe` start-up.

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
