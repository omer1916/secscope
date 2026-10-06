# SecScope user guide (English)

SecScope checks **your own** web site or web app **on your own computer** before you launch it:
source-code security, secrets, vulnerable dependencies, configuration mistakes and technical SEO
for Google visibility. The result is one report with copy-paste fixes.

> Only scan projects you own. SecScope sends network traffic only to your own machine
> (localhost, 127.0.0.1, ::1); this cannot be switched off.

## 1. Installation

**Packaged build (Windows):** copy the `SecScope` folder anywhere and run `SecScopeApp.exe`.
The command line is `secscope.exe` in the same folder.

**From source:** Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run secscope-gui        # desktop app
uv run secscope --help     # command line
```

## 2. Optional tools

SecScope always runs its own engines; extra tools widen coverage:

| Tool | Adds | Install |
|---|---|---|
| Semgrep | more SAST rules (data flow) | `uv tool install semgrep` |
| gitleaks | secrets in git history | Settings > Tool manager > Install, or `secscope tools install gitleaks` |
| Trivy, osv-scanner | dependency vulnerabilities (offline database) | `secscope tools install trivy osv-scanner`, then `secscope tools update-db` |

Every download is verified against a pinned version and SHA-256. Missing tools show up as
"SKIPPED" or "reduced coverage" in the report; the scan never stops because of them.

## 3. First scan (desktop)

1. Click **New scan**.
2. **Source:** choose the project folder or archive (drag and drop works), or enter an app
   already running on `http://localhost:PORT`.
3. **Detected project:** SecScope suggests the stack (static site, Express, Flask, Django, PHP…)
   and the run command; edit if needed. The optional **public address** is used for sitemap and
   canonical checks (it is never contacted).
4. **Profile and modules:** Quick / Standard / Deep or Custom.
5. **Confirmation:** tick "This system is mine…" and press **Start scan**.

The **Live monitor** shows module progress, findings as they arrive and the log; you can pause
or cancel. When it finishes, **Results** opens.

## 4. Reading results

- **Overall score and grade (A–F)**: security 45 %, SEO 20 %, resilience 20 %, quality 10 %,
  dependencies 5 %; weights of unmeasured areas are redistributed. See `docs/scoring.md`.
- Each finding shows what, where, evidence (secrets masked), why it matters, a fix with code
  **for your stack**, and references (CWE, OWASP Top 10:2025).
- **Copy fix** puts the steps and code on the clipboard.
- Not a real problem? **Mark as false positive** — a reason is required; it is hidden in future
  scans (undo in Settings).
- **Open HTML report** opens the offline single-file report. **Export** writes HTML, JSON,
  SARIF (for IDEs/CI) and CSV.

### Visibility in Google

Google cannot crawl a local site; this section measures launch readiness and never guarantees
rankings. SecScope generates `robots.txt`, `sitemap.xml`, structured data (JSON-LD) and title
drafts — in the report and in the `patches/` folder. Your source is never modified.

## 5. History and comparison

On **History**, select two scans and press **Compare** to see new, fixed, persistent and regressed
findings and the score delta.

## 6. Command line and CI

```bash
secscope scan --path ./project --accept-scope-statement --format html,json,sarif --fail-on high
secscope report <scan-id> --format pdf
secscope diff <old-id> <new-id>
secscope suppress --rule SEO-OG-001 --reason "No social previews needed"
```

`--fail-on high` exits with code 3 when a high or critical finding exists (for CI).

```bash
secscope scan --path . --exclude docs --exclude "legacy/" --changed-since origin/main --fail-on high
```

- `--exclude` (or **Paths to exclude** in the wizard): these paths are not copied, scanned or run;
  the report's **Coverage** section lists them.
- `--changed-since`: report code findings only in files changed since this git reference (for pull
  request reviews).

### Extra report sections

- **Coverage:** how many files were examined, what was excluded, dependency folders that were not
  code-analysed. A clean result also says what was examined.
- **Test and fixture code:** code findings in `tests/`, `fixtures/`, `*.test.js` and similar are shown
  as "info" and not scored. Secrets are the exception: a real-looking key is reported at full
  severity even in a test file.
- **Attack surface:** endpoints found in the code and whether an authorisation check is visible on
  each; state-changing endpoints without one are highlighted. An inventory, not findings.
- **Commit:** for git projects, the commit the report describes (and whether uncommitted changes were
  included). Report folders SecScope creates get a `.gitignore`.

## 7. Privacy

No telemetry. Network traffic goes only to the target (localhost), tool/database downloads you
start, and — if you enable "install dependencies" — your project's package registries.

## 8. Not in this build

Active attack simulation (DAST), load/stress testing and lab Core Web Vitals are not included
(`docs/decisions/009-scope-of-this-build.md`).
