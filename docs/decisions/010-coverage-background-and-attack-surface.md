# ADR-010: Coverage accounting, test/fixture background, attack surface, diff mode

- Status: accepted
- Date: 2026-10-06

## Context

A review of other security tools' public designs (Anthropic's claude-security README,
anthropics/claude-code-security-review, Trail of Bits skills; see ADR-003 for licences — ideas
only, no code or text copied) showed gaps in how SecScope accounts for what it scanned and in
how much noise test code produces.

## Decisions

1. **Coverage section.** Every report states the files examined (by language), test/fixture
   files, user exclusions, dependency/build folders and symbolic links that were not followed.
   A clean result must say what was examined (`core/coverage.py`).
2. **Exclusions** (`--exclude`, wizard field) are applied when the project is copied, so
   every engine (native, Semgrep, Bandit, Trivy...) sees the same tree. Excluded files are also
   not run. Patterns are gitignore-like; `..` is rejected.
3. **Test, fixture, example and generated code is background.** Code findings there are
   shown as `info` (visible, not scored) with the original severity kept in the evidence.
   Secrets are *not* demoted: a real key committed in a fixture is a leak. Documented example
   keys (values saying EXAMPLE, dummy, fake...) are `info` in tests and `low` elsewhere.
4. **Revision stamp.** For folder scans in a git work tree the report records the commit,
   branch and whether uncommitted changes were scanned.
5. **Report folders are git-ignored** when SecScope creates them (`*` in `.gitignore`), so a
   stray `git add .` does not commit reports. Existing folders are never touched.
6. **Attack-surface inventory.** Flask/FastAPI, Express and Django routes with the
   authorisation guard visible on each; state-changing routes without one (and not sign-in
   style) are highlighted for review. It is an inventory, not findings: guards applied
   elsewhere cannot be seen statically. Tests/fixtures are excluded.
7. **Diff mode** (`--changed-since <git ref>`): only code findings in files changed since the
   reference (committed, staged, unstaged, untracked) are reported — for CI on pull requests.
   The reference is validated (never an option for git: refs starting with `-` are refused).

## Rejected

- LLM-based verification and patch generation: SecScope is deterministic and offline.
- Hard exclusion of whole vulnerability classes (DoS, open redirect...) as in
  claude-code-security-review: those filters suit LLM findings; SecScope's rules are precise.
