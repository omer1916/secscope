"""Record real external-tool outputs on the fixtures as golden files (tool contract tests).

Re-run after bumping a tool version in tools/manifest.toml:

    uv run python scripts/record_golden.py

Absolute fixture paths are replaced by ``{ROOT}``; secrets are redacted by the tools themselves
(gitleaks --redact) or never printed (semgrep/bandit show code lines only via our own reader).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from secscope.core.advisories import TRIVY_PRIVACY_FLAGS, osv_env, trivy_cache
from secscope.core.config import Settings
from secscope.core.process import python_tool_command, run_capture
from secscope.core.resources import data_path
from secscope.core.session import tool_manager

REPO = Path(__file__).resolve().parents[1]
GOLDEN = REPO / "tests" / "golden"
FIXTURES = ["vuln-flask", "vuln-express"]


def _scrub(text: str, root: Path) -> str:
    for variant in {str(root), root.as_posix(), str(root).replace("\\", "\\\\")}:
        text = text.replace(variant, "{ROOT}")
    return text


async def main() -> int:
    settings = Settings()
    tools = tool_manager(settings)
    for fixture in FIXTURES:
        root = REPO / "fixtures" / fixture
        runs: dict[str, list[str]] = {
            "semgrep": [str(tools.path("semgrep")), "scan", "--config", str(data_path("rules") / "semgrep"), "--json",
                        "--metrics=off", "--disable-version-check", "--no-rewrite-rule-ids", "--no-git-ignore", "--quiet", str(root)],
            "bandit": [*python_tool_command("bandit"), "-r", str(root), "-f", "json", "-q"],
            "gitleaks": [str(tools.path("gitleaks")), "dir", str(root), "--redact=100", "--no-banner", "-f", "json",
                         "-r", "-", "--exit-code", "0", "-l", "error"],
            "trivy": [str(tools.path("trivy")), "fs", str(root), "--scanners", "vuln", "--format", "json", "--list-all-pkgs=false",
                      "--cache-dir", str(trivy_cache(settings.data_dir)), "--skip-db-update", "--skip-java-db-update",
                      "--skip-check-update", "--offline-scan", *TRIVY_PRIVACY_FLAGS, "-q"],
            "osv-scanner": [str(tools.path("osv-scanner")), "scan", "source", "--offline", "--offline-vulnerabilities",
                            "-r", str(root), "--format", "json", "--verbosity", "error"],
        }  # fmt: skip
        for tool, argv in runs.items():
            if tool == "bandit" and fixture != "vuln-flask":
                continue
            env = osv_env(settings.data_dir) if tool == "osv-scanner" else None
            run = await run_capture(argv, cwd=root, env=env, timeout=900)
            data = json.loads(run.stdout)
            if tool == "semgrep":
                data.pop("time", None)
            out = GOLDEN / tool / f"{fixture}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                _scrub(json.dumps(data, indent=1, ensure_ascii=False), root) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            print(f"{out.relative_to(REPO)} ({run.returncode})")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
