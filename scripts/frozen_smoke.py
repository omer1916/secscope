"""Smoke-test a PyInstaller build the way the desktop UI uses it.

    uv run python scripts/frozen_smoke.py [dist/SecScope]

Starts ``secscope.exe worker`` (as SecScopeApp does), sends a StartCommand over stdin and
waits for ``scan.finished``: one static scan of fixtures/vuln-flask and one SEO scan of
fixtures/static-seo-good (which runs the bundled static server). Exits non-zero on failure.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

from secscope.core.config import ScanConfig, Settings, Target, TargetKind
from secscope.core.events import ScanFinished, StartCommand, decode_event, encode
from secscope.core.session import new_scan_id

ROOT = Path(__file__).resolve().parents[1]


def run(exe: Path, config: ScanConfig, modules: list[str], data_dir: Path) -> ScanFinished:
    proc = subprocess.Popen(  # noqa: S603 - our own build, fixed arguments
        [str(exe), "worker"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    command = StartCommand(
        config=config.model_dump(mode="json"),
        settings=Settings(data_dir=data_dir).model_dump(mode="json"),
        scan_id=new_scan_id(),
        modules=modules,
    )
    proc.stdin.write((encode(command) + "\n").encode("utf-8"))
    proc.stdin.flush()
    deadline = time.monotonic() + 300
    finished: ScanFinished | None = None
    counts: dict[str, int] = {}
    for raw in proc.stdout:
        event = decode_event(raw)
        counts[event.type] = counts.get(event.type, 0) + 1
        if isinstance(event, ScanFinished):
            finished = event
            break
        if time.monotonic() > deadline:
            break
    proc.stdin.close()
    proc.wait(timeout=30)
    if finished is None:
        err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        raise SystemExit(f"no scan.finished; events={counts}\n{err[-2000:]}")
    print(f"  events={counts}")
    return finished


def main() -> int:
    dist = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / "SecScope"
    exe = dist / ("secscope.exe" if sys.platform == "win32" else "secscope")
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp)
        static = ScanConfig(
            target=Target(kind=TargetKind.FOLDER, value=str(ROOT / "fixtures" / "vuln-flask"))
        )
        done = run(exe, static, ["sast", "secrets", "config_audit"], data)
        print(f"static: {done.status} in {done.duration_s:.1f}s")
        assert done.status == "completed", done
        seo = ScanConfig(
            target=Target(kind=TargetKind.FOLDER, value=str(ROOT / "fixtures" / "static-seo-good")),
            scope_statement_accepted=True,
            public_url="https://www.example.com",
        )
        done = run(exe, seo, ["seo"], data)
        print(f"seo: {done.status} in {done.duration_s:.1f}s")
        assert done.status == "completed", done
    print("frozen smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
