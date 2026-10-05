"""Tool and advisory-database downloads (ADR-006) — the second sanctioned network path.

Rules (enforced here, tested in tests/unit/test_downloader.py):
* only on explicit user action (``secscope tools install`` / the UI's install button,
  advisory DB "update"), never during a scan;
* HTTPS only, and every hop (including redirects) must be on the manifest's
  ``download_hosts`` allow-list;
* size cap; SHA-256 verified before anything is unpacked or made executable;
* archives are unpacked with the safe extractor.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from secscope.core.archive import ExtractLimits, safe_extract
from secscope.core.toolmgr import Download, ToolManager, platform_key

MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024
MAX_REDIRECTS = 5
Progress = Callable[[int, int | None], None]


class DownloadError(RuntimeError):
    pass


def _check_url(url: str, allowed_hosts: frozenset[str]) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise DownloadError(f"refusing non-HTTPS download: {url}")
    if parts.hostname is None or parts.hostname.lower() not in allowed_hosts:
        raise DownloadError(f"host {parts.hostname!r} is not on the download allow-list")
    if parts.username or parts.password:
        raise DownloadError("credentials in download URLs are not allowed")


def fetch(
    url: str,
    dest: Path,
    *,
    allowed_hosts: frozenset[str],
    expected_sha256: str | None,
    progress: Progress | None = None,
    transport: httpx.BaseTransport | None = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> str:
    """Download ``url`` to ``dest`` following allow-listed redirects; return the SHA-256."""
    digest = hashlib.sha256()
    with httpx.Client(
        transport=transport, follow_redirects=False, timeout=60, trust_env=False
    ) as client:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            _check_url(current, allowed_hosts)
            with client.stream("GET", current) as response:
                if response.is_redirect:
                    location = response.headers.get("location", "")
                    current = str(response.url.join(location))
                    continue
                if response.status_code != 200:
                    raise DownloadError(f"HTTP {response.status_code} for {current}")
                total = int(response.headers.get("content-length", "0")) or None
                if total is not None and total > max_bytes:
                    raise DownloadError(f"download exceeds the size limit ({total} bytes)")
                received = 0
                with dest.open("wb") as fh:
                    for chunk in response.iter_bytes(1024 * 256):
                        received += len(chunk)
                        if received > max_bytes:
                            raise DownloadError("download exceeded the size limit")
                        digest.update(chunk)
                        fh.write(chunk)
                        if progress is not None:
                            progress(received, total)
                break
        else:
            raise DownloadError("too many redirects")
    actual = digest.hexdigest()
    if expected_sha256 is not None and actual != expected_sha256.lower():
        dest.unlink(missing_ok=True)
        raise DownloadError(f"SHA-256 mismatch: expected {expected_sha256}, got {actual}")
    return actual


def install_tool(
    manager: ToolManager,
    name: str,
    *,
    progress: Progress | None = None,
    transport: httpx.BaseTransport | None = None,
) -> Path:
    """Download, verify and unpack the pinned version of ``name``; return the binary path."""
    spec = manager.spec(name)
    key = platform_key()
    download: Download | None = spec.downloads.get(key)
    if spec.version is None or download is None:
        raise DownloadError(
            f"{name} has no pinned download for {key}; install it manually ({spec.homepage})"
        )
    target = manager.managed_path(spec)
    assert target is not None
    version_dir = manager.tools_dir / spec.name / spec.version
    with tempfile.TemporaryDirectory(prefix="secscope-dl-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / Path(urlsplit(download.url).path).name
        fetch(
            download.url,
            archive,
            allowed_hosts=manager.manifest.download_hosts,
            expected_sha256=download.sha256,
            progress=progress,
            transport=transport,
        )
        staging = tmp_path / "unpacked"
        if download.archive == "none":
            staging.mkdir()
            shutil.copy2(archive, staging / download.binary)
        else:
            safe_extract(
                archive, staging, ExtractLimits(max_total_bytes=2 * 1024**3, ratio_min_bytes=10**9)
            )
        binary = staging / Path(*download.binary.split("/"))
        if not binary.is_file():
            raise DownloadError(f"{download.binary} not found in the downloaded archive")
        if version_dir.exists():
            shutil.rmtree(version_dir)
        shutil.copytree(staging, version_dir)
    if os.name != "nt":
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    manager.refresh()
    return target


def verify_tool(manager: ToolManager, name: str) -> bool:
    """Re-run the version check of a managed tool (the archive hash was verified at install)."""
    manager.refresh()
    status = manager.status(name)
    return status.available and status.source == "managed"
