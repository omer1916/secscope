"""ADR-006: the download path only talks HTTPS to allow-listed hosts and verifies SHA-256."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

import httpx
import pytest

from secscope.core.downloader import DownloadError, fetch, install_tool
from secscope.core.toolmgr import Manifest, ToolManager, platform_key

ALLOWED = frozenset({"github.com", "objects.githubusercontent.com"})
PAYLOAD = b"binary-content"
SHA = hashlib.sha256(PAYLOAD).hexdigest()


def transport(routes: dict[str, httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(lambda req: routes.get(str(req.url), httpx.Response(404)))


def test_fetch_follows_allowlisted_redirect(tmp_path: Path) -> None:
    t = transport(
        {
            "https://github.com/a/b": httpx.Response(
                302, headers={"Location": "https://objects.githubusercontent.com/x"}
            ),
            "https://objects.githubusercontent.com/x": httpx.Response(200, content=PAYLOAD),
        }
    )
    assert (
        fetch(
            "https://github.com/a/b",
            tmp_path / "f",
            allowed_hosts=ALLOWED,
            expected_sha256=SHA,
            transport=t,
        )
        == SHA
    )
    assert (tmp_path / "f").read_bytes() == PAYLOAD


def test_redirect_to_unlisted_host_rejected(tmp_path: Path) -> None:
    t = transport(
        {
            "https://github.com/a/b": httpx.Response(
                302, headers={"Location": "https://evil.example/x"}
            )
        }
    )
    with pytest.raises(DownloadError, match="allow-list"):
        fetch(
            "https://github.com/a/b",
            tmp_path / "f",
            allowed_hosts=ALLOWED,
            expected_sha256=SHA,
            transport=t,
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a",
        "https://evil.example/a",
        "https://user:pw@github.com/a",
        "ftp://github.com/a",
    ],
)
def test_bad_urls_rejected(tmp_path: Path, url: str) -> None:
    with pytest.raises(DownloadError):
        fetch(
            url, tmp_path / "f", allowed_hosts=ALLOWED, expected_sha256=SHA, transport=transport({})
        )


def test_checksum_mismatch_deletes_file(tmp_path: Path) -> None:
    t = transport({"https://github.com/a": httpx.Response(200, content=b"tampered")})
    with pytest.raises(DownloadError, match="SHA-256 mismatch"):
        fetch(
            "https://github.com/a",
            tmp_path / "f",
            allowed_hosts=ALLOWED,
            expected_sha256=SHA,
            transport=t,
        )
    assert not (tmp_path / "f").exists()


def test_size_limit(tmp_path: Path) -> None:
    t = transport({"https://github.com/a": httpx.Response(200, content=b"x" * 1000)})
    with pytest.raises(DownloadError, match="size"):
        fetch(
            "https://github.com/a",
            tmp_path / "f",
            allowed_hosts=ALLOWED,
            expected_sha256=None,
            transport=t,
            max_bytes=100,
        )


def test_redirect_loop(tmp_path: Path) -> None:
    t = transport(
        {"https://github.com/a": httpx.Response(302, headers={"Location": "https://github.com/a"})}
    )
    with pytest.raises(DownloadError, match="redirects"):
        fetch(
            "https://github.com/a",
            tmp_path / "f",
            allowed_hosts=ALLOWED,
            expected_sha256=None,
            transport=t,
        )


def test_install_tool_end_to_end(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bin/fake-tool", "#!/bin/sh\necho fake 1.2.3\n")
    archive = buf.getvalue()
    manifest = Manifest.from_dict(
        {
            "schema": 1,
            "download_hosts": {"allowed": ["github.com"]},
            "tools": {
                "fake": {
                    "kind": "binary",
                    "version": "1.2.3",
                    "commands": ["fake-tool"],
                    "version_args": ["--version"],
                    "version_regex": r"fake (\d+\.\d+\.\d+)",
                    "min_version": "1.0.0",
                    "install_hint": {"tr": "kur", "en": "install"},
                    "downloads": {
                        platform_key(): {
                            "url": "https://github.com/x/fake.zip",
                            "sha256": hashlib.sha256(archive).hexdigest(),
                            "archive": "zip",
                            "binary": "bin/fake-tool",
                        }
                    },
                }
            },
        }
    )
    mgr = ToolManager(
        manifest,
        tmp_path / "tools",
        version_runner=lambda _argv: "fake 1.2.3",
        which=lambda _c: None,
    )
    path = install_tool(
        mgr,
        "fake",
        transport=transport(
            {"https://github.com/x/fake.zip": httpx.Response(200, content=archive)}
        ),
    )
    assert path == tmp_path / "tools" / "fake" / "1.2.3" / "bin" / "fake-tool"
    assert mgr.status("fake").source == "managed"


def test_install_without_pinned_download(tmp_path: Path) -> None:
    mgr = ToolManager(Manifest.load(), tmp_path)
    with pytest.raises(DownloadError, match="no pinned download"):
        install_tool(mgr, "java")
