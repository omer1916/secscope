from __future__ import annotations

import http.client
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from secscope.core.snapshot import Snapshot, find_sqlite_files
from secscope.core.static_server import make_server, parse_redirects

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.fixture(scope="module")
def bad_site() -> Iterator[int]:
    server = make_server(FIXTURES / "static-seo-bad", "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def get(port: int, path: str, method: str = "GET") -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path)
    response = conn.getresponse()
    response.read()
    return response


def test_serves_files_without_server_header(bad_site: int) -> None:
    r = get(bad_site, "/about.html")
    assert r.status == 200
    assert r.getheader("Server") is None
    assert r.getheader("Content-Type") == "text/html; charset=utf-8"


def test_index_and_404(bad_site: int) -> None:
    assert get(bad_site, "/").status == 200
    assert get(bad_site, "/nope.html").status == 404
    assert get(bad_site, "/images/").status == 404  # no directory listing


@pytest.mark.parametrize("path", ["/../app.py", "/%2e%2e/%2e%2e/secret", "/images/../../README.md"])
def test_no_escape_from_root(bad_site: int, path: str) -> None:
    assert get(bad_site, path).status == 404


def test_redirect_chain(bad_site: int) -> None:
    r = get(bad_site, "/old")
    assert (r.status, r.getheader("Location")) == (302, "/old2")
    assert get(bad_site, "/old2").status == 301
    assert get(bad_site, "/old3").getheader("Location") == "/about.html"


def test_soft_404_rewrite(bad_site: int) -> None:
    assert get(bad_site, "/gone-page").status == 200


def test_head(bad_site: int) -> None:
    assert get(bad_site, "/about.html", "HEAD").status == 200


def test_directory_redirects_to_slash(tmp_path: Path) -> None:
    (tmp_path / "blog").mkdir()
    (tmp_path / "blog" / "index.html").write_text("x")
    server = make_server(tmp_path, "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        r = get(server.server_address[1], "/blog")
        assert (r.status, r.getheader("Location")) == (301, "/blog/")
    finally:
        server.shutdown()
        server.server_close()


def test_refuses_non_loopback(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        make_server(tmp_path, "0.0.0.0", 0)


def test_parse_redirects() -> None:
    rules = parse_redirects("# c\n/a /b\n/c /d 302\n/e /f 200!\nbad\n/a /z 301\n")
    assert rules["/a"].target == "/b"
    assert rules["/a"].status == 301  # first rule wins
    assert rules["/c"].status == 302
    assert rules["/e"].status == 200


def test_sqlite_snapshot_roundtrip(tmp_path: Path) -> None:
    db = tmp_path / "data" / "app.db"
    db.parent.mkdir()
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()
    (tmp_path / "fake.db").write_text("not sqlite")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    sqlite3.connect(nm / "cache.sqlite").close()

    assert find_sqlite_files(tmp_path) == [db]
    snap = Snapshot.take(tmp_path, tmp_path.parent / "snaps")
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM t")
    conn.commit()
    conn.close()
    assert snap.restore() == [db]
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT x FROM t").fetchall() == [(1,)]
    conn.close()
