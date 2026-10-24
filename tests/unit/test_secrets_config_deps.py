from __future__ import annotations

import json
from pathlib import Path

import pytest

from secscope.analysis.config_checks import check_config, is_ignored
from secscope.analysis.deps import (
    Inventory,
    Package,
    _edit_distance_le1,  # pyright: ignore[reportPrivateUsage]
    build_inventory,
    copyleft_packages,
    cyclonedx,
    typosquat_candidates,
)
from secscope.analysis.secret_scan import is_env_file, scan_secrets, shannon_entropy
from secscope.analysis.source import SourceFile
from tests.fake_secrets import AWS_KEY_ID, AWS_SECRET, STRIPE_KEY_SHORT

# ------------------------------------------------------------------ secrets

SECRET_CASES: list[tuple[str, str, str]] = [
    ("SECRET-CLOUD-001", f'key = "{AWS_KEY_ID}"', 'key = "AKIA_NOT_A_KEY"'),
    (
        "SECRET-CLOUD-001",
        f"aws_secret_access_key = {AWS_SECRET}",
        "aws_secret_access_key = ${AWS_SECRET}",
    ),
    ("SECRET-TOKEN-001", "GH=ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "GH=ghp_short"),
    ("SECRET-TOKEN-001", f"STRIPE={STRIPE_KEY_SHORT}", "STRIPE=sk_live_"),
    (
        "SECRET-PRIVKEY-001",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        "-----BEGIN PUBLIC KEY-----",
    ),
    (
        "SECRET-DBURL-001",
        "DATABASE_URL=postgres://app:Pr0dPassw0rd@db:5432/x",
        "DATABASE_URL=postgres://db:5432/x",
    ),
    (
        "SECRET-JWT-001",
        "t = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N'",
        "t = 'eyJ'",
    ),
    (
        "SECRET-GENERIC-001",
        'client_secret = "x9F2kLq7Zp4Wm8Rt"',
        'client_secret = "your-client-secret-here"',
    ),
    ("SECRET-GENERIC-001", "API_TOKEN=7fA9c2Ld8Kq1Zx", "API_TOKEN=${API_TOKEN}"),
]


def secrets_in(text: str, name: str = "config.txt") -> set[str]:
    file = SourceFile(root=Path(), path=Path(name), text=text + "\n", language=None)
    return {h.rule_id for h in scan_secrets(file)}


@pytest.mark.parametrize(("rule_id", "positive", "negative"), SECRET_CASES)
def test_secret_rules(rule_id: str, positive: str, negative: str) -> None:
    assert rule_id in secrets_in(positive)
    assert rule_id not in secrets_in(negative)


def test_one_finding_per_line_most_specific_wins() -> None:
    hits = secrets_in(f'aws_key = "{AWS_KEY_ID}"')
    assert hits == {"SECRET-CLOUD-001"}


def test_test_paths_lower_confidence() -> None:
    file = SourceFile(
        root=Path(),
        path=Path("tests/fixtures.py"),
        text='secret_key = "x9F2kLq7Zp4Wm8RtQ"\n',
        language="python",
    )
    assert [h.confidence for h in scan_secrets(file)] == ["low"]


def test_suppression_comment() -> None:
    assert secrets_in('client_secret = "x9F2kLq7Zp4Wm8Rt"  # secscope: ignore') == set()


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        (".env", True),
        ("app/.env.production", True),
        (".env.example", False),
        ("config.env", True),
        ("environment.py", False),
    ],
)
def test_env_file_detection(rel: str, expected: bool) -> None:
    assert is_env_file(rel) is expected


def test_entropy() -> None:
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("x9F2kLq7Zp4Wm8Rt") > 3.5


# ------------------------------------------------------------------- config

CONFIG_CASES: list[tuple[str, str, str, str]] = [
    (
        "CONF-DOCKER-ROOT-001",
        "Dockerfile",
        "FROM python:3.12-slim\nRUN pip install x\n",
        "FROM python:3.12-slim\nUSER app\n",
    ),
    (
        "CONF-DOCKER-LATEST-001",
        "Dockerfile",
        "FROM node:latest\nUSER node\n",
        "FROM node:20.11-alpine\nUSER node\n",
    ),
    (
        "CONF-DOCKER-ADD-001",
        "Dockerfile",
        "FROM a:1\nADD https://x.example/t.tgz /t\nUSER a\n",
        "FROM a:1\nCOPY t.tgz /t\nUSER a\n",
    ),
    (
        "CONF-DOCKER-SECRET-001",
        "Dockerfile",
        "FROM a:1\nENV DB_PASSWORD=hunter2\nUSER a\n",
        "FROM a:1\nENV DB_PASSWORD=$DB_PASSWORD\nUSER a\n",
    ),
    (
        "CONF-COMPOSE-PRIV-001",
        "docker-compose.yml",
        "services:\n  app:\n    image: a\n    privileged: true\n",
        "services:\n  app:\n    image: a\n",
    ),
    (
        "CONF-COMPOSE-PORT-001",
        "docker-compose.yml",
        'services:\n  db:\n    image: pg\n    ports:\n      - "5432:5432"\n',
        'services:\n  db:\n    image: pg\n    ports:\n      - "127.0.0.1:5432:5432"\n',
    ),
    (
        "CONF-NGINX-AUTOINDEX-001",
        "nginx.conf",
        "server {\n  autoindex on;\n}\n",
        "server {\n  autoindex off;\n}\n",
    ),
    (
        "CONF-NGINX-TOKENS-001",
        "nginx.conf",
        "server {\n listen 80;\n}\n",
        "server_tokens off;\nserver {\n listen 80;\n}\n",
    ),
    (
        "CONF-NGINX-HDR-001",
        "nginx.conf",
        "server {\n listen 80;\n}\n",
        "server {\n add_header X-Content-Type-Options nosniff always;\n add_header Content-Security-Policy \"default-src 'self'\" always;\n add_header X-Frame-Options DENY always;\n}\n",
    ),
    ("CONF-HTACCESS-INDEXES-001", ".htaccess", "Options +Indexes\n", "Options -Indexes\n"),
    (
        "CONF-CI-PRT-001",
        ".github/workflows/ci.yml",
        "on: pull_request_target\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
        "on: pull_request\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n",
    ),
    (
        "CONF-CI-INJECT-001",
        ".github/workflows/t.yml",
        'jobs:\n  a:\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n',
        'jobs:\n  a:\n    steps:\n      - env:\n          T: ${{ github.event.issue.title }}\n        run: echo "$T"\n',
    ),
    ("CONF-SOURCEMAP-001", "public/app.js.map", "{}", None),  # type: ignore[list-item]
    ("CONF-BACKUP-001", "app.py.bak", "x", None),  # type: ignore[list-item]
    ("CONF-GITIGNORE-001", ".env", "A=1", None),  # type: ignore[list-item]
]


def config_rules(
    tmp_path: Path, rel: str, content: str, extra: dict[str, str] | None = None
) -> set[str]:
    for name, text in {rel: content, **(extra or {})}.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return {i.rule_id for i in check_config(tmp_path)}


@pytest.mark.parametrize(("rule_id", "rel", "positive", "negative"), CONFIG_CASES)
def test_config_rules(
    tmp_path: Path, rule_id: str, rel: str, positive: str, negative: str | None
) -> None:
    assert rule_id in config_rules(tmp_path / "pos", rel, positive)
    if negative is not None:
        assert rule_id not in config_rules(tmp_path / "neg", rel, negative)


def test_gitignored_env_is_fine(tmp_path: Path) -> None:
    assert "CONF-GITIGNORE-001" not in config_rules(
        tmp_path, ".env", "A=1", {".gitignore": ".env\n"}
    )


def test_sourcemap_outside_public_dir_ok(tmp_path: Path) -> None:
    assert "CONF-SOURCEMAP-001" not in config_rules(tmp_path, "src/app.js.map", "{}")


@pytest.mark.parametrize(
    ("rel", "patterns", "ignored"),
    [
        (".env", [".env"], True),
        ("a/b/.env", [".env"], True),
        (".env.example", [".env*", "!.env.example"], False),
        ("keys/id_rsa", ["keys/"], True),
        ("x.pem", ["*.key"], False),
        ("src/secret.key", ["/secret.key"], False),
    ],
)
def test_gitignore_matching(rel: str, patterns: list[str], ignored: bool) -> None:
    assert is_ignored(rel, patterns) is ignored


# --------------------------------------------------------------------- deps


def write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def test_inventory_from_fixtures() -> None:
    flask = build_inventory(Path(__file__).resolve().parents[2] / "fixtures" / "vuln-flask")
    assert {(p.name, p.version) for p in flask.packages} == {
        ("flask", "2.2.2"),
        ("werkzeug", "2.2.3"),
        ("pyjwt", "2.4.0"),
    }
    express = build_inventory(Path(__file__).resolve().parents[2] / "fixtures" / "vuln-express")
    lodash = next(p for p in express.packages if p.name == "lodash")
    assert (lodash.version, lodash.direct, lodash.license) == ("4.17.15", True, "MIT")
    assert any(not p.direct for p in express.packages)


def test_inventory_other_formats(tmp_path: Path) -> None:
    write(
        tmp_path,
        {
            "Pipfile.lock": json.dumps(
                {
                    "default": {"requests": {"version": "==2.0.0"}},
                    "develop": {"pytest": {"version": "==7.0.0"}},
                }
            ),
            "poetry.lock": '[[package]]\nname = "Django"\nversion = "4.0.0"\n',
            "composer.lock": json.dumps(
                {"packages": [{"name": "monolog/monolog", "version": "v3.5.0", "license": ["MIT"]}]}
            ),
            "requirements-dev.txt": "black\nrequests[security]==2.0.0\n",
            "node_modules/x/package-lock.json": "{}",
        },
    )
    inv = build_inventory(tmp_path)
    names = {(p.ecosystem, p.name, p.version) for p in inv.packages}
    assert ("PyPI", "requests", "2.0.0") in names
    assert ("PyPI", "Django", "4.0.0") in names
    assert ("Packagist", "monolog/monolog", "3.5.0") in names
    assert inv.unpinned == ["requirements-dev.txt: black"]
    assert "node_modules/x/package-lock.json" not in inv.manifests


def test_cyclonedx_shape() -> None:
    inv = Inventory(
        packages=[
            Package("npm", "@scope/pkg", "1.0.0", "package-lock.json", license="MIT"),
            Package("PyPI", "Flask", "2.2.2", "requirements.txt"),
        ]
    )
    bom = cyclonedx(inv, "demo")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    purls = [c["purl"] for c in bom["components"]]
    assert purls == ["pkg:npm/%40scope/pkg@1.0.0", "pkg:pypi/flask@2.2.2"]
    assert bom["components"][0]["licenses"] == [{"license": {"id": "MIT"}}]


@pytest.mark.parametrize(
    ("a", "b", "close"),
    [
        ("lodash", "lodahs", True),
        ("express", "expres", True),
        ("requests", "request", True),
        ("axios", "axois", True),
        ("react", "preact", True),
        ("lodash", "lodash-es", False),
        ("flask", "django", False),
    ],
)
def test_edit_distance(a: str, b: str, close: bool) -> None:
    assert _edit_distance_le1(a, b) is close


def test_typosquat_and_licences() -> None:
    inv = Inventory(
        packages=[
            Package("npm", "expres", "1.0.0", "package-lock.json"),
            Package("npm", "express", "4.0.0", "package-lock.json"),
            Package("PyPI", "requestss", "1.0", "requirements.txt"),
            Package("npm", "copyleft-lib", "1.0.0", "package-lock.json", license="GPL-3.0"),
            Package("npm", "lgpl-lib", "1.0.0", "package-lock.json", license="LGPL-2.1"),
        ]
    )
    assert {(p.name, c) for p, c in typosquat_candidates(inv)} == {
        ("expres", "express"),
        ("requestss", "requests"),
    }
    assert [p.name for p in copyleft_packages(inv)] == ["copyleft-lib"]


@pytest.mark.parametrize(
    "code",
    [
        "class SecretHit:\n    rule_id: str\n",
        "_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (\n",
        '    "secscope.modules.secrets:SecretsModule",\n',
        "token_type = SecretStrategy\n",
    ],
)
def test_generic_secret_ignores_code(code: str) -> None:
    assert "SECRET-GENERIC-001" not in secrets_in(code, "module.py")
