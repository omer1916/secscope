"""Dependency inventory from manifests/lockfiles, CycloneDX SBOM, typosquatting and licences.

Supported inputs: package-lock.json (v2/v3), npm-shrinkwrap.json, requirements*.txt (pinned
``==``), Pipfile.lock, poetry.lock, composer.lock. Vulnerability matching is delegated to
Trivy / osv-scanner (offline databases) by the SCA module.
"""

from __future__ import annotations

import json
import re
import tomllib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from secscope.__about__ import __app_name__, __version__
from secscope.core.intake import iter_source_files
from secscope.core.jsonutil import jdict, jlist, jstr
from secscope.core.resources import data_path

ECOSYSTEM_PURL = {"npm": "npm", "PyPI": "pypi", "Packagist": "composer"}
COPYLEFT = re.compile(r"\b(?:A?GPL|SSPL|EUPL|OSL|CC-BY-SA)", re.I)


@dataclass
class Package:
    ecosystem: str  # npm | PyPI | Packagist
    name: str
    version: str
    manifest: str  # relative path of the file declaring it
    direct: bool = True
    license: str | None = None
    install_script: bool = False
    dev: bool = False

    @property
    def purl(self) -> str:
        eco = ECOSYSTEM_PURL[self.ecosystem]
        name = self.name.lower() if eco == "pypi" else self.name
        if eco == "npm" and name.startswith("@"):
            name = "%40" + name[1:]
        return f"pkg:{eco}/{name}@{self.version}"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, normalise_name(self.ecosystem, self.name), self.version)


@dataclass
class Inventory:
    packages: list[Package] = field(default_factory=list[Package])
    manifests: list[str] = field(default_factory=list[str])
    unpinned: list[str] = field(default_factory=list[str])  # declarations without exact versions

    def ecosystems(self) -> set[str]:
        return {p.ecosystem for p in self.packages}


def normalise_name(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _npm_lock(root: Path, path: Path, inv: Inventory) -> None:
    data = jdict(json.loads(path.read_text(encoding="utf-8")))
    packages = jdict(data.get("packages"))
    root_entry = jdict(packages.get(""))
    direct = set(jdict(root_entry.get("dependencies"))) | set(
        jdict(root_entry.get("devDependencies"))
    )
    for key, raw in packages.items():
        meta = jdict(raw)
        if not key or "node_modules/" not in key or meta.get("link"):
            continue
        name = jstr(meta.get("name")) or key.rsplit("node_modules/", 1)[1]
        version = jstr(meta.get("version"))
        if not version:
            continue
        nested = key.count("node_modules/") > 1
        inv.packages.append(
            Package("npm", name, version, _rel(root, path), direct=(name in direct and not nested),
                    license=jstr(meta.get("license")) or None,
                    install_script=bool(meta.get("hasInstallScript")), dev=bool(meta.get("dev")))
        )  # fmt: skip


_REQ = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.+!\-]+)"
)


def _requirements(root: Path, path: Path, inv: Inventory) -> None:
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ.match(line)
        if m:
            inv.packages.append(Package("PyPI", m.group(1), m.group(2), _rel(root, path)))
        elif re.match(r"^[A-Za-z0-9]", line):
            inv.unpinned.append(f"{_rel(root, path)}: {line}")


def _pipfile_lock(root: Path, path: Path, inv: Inventory) -> None:
    data = jdict(json.loads(path.read_text(encoding="utf-8")))
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in jdict(data.get(section)).items():
            version = jstr(jdict(meta).get("version")).lstrip("=")
            if version:
                inv.packages.append(Package("PyPI", name, version, _rel(root, path), dev=dev))


def _poetry_lock(root: Path, path: Path, inv: Inventory) -> None:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for raw in jlist(data.get("package")):
        pkg = jdict(raw)
        name, version = jstr(pkg.get("name")), jstr(pkg.get("version"))
        if name and version:
            inv.packages.append(Package("PyPI", name, version, _rel(root, path), direct=False))


def _composer_lock(root: Path, path: Path, inv: Inventory) -> None:
    data = jdict(json.loads(path.read_text(encoding="utf-8")))
    for section, dev in (("packages", False), ("packages-dev", True)):
        for raw in jlist(data.get(section)):
            pkg = jdict(raw)
            lic = pkg.get("license")
            licence = (
                ", ".join(jstr(x) for x in jlist(lic))
                if isinstance(lic, list)
                else jstr(lic) or None
            )
            inv.packages.append(
                Package("Packagist", jstr(pkg.get("name")), jstr(pkg.get("version")).lstrip("v"),
                        _rel(root, path), dev=dev, license=licence)
            )  # fmt: skip


PARSERS = {
    "package-lock.json": _npm_lock,
    "npm-shrinkwrap.json": _npm_lock,
    "Pipfile.lock": _pipfile_lock,
    "poetry.lock": _poetry_lock,
    "composer.lock": _composer_lock,
}


def build_inventory(root: Path) -> Inventory:
    inv = Inventory()
    for path in iter_source_files(root):
        parser = PARSERS.get(path.name)
        if parser is None and re.match(r"^requirements[\w.-]*\.txt$", path.name):
            parser = _requirements
        if parser is None:
            continue
        try:
            parser(root, path, inv)
            inv.manifests.append(_rel(root, path))
        except (ValueError, KeyError, tomllib.TOMLDecodeError):
            continue
    # One entry per (ecosystem, name, version): the direct declaration wins.
    unique: dict[tuple[str, str, str], Package] = {}
    for pkg in inv.packages:
        existing = unique.get(pkg.key)
        if existing is None or (pkg.direct and not existing.direct):
            unique[pkg.key] = pkg
    inv.packages = sorted(unique.values(), key=lambda p: (p.ecosystem, p.name.lower(), p.version))
    return inv


def cyclonedx(inv: Inventory, project_name: str) -> dict[str, Any]:
    """CycloneDX 1.5 JSON SBOM."""
    components: list[dict[str, Any]] = []
    for p in inv.packages:
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": p.purl,
            "name": p.name,
            "version": p.version,
            "purl": p.purl,
            "scope": "optional" if p.dev else "required",
            "properties": [
                {"name": "secscope:manifest", "value": p.manifest},
                {"name": "secscope:direct", "value": str(p.direct).lower()},
            ],
        }
        if p.license:
            comp["licenses"] = (
                [{"expression": p.license}]
                if " " in p.license
                else [{"license": {"id": p.license}}]
            )
        components.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {"type": "application", "name": __app_name__, "version": __version__}
                ]
            },
            "component": {"type": "application", "name": project_name, "bom-ref": "root"},
        },
        "components": components,
    }


def _load_popular() -> dict[str, set[str]]:
    raw: dict[str, list[str]] = yaml.safe_load(
        (data_path("rules") / "popular_packages.yaml").read_text(encoding="utf-8")
    )
    return {
        "npm": set(raw.get("npm", [])),
        "PyPI": {normalise_name("PyPI", n) for n in raw.get("pypi", [])},
        "Packagist": set(raw.get("composer", [])),
    }


def _edit_distance_le1(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance <= 1 (insert, delete, substitute or adjacent swap)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and a[diffs[0]] == b[diffs[1]]
            and a[diffs[1]] == b[diffs[0]]
        )
    short, long_ = (a, b) if la < lb else (b, a)
    i = 0
    while i < len(short) and short[i] == long_[i]:
        i += 1
    return short[i:] == long_[i + 1 :]


def typosquat_candidates(inv: Inventory) -> list[tuple[Package, str]]:
    popular = _load_popular()
    hits: list[tuple[Package, str]] = []
    for p in inv.packages:
        if not p.direct:
            continue
        names = popular.get(p.ecosystem, set())
        name = normalise_name(p.ecosystem, p.name)
        if name in names or len(name) < 4:
            continue
        for candidate in names:
            if len(candidate) >= 4 and _edit_distance_le1(name, candidate):
                hits.append((p, candidate))
                break
    return hits


def copyleft_packages(inv: Inventory) -> list[Package]:
    return [
        p
        for p in inv.packages
        if p.license and COPYLEFT.search(p.license) and not re.search(r"\bLGPL", p.license, re.I)
    ]
