"""Software composition analysis (SPEC §6.2): inventory, SBOM, known vulnerabilities, supply chain.

Vulnerabilities come from Trivy and osv-scanner run **offline** against locally cached
databases; results for the same package are merged (both tools agreeing raises confidence).
One finding per vulnerable package version lists all of its advisories.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from secscope.analysis.deps import (
    Inventory,
    Package,
    build_inventory,
    copyleft_packages,
    cyclonedx,
    normalise_name,
    typosquat_candidates,
)
from secscope.analysis.kb import KnowledgeBase, default_kb
from secscope.core.advisories import (
    TRIVY_PRIVACY_FLAGS,
    osv_env,
    osv_status,
    trivy_cache,
    trivy_status,
)
from secscope.core.jsonutil import jdict, jlist, jstr
from secscope.core.models import (
    SEVERITY_ORDER,
    Category,
    Confidence,
    LocalizedStr,
    Ref,
    Severity,
    max_severity,
)
from secscope.core.process import run_capture
from secscope.modules.base import BaseModule, Emitter, ModuleResult, Requirements, ScanContext
from secscope.modules.common import code_finding, project_root, stack_of

TOOL_TIMEOUT_S = 15 * 60
_TRIVY_ECOSYSTEM = {
    "pip": "PyPI",
    "pipenv": "PyPI",
    "poetry": "PyPI",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "composer": "Packagist",
}


@dataclass
class Advisory:
    id: str
    severity: Severity
    summary: str = ""
    fixed: list[str] = field(default_factory=list[str])
    aliases: set[str] = field(default_factory=set[str])


@dataclass
class VulnerablePackage:
    ecosystem: str
    name: str
    version: str
    manifest: str
    advisories: dict[str, Advisory] = field(default_factory=dict[str, Advisory])
    tools: set[str] = field(default_factory=set[str])

    def add(self, adv: Advisory, tool: str) -> None:
        self.tools.add(tool)
        # The same advisory may come as CVE from one tool and GHSA/PYSEC from another.
        for existing in self.advisories.values():
            if adv.id == existing.id or adv.id in existing.aliases or existing.id in adv.aliases:
                existing.aliases |= adv.aliases | {adv.id}
                existing.fixed = sorted(set(existing.fixed) | set(adv.fixed))
                if SEVERITY_ORDER[adv.severity] > SEVERITY_ORDER[existing.severity]:
                    existing.severity = adv.severity
                return
        self.advisories[adv.id] = adv

    @property
    def severity(self) -> Severity:
        return max_severity([a.severity for a in self.advisories.values()])


def _cvss_severity(score: float) -> Severity:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else "medium"


_TRIVY_SEVERITY: dict[str, Severity] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}
Row = tuple[str, str, str, str, Advisory]  # (ecosystem, name, version, manifest, advisory)


def parse_trivy(output: str, root: Path) -> list[Row]:
    out: list[Row] = []
    for res in jlist(jdict(json.loads(output)).get("Results")):
        r = jdict(res)
        eco = _TRIVY_ECOSYSTEM.get(jstr(r.get("Type")))
        if eco is None:
            continue
        manifest = Path(jstr(r.get("Target"))).as_posix()
        for raw in jlist(r.get("Vulnerabilities")):
            v = jdict(raw)
            severity = _TRIVY_SEVERITY.get(jstr(v.get("Severity")).lower(), "medium")
            fixed = [f.strip() for f in jstr(v.get("FixedVersion")).split(",") if f.strip()]
            adv = Advisory(
                jstr(v.get("VulnerabilityID")), severity, jstr(v.get("Title")), fixed, set()
            )
            out.append(
                (eco, jstr(v.get("PkgName")), jstr(v.get("InstalledVersion")), manifest, adv)
            )
    return out


def _osv_fixed(vuln: dict[str, Any], name: str) -> list[str]:
    fixed: set[str] = set()
    for raw in jlist(vuln.get("affected")):
        aff = jdict(raw)
        if jstr(jdict(aff.get("package")).get("name")).lower() != name.lower():
            continue
        for rng in jlist(aff.get("ranges")):
            for event in jlist(jdict(rng).get("events")):
                value = jdict(event).get("fixed")
                if isinstance(value, str):
                    fixed.add(value)
    return sorted(fixed)


def parse_osv(output: str, root: Path) -> list[Row]:
    out: list[Row] = []
    for raw_res in jlist(jdict(json.loads(output)).get("results")):
        res = jdict(raw_res)
        src = Path(jstr(jdict(res.get("source")).get("path")))
        try:
            manifest = src.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            manifest = src.name
        for raw_pkg in jlist(res.get("packages")):
            pkg = jdict(raw_pkg)
            p = jdict(pkg.get("package"))
            name = jstr(p.get("name"))
            scores: dict[str, float] = {}
            for raw_group in jlist(pkg.get("groups")):
                group = jdict(raw_group)
                try:
                    score = float(jstr(group.get("max_severity"), "0") or 0)
                except ValueError:
                    score = 0.0
                for vid in jlist(group.get("ids")):
                    scores[jstr(vid)] = score
            for raw_v in jlist(pkg.get("vulnerabilities")):
                v = jdict(raw_v)
                vid = jstr(v.get("id"))
                adv = Advisory(
                    vid,
                    _cvss_severity(scores.get(vid, 0.0)),
                    jstr(v.get("summary")),
                    _osv_fixed(v, name),
                    {jstr(a) for a in jlist(v.get("aliases"))},
                )
                out.append((jstr(p.get("ecosystem")), name, jstr(p.get("version")), manifest, adv))
    return out


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def _manifest_line(root: Path, manifest: str, name: str) -> int | None:
    try:
        lines = (root / manifest).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    pattern = re.compile(rf'(?i)(^|["/\s]){re.escape(name)}(["\s=<>~!\[]|$)')
    for i, line in enumerate(lines, start=1):
        if pattern.search(line):
            return i
    return None


class ScaModule(BaseModule):
    id: ClassVar[str] = "sca"
    title: ClassVar[LocalizedStr] = LocalizedStr(
        tr="Bağımlılık analizi (SCA)", en="Dependency analysis (SCA)"
    )
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(needs_source=True)
    timeout_s: ClassVar[float] = 30 * 60

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        root = project_root(ctx)
        kb = default_kb()
        stack = stack_of(ctx)
        result = ModuleResult()
        inv = await asyncio.to_thread(build_inventory, root)
        result.data["packages"] = len(inv.packages)
        result.data["manifests"] = inv.manifests
        sbom_path = ctx.work_dir / "sbom.cdx.json"
        sbom_path.write_text(json.dumps(cyclonedx(inv, root.name), indent=2), encoding="utf-8")
        result.data["sbom_path"] = str(sbom_path)
        emit.log(
            f"{len(inv.packages)} dependencies in {len(inv.manifests)} manifest(s); SBOM written"
        )
        if not inv.manifests:
            result.notes.append("no dependency manifests found")
            return result

        vulnerable: dict[tuple[str, str, str], VulnerablePackage] = {}
        by_key = {p.key: p for p in inv.packages}

        def record(rows: list[tuple[str, str, str, str, Advisory]], tool: str) -> None:
            for eco, name, version, manifest, adv in rows:
                key = (eco, normalise_name(eco, name), version)
                pkg = by_key.get(key)
                entry = vulnerable.setdefault(
                    key,
                    VulnerablePackage(
                        eco, pkg.name if pkg else name, version, pkg.manifest if pkg else manifest
                    ),
                )
                entry.add(adv, tool)

        data_dir = ctx.settings.data_dir
        used_tools = 0
        trivy = ctx.tools.status("trivy")
        tdb = trivy_status(data_dir)
        if trivy.available and trivy.path is not None and tdb.present:
            emit.progress(30, "trivy (offline)")
            run = await run_capture(
                [str(trivy.path), "fs", str(root), "--scanners", "vuln", "--format", "json", "--list-all-pkgs=false",
                 "--cache-dir", str(trivy_cache(data_dir)), "--skip-db-update", "--skip-java-db-update",
                 "--skip-check-update", "--offline-scan", *TRIVY_PRIVACY_FLAGS, "-q"],
                cwd=root, timeout=TOOL_TIMEOUT_S,
            )  # fmt: skip
            if run.returncode == 0 and run.stdout.strip():
                record(parse_trivy(run.stdout, root), "trivy")
                used_tools += 1
                result.data["trivy_db_updated"] = (
                    tdb.updated_at.isoformat() if tdb.updated_at else None
                )
            else:
                emit.log(f"trivy failed (exit {run.returncode}): {run.stderr[-300:]}", "warning")
        await ctx.checkpoint()

        osv = ctx.tools.status("osv-scanner")
        odb = osv_status(data_dir)
        if osv.available and osv.path is not None and odb.present:
            emit.progress(60, "osv-scanner (offline)")
            run = await run_capture(
                [str(osv.path), "scan", "source", "--offline", "--offline-vulnerabilities", "-r", str(root),
                 "--format", "json", "--verbosity", "error"],
                cwd=root, env=osv_env(data_dir), timeout=TOOL_TIMEOUT_S,
            )  # fmt: skip
            if run.returncode in (0, 1) and run.stdout.strip().startswith("{"):
                record(parse_osv(run.stdout, root), "osv-scanner")
                used_tools += 1
                result.data["osv_db_updated"] = (
                    odb.updated_at.isoformat() if odb.updated_at else None
                )
            else:
                emit.log(
                    f"osv-scanner failed (exit {run.returncode}): {run.stderr[-300:]}", "warning"
                )

        # Without an advisory database nothing was measured: the dependency score must not
        # read as a clean bill of health (scoring leaves it unmeasured).
        result.data["advisories_assessed"] = used_tools > 0
        if used_tools == 0:
            result.notes.append(
                "reduced-coverage: no offline vulnerability database (run 'secscope tools update-db')"
            )
            emit.log(
                "No offline vulnerability database: install Trivy/osv-scanner and run 'secscope tools update-db'",
                "warning",
            )

        for vp in vulnerable.values():
            emit.finding(
                self._vuln_finding(
                    kb,
                    root,
                    vp,
                    by_key.get((vp.ecosystem, normalise_name(vp.ecosystem, vp.name), vp.version)),
                    stack,
                )
            )
        self._supply_chain(kb, root, inv, emit, stack)
        emit.progress(100)
        return result

    @staticmethod
    def _vuln_finding(
        kb: KnowledgeBase, root: Path, vp: VulnerablePackage, pkg: Package | None, stack: str | None
    ) -> Any:
        advisories = sorted(
            vp.advisories.values(), key=lambda a: (-SEVERITY_ORDER[a.severity], a.id)
        )
        fixes = sorted({f for a in advisories for f in a.fixed}, key=_version_key)
        # The smallest version that fixes every advisory = highest of the per-advisory minimum fixes.
        needed = [min(a.fixed, key=_version_key) for a in advisories if a.fixed]
        fix_to = max(needed, key=_version_key) if needed else None
        direct = pkg.direct if pkg else True
        ids = [a.id for a in advisories]
        title = LocalizedStr(
            tr=f"{vp.name} {vp.version}: {len(ids)} bilinen güvenlik açığı",
            en=f"{vp.name} {vp.version}: {len(ids)} known vulnerabilit{'y' if len(ids) == 1 else 'ies'}",
        )
        confidence: Confidence = "high" if len(vp.tools) > 1 else "medium"
        f = code_finding(
            kb, "SCA-VULN-001", module="sca", path=vp.manifest, line=_manifest_line(root, vp.manifest, vp.name),
            snippet=f"{vp.name}@{vp.version}", severity=vp.severity, confidence=confidence, stack=stack,
            extra={"ecosystem": vp.ecosystem, "advisories": ", ".join(ids[:20]), "fix_to": fix_to or "none",
                   "all_fixed_versions": ", ".join(fixes[:10]), "dependency": "direct" if direct else "transitive",
                   "summary": advisories[0].summary[:300] if advisories else ""},
        )  # fmt: skip
        refs = [
            Ref(type="url", href=f"https://osv.dev/vulnerability/{a.id}", title=a.id)
            for a in advisories[:10]
        ]
        return f.model_copy(
            update={
                "title": title,
                "source_tools": sorted(vp.tools),
                "references": [*f.references, *refs],
            }
        )

    @staticmethod
    def _supply_chain(
        kb: KnowledgeBase, root: Path, inv: Inventory, emit: Emitter, stack: str | None
    ) -> None:
        for pkg, popular in typosquat_candidates(inv):
            emit.finding(
                code_finding(kb, "SCA-TYPO-001", module="sca", path=pkg.manifest, line=_manifest_line(root, pkg.manifest, pkg.name),
                             snippet=f"{pkg.name}@{pkg.version}", stack=stack, extra={"similar_to": popular})
            )  # fmt: skip
        scripts = [p for p in inv.packages if p.install_script]
        if scripts:
            emit.finding(
                code_finding(kb, "SCA-INSTALLSCRIPT-001", module="sca", path=scripts[0].manifest, line=None,
                             snippet="install scripts: " + ", ".join(sorted(p.name for p in scripts)[:30]), stack=stack)
            )  # fmt: skip
        copyleft = copyleft_packages(inv)
        if copyleft:
            emit.finding(
                code_finding(kb, "SCA-LICENSE-001", module="sca", path=copyleft[0].manifest, line=None,
                             snippet=", ".join(f"{p.name} ({p.license})" for p in copyleft[:30]), stack=stack)
            )  # fmt: skip
