"""Core data models shared by the worker, modules, storage and UI (SPEC §5).

Models are immutable (``frozen``) and reject unknown fields, so a typo in a
module surfaces as a validation error instead of silently dropped data. Use
``model_copy(update=...)`` to derive modified copies (e.g. in dedup).
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal, Self
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secscope.core.redact import redact, redact_headers

SCHEMA_VERSION = 1

# Evidence is for humans: keep it short enough for reports and the database.
MAX_SNIPPET_CHARS = 4_000
MAX_BODY_CHARS = 16_000


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=False)


class Category(StrEnum):
    SECURITY = "security"
    SEO = "seo"
    PERFORMANCE = "performance"
    RESILIENCE = "resilience"
    QUALITY = "quality"


Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "high", "medium", "low"]
Effort = Literal["S", "M", "L"]
Language = Literal["tr", "en"]

SEVERITY_ORDER: dict[Severity, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONFIDENCE_ORDER: dict[Confidence, int] = {"confirmed": 3, "high": 2, "medium": 1, "low": 0}


def max_severity(values: list[Severity], default: Severity = "medium") -> Severity:
    best: Severity | None = None
    for value in values:
        if best is None or SEVERITY_ORDER[value] > SEVERITY_ORDER[best]:
            best = value
    return best or default


class LocalizedStr(_Model):
    """User-facing text in every supported UI language."""

    tr: str
    en: str

    def get(self, lang: Language) -> str:
        return self.tr if lang == "tr" else self.en


class LocalizedList(_Model):
    tr: list[str] = Field(default_factory=list[str])
    en: list[str] = Field(default_factory=list[str])

    def get(self, lang: Language) -> list[str]:
        return self.tr if lang == "tr" else self.en


# ------------------------------------------------------------------ locations


class CodeLocation(_Model):
    """A position in the scanned project's source tree (POSIX path, relative to its root)."""

    kind: Literal["code"] = "code"
    path: str
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)

    @field_validator("path")
    @classmethod
    def _relative_posix(cls, v: str) -> str:
        v = v.replace("\\", "/")
        if v.startswith("/") or re.match(r"^[A-Za-z]:", v) or ".." in v.split("/"):
            raise ValueError("path must be relative to the project root, without '..'")
        return v

    def fingerprint_key(self) -> str:
        # Line numbers drift whenever code above the finding changes; the
        # normalised evidence snippet disambiguates findings within a file.
        return f"code:{self.path}"

    def short(self) -> str:
        return self.display()

    def display(self) -> str:
        parts = [self.path]
        if self.line is not None:
            parts.append(str(self.line))
            if self.column is not None:
                parts.append(str(self.column))
        return ":".join(parts)


class HttpLocation(_Model):
    """An HTTP endpoint (optionally a single parameter of it) on the target."""

    kind: Literal["http"] = "http"
    url: str
    method: str = "GET"
    parameter: str | None = None

    @field_validator("method")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @field_validator("url")
    @classmethod
    def _mask_url(cls, v: str) -> str:
        return redact(v)

    def fingerprint_key(self) -> str:
        # Query *values* vary between requests; parameter *names* identify the endpoint.
        parts = urlsplit(self.url)
        names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
        path = parts.path or "/"
        host = (parts.hostname or "").lower()
        if (
            host in {"localhost", "127.0.0.1", "::1"}
            or host.endswith(".localhost")
            or host.startswith("127.")
        ):
            # The target runs on a random loopback port per scan; the port must not change
            # the identity, or every rescan would show all findings as "fixed + new".
            origin = "local"
        else:
            origin = f"{parts.scheme}://{parts.netloc.lower()}"
        return f"http:{self.method} {origin}{path}?{'&'.join(names)}#{self.parameter or ''}"

    def display(self) -> str:
        suffix = f" [{self.parameter}]" if self.parameter else ""
        return f"{self.method} {self.url}{suffix}"

    def short(self) -> str:
        """Method and path only (the target's origin is a throwaway loopback port)."""
        parts = urlsplit(self.url)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        suffix = f" [{self.parameter}]" if self.parameter else ""
        return f"{self.method} {path}{suffix}"


Location = Annotated[CodeLocation | HttpLocation, Field(discriminator="kind")]


# ------------------------------------------------------------------- evidence


class HttpMessage(_Model):
    """A captured request or response. Secrets are masked on construction."""

    method: str | None = None
    url: str | None = None
    status: int | None = None
    headers: list[tuple[str, str]] = Field(default_factory=list[tuple[str, str]])
    body: str | None = None
    body_truncated: bool = False

    @model_validator(mode="before")
    @classmethod
    def _mask(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d: dict[str, Any] = dict(data)  # pyright: ignore[reportUnknownArgumentType]
        if isinstance(d.get("url"), str):
            d["url"] = redact(d["url"])
        if d.get("headers"):
            d["headers"] = redact_headers((str(k), str(v)) for k, v in d["headers"])
        body = d.get("body")
        if isinstance(body, str):
            if len(body) > MAX_BODY_CHARS:
                body = body[:MAX_BODY_CHARS]
                d["body_truncated"] = True
            d["body"] = redact(body)
        return d


class Evidence(_Model):
    """Proof for a finding. All free text is secret-masked on construction."""

    snippet: str | None = None
    request: HttpMessage | None = None
    response: HttpMessage | None = None
    screenshot_path: str | None = None
    notes: str | None = None
    extra: dict[str, str] = Field(default_factory=dict[str, str])

    @field_validator("snippet", "notes")
    @classmethod
    def _mask_text(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return redact(v[:MAX_SNIPPET_CHARS])

    @field_validator("extra")
    @classmethod
    def _mask_extra(cls, v: dict[str, str]) -> dict[str, str]:
        return {k: redact(val[:MAX_SNIPPET_CHARS]) for k, val in v.items()}

    def normalized(self) -> str:
        """Whitespace-insensitive representation used for the finding fingerprint."""
        text = self.snippet or ""
        if not text and self.response is not None:
            text = f"{self.response.status}"
        return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------- remediation


class CodeSnippet(_Model):
    lang: str
    code: str


class Remediation(_Model):
    steps: LocalizedList = Field(default_factory=LocalizedList)
    # Keyed by stack id: express, flask, django, php, nginx, apache, static, ...
    snippets: dict[str, CodeSnippet] = Field(default_factory=dict[str, CodeSnippet])
    verify: LocalizedStr | None = None


RefType = Literal["cwe", "owasp", "asvs", "url", "mdn", "google", "cve"]


class Ref(_Model):
    type: RefType
    id: str | None = None
    href: str | None = None
    title: str | None = None

    @field_validator("id", mode="before")
    @classmethod
    def _id_as_str(cls, v: object) -> object:
        return str(v) if isinstance(v, int) else v

    @model_validator(mode="after")
    def _id_or_href(self) -> Self:
        if self.id is None and self.href is None:
            raise ValueError("a reference needs an id or an href")
        return self


# -------------------------------------------------------------------- finding


def compute_finding_id(
    rule_id: str, location: CodeLocation | HttpLocation, evidence: Evidence
) -> str:
    """Stable fingerprint: sha256(rule_id + location + normalised evidence)."""
    payload = json.dumps(
        [rule_id, location.fingerprint_key(), evidence.normalized()], ensure_ascii=False
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Finding(_Model):
    """A single, explainable result of a scan module (SPEC §5).

    ``id`` is derived from rule, location and evidence when omitted, so the same
    issue keeps the same id across scans (used for diffs and suppressions).
    ``description``/``impact``/``remediation``/``references`` may be left empty
    by a module; they are filled from the remediation KB by ``rule_id``.
    """

    schema_version: ClassVar[int] = SCHEMA_VERSION

    id: str = ""
    rule_id: str = Field(pattern=r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
    module: str
    category: Category
    title: LocalizedStr
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: Evidence = Field(default_factory=Evidence)
    description: LocalizedStr | None = None
    impact: LocalizedStr | None = None
    remediation: Remediation | None = None
    references: list[Ref] = Field(default_factory=list[Ref])
    cwe: list[int] = Field(default_factory=list[int])
    owasp: list[str] = Field(default_factory=list[str])
    asvs: list[str] = Field(default_factory=list[str])
    effort: Effort = "M"
    # Every tool that reported this finding; dedup merges lists (SPEC §5 rules).
    source_tools: list[str] = Field(min_length=1)
    first_seen_scan: str | None = None

    @model_validator(mode="after")
    def _fill_id(self) -> Self:
        # A stored id is kept as-is: recomputing it after a masking-rule change
        # would break diffs and suppressions against older scans.
        if not self.id:
            object.__setattr__(
                self, "id", compute_finding_id(self.rule_id, self.location, self.evidence)
            )
        return self
