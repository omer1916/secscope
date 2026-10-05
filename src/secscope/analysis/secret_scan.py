"""Native secret scanner: known token formats, private keys, credentials in URLs,
high-entropy values assigned to secret-looking names, and committed ``.env`` files.

False-positive controls: placeholders and env lookups are ignored, generic matches need
Shannon entropy ≥ 3.0 bits/char and length ≥ 8, files under test/docs folders get lower
confidence, and ``secscope: ignore`` comments suppress a line. Matched values are only
ever stored masked (the Evidence model masks on construction).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass

from secscope.analysis.regex_rules import suppressed
from secscope.analysis.source import SourceFile
from secscope.core.models import Confidence, Severity


@dataclass(frozen=True, slots=True)
class SecretHit:
    rule_id: str
    kind: str  # human label, e.g. "AWS access key"
    line: int
    column: int
    confidence: Confidence
    severity: Severity | None = None


@dataclass(frozen=True, slots=True)
class _Detector:
    rule_id: str
    kind: str
    pattern: re.Pattern[str]
    severity: Severity | None = None


DETECTORS: tuple[_Detector, ...] = (
    _Detector(
        "SECRET-CLOUD-001",
        "AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"),
    ),
    _Detector(
        "SECRET-CLOUD-001",
        "AWS secret access key",
        re.compile(r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"),
    ),
    _Detector(
        "SECRET-CLOUD-001",
        "Google Cloud service account key",
        re.compile(r"\"type\"\s*:\s*\"service_account\""),
    ),
    _Detector(
        "SECRET-CLOUD-001",
        "Azure storage connection string",
        re.compile(
            r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}"
        ),
    ),
    _Detector(
        "SECRET-TOKEN-001",
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    ),
    _Detector("SECRET-TOKEN-001", "GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    _Detector("SECRET-TOKEN-001", "Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b")),
    _Detector(
        "SECRET-TOKEN-001",
        "Slack webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ),
    _Detector("SECRET-TOKEN-001", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    _Detector(
        "SECRET-TOKEN-001",
        "Stripe secret key",
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
        "critical",
    ),
    _Detector(
        "SECRET-TOKEN-001",
        "Stripe test key",
        re.compile(r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b"),
        "low",
    ),
    _Detector(
        "SECRET-TOKEN-001",
        "OpenAI / Anthropic API key",
        re.compile(r"\bsk-(?:ant-[A-Za-z0-9_\-]{20,}|proj-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{40,})\b"),
    ),
    _Detector("SECRET-TOKEN-001", "npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    _Detector(
        "SECRET-TOKEN-001",
        "SendGrid API key",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),
    ),
    _Detector("SECRET-TOKEN-001", "Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    _Detector("SECRET-TOKEN-001", "Mailgun API key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    _Detector(
        "SECRET-TOKEN-001",
        "Discord / Telegram bot token",
        re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b"),
    ),
    _Detector(
        "SECRET-PRIVKEY-001",
        "private key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
        ),
    ),
    _Detector(
        "SECRET-DBURL-001",
        "credentials in connection URL",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|ftp|smtp|ldap)"
            r"://[^\s:/@\"']+:([^\s@/\"']{3,})@[^\s\"']+"
        ),
    ),
    _Detector(
        "SECRET-JWT-001",
        "hardcoded JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
)

_GENERIC = re.compile(
    r"(?i)(?P<name>[A-Za-z0-9_.\-]{0,30}(?:secret|token|api[_\-]?key|apikey|passw(?:or)?d|passwd|pwd|"
    r"private[_\-]?key|client[_\-]?secret|access[_\-]?key|auth[_\-]?key|credential)[A-Za-z0-9_.\-]{0,20})"
    r"[\"']?\s*(?::=|=>|[:=])\s*[\"']?(?P<value>[^\s\"'`,;)}\]#]{8,})"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x+|\*+|\.+|changeme|change[-_]?me|your[-_].*|<.*>|\$[{(]?[A-Za-z_].*|%\(.*\)s|\{\{.*|"
    r"process\.env.*|os\.environ.*|getenv.*|env\(.*|config\.\w+|settings\.\w+|true|false|null|none|"
    r"undefined|example.*|sample.*|dummy.*|placeholder.*|todo|required|optional|string|password|secret|"
    r"\w+\(.*|[a-z_]+\.[a-z_]+.*|.*_here)$"
)
_ENV_EXAMPLE = re.compile(r"(?i)\.(?:example|sample|template|dist|defaults?)$")
_TEST_PATH = re.compile(
    r"(?i)(?:^|/)(?:tests?|__tests__|spec|specs|docs?|examples?|samples?|mocks?)/"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_env_file(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return (
        name == ".env" or name.startswith(".env.") or name.endswith(".env")
    ) and not _ENV_EXAMPLE.search(name)


def scan_secrets(file: SourceFile) -> Iterator[SecretHit]:
    test_like = bool(_TEST_PATH.search(file.rel))
    base_conf: Confidence = "medium" if test_like else "high"
    seen_lines: set[int] = set()
    for det in DETECTORS:
        for m in det.pattern.finditer(file.text):
            line = file.line_of(m.start())
            text = file.line_text(line)
            # One finding per line: the most specific detector (listed first) wins.
            if suppressed(text, det.rule_id) or line in seen_lines:
                continue
            value = m.group(1) if m.groups() else m.group(0)
            if det.rule_id == "SECRET-DBURL-001" and _PLACEHOLDER.match(value):
                continue
            seen_lines.add(line)
            yield SecretHit(
                det.rule_id,
                det.kind,
                line,
                m.start() - file.text.rfind("\n", 0, m.start()),
                base_conf,
                det.severity,
            )
    for m in _GENERIC.finditer(file.text):
        line = file.line_of(m.start())
        if line in seen_lines:
            continue
        value = m.group("value").strip()
        text = file.line_text(line)
        if _PLACEHOLDER.match(value) or suppressed(text, "SECRET-GENERIC-001"):
            continue
        entropy = shannon_entropy(value)
        if (
            entropy < 3.0
            or value.isdigit()
            or (value.isalpha() and value.islower() and len(value) < 12)
        ):
            continue
        seen_lines.add(line)
        conf: Confidence = "low" if test_like else ("high" if entropy >= 4.0 else "medium")
        yield SecretHit(
            "SECRET-GENERIC-001",
            f"secret-like value in '{m.group('name')}'",
            line,
            m.start("value") - file.text.rfind("\n", 0, m.start()),
            conf,
        )
