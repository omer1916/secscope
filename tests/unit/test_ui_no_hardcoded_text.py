"""SPEC §11.2: UI text only via i18n catalogs — no string literals passed to widget text APIs."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from secscope.ui.i18n import LANGUAGES, catalog

UI = Path(__file__).resolve().parents[2] / "src" / "secscope" / "ui"
TEXT_CALLS = {
    "setText", "setWindowTitle", "setPlaceholderText", "setToolTip", "setStatusTip", "setTitle",
    "setHorizontalHeaderLabels", "setAccessibleName", "addItem", "addRow", "setLabel",
    "QLabel", "QPushButton", "QCheckBox", "QRadioButton", "QGroupBox", "QAction", "label",
    "information", "warning", "question", "getText",
}  # fmt: skip
# Not translatable on purpose: language names in their own language, a sample URL, log levels.
ALLOWED = {
    "Türkçe",
    "English",
    "https://www.example.com",
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "left",
    "bottom",
    "%",
}
LETTERS = re.compile(r"[A-Za-zÇĞİÖŞÜçğıöşü]")


def literal_texts(source: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.attr
            if isinstance(func, ast.Attribute)
            else func.id
            if isinstance(func, ast.Name)
            else ""
        )
        if name not in TEXT_CALLS:
            continue
        # The visible text is the first argument (later ones are roles, data or parents).
        for arg in node.args[:1]:
            values = (
                [arg]
                if isinstance(arg, ast.Constant)
                else list(arg.elts)
                if isinstance(arg, ast.List)
                else []
            )
            for v in values:
                if (
                    isinstance(v, ast.Constant)
                    and isinstance(v.value, str)
                    and LETTERS.search(v.value)
                    and v.value not in ALLOWED
                ):
                    found.append((node.lineno, v.value))
    return found


def test_no_hardcoded_ui_text() -> None:
    offenders = {
        str(p.relative_to(UI)): hits
        for p in UI.rglob("*.py")
        if (hits := literal_texts(p.read_text(encoding="utf-8")))
    }
    assert offenders == {}


@pytest.mark.parametrize(
    "snippet",
    [
        'QLabel("Hello")',
        'btn.setText("Save")',
        'box.setHorizontalHeaderLabels(["Name", "x"])',
        'label("Başlık", "h1")',
    ],
)
def test_detector_catches(snippet: str) -> None:
    assert literal_texts(snippet)


def test_detector_allows_translations() -> None:
    assert literal_texts('QLabel(t("ui.x"))\nbtn.setText("")\nlbl.setProperty("role", "h1")') == []


def test_every_t_key_used_in_ui_exists() -> None:
    keys: set[str] = set()
    for p in UI.rglob("*.py"):
        keys |= set(re.findall(r'\bt\(\s*"([a-z0-9_.]+)"', p.read_text(encoding="utf-8")))
    for lang in LANGUAGES:
        missing = sorted(k for k in keys if k not in catalog(lang))
        assert missing == [], f"{lang}: {missing}"
