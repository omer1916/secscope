"""UI string catalogs. Every user-visible UI string comes from tr.json / en.json."""

from __future__ import annotations

import json
from functools import cache
from importlib import resources

from secscope.core.models import Language

LANGUAGES: tuple[Language, ...] = ("tr", "en")


@cache
def catalog(lang: Language) -> dict[str, str]:
    text = resources.files("secscope.ui.i18n").joinpath(f"{lang}.json").read_text("utf-8")
    data: dict[str, str] = json.loads(text)
    return data


class Translator:
    def __init__(self, lang: Language = "tr") -> None:
        self.lang: Language = lang

    def __call__(self, key: str, **params: object) -> str:
        text = catalog(self.lang).get(key) or catalog("en").get(key) or key
        return text.format(**params) if params else text

    def note(self, text: str) -> str:
        """A module note in this language; unknown notes are shown as they are."""
        key = f"note.{text}"
        return self(key) if key in catalog(self.lang) or key in catalog("en") else text

    def status(self, value: str) -> str:
        return self(f"scan.status.{value}")

    def profile(self, value: str) -> str:
        return self(f"ui.profile.{value}")

    def confidence(self, value: str) -> str:
        return self(f"report.conf.{value}")

    def tools(self, names: list[str]) -> str:
        """Tool names for display: the built-in engines show as "SecScope"."""
        shown = [self("report.tool.native") if n == "native" else n for n in names]
        return ", ".join(dict.fromkeys(shown))

    def module(self, module_id: str) -> str:
        """A module's title in this language (falls back to the id)."""
        from secscope.modules.registry import module_titles  # noqa: PLC0415 - avoid import cycle

        title = module_titles().get(module_id)
        if title is not None:
            return title.get(self.lang)
        key = f"module.{module_id}"  # pseudo-modules: prepare, cleanup
        return self(key) if key in catalog("en") else module_id
