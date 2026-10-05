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
