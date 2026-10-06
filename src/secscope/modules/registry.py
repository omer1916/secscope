"""Module registry. To add a scanner, add one ``"package.module:Class"`` line below."""

from __future__ import annotations

import importlib
from collections.abc import Iterable
from functools import cache

from secscope.core.config import ScanProfile
from secscope.core.models import LocalizedStr
from secscope.modules.base import BaseModule

BUILTIN_MODULES: tuple[str, ...] = (
    "secscope.modules.sast:SastModule",
    "secscope.modules.secrets:SecretsModule",
    "secscope.modules.sca:ScaModule",
    "secscope.modules.config_audit:ConfigAuditModule",
    "secscope.modules.seo:SeoModule",
)


class ModuleRegistry:
    def __init__(self, classes: Iterable[type[BaseModule]] = ()) -> None:
        self._classes: dict[str, type[BaseModule]] = {}
        for cls in classes:
            self.register(cls)

    def register(self, cls: type[BaseModule]) -> type[BaseModule]:
        module_id = cls.id
        if module_id in self._classes and self._classes[module_id] is not cls:
            raise ValueError(f"duplicate module id {module_id!r}")
        self._classes[module_id] = cls
        return cls

    def get(self, module_id: str) -> type[BaseModule]:
        try:
            return self._classes[module_id]
        except KeyError:
            known = ", ".join(sorted(self._classes)) or "none"
            raise KeyError(f"unknown module {module_id!r} (known: {known})") from None

    def ids(self) -> list[str]:
        return sorted(self._classes)

    def classes(self) -> list[type[BaseModule]]:
        return [self._classes[i] for i in self.ids()]

    def for_profile(self, profile: ScanProfile) -> list[str]:
        return [c.id for c in self.classes() if profile in c.profiles]

    def create(self, module_id: str) -> BaseModule:
        return self.get(module_id)()


@cache
def module_titles() -> dict[str, LocalizedStr]:
    return {cls.id: cls.title for cls in load_builtin().classes()}


def load_builtin(extra: Iterable[str] = ()) -> ModuleRegistry:
    registry = ModuleRegistry()
    for ref in (*BUILTIN_MODULES, *extra):
        module_name, _, class_name = ref.partition(":")
        cls = getattr(importlib.import_module(module_name), class_name)
        registry.register(cls)
    return registry
