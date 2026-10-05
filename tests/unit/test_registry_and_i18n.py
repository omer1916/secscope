from __future__ import annotations

import pytest

from secscope.core.config import ScanProfile
from secscope.modules.registry import ModuleRegistry, load_builtin
from secscope.ui.i18n import LANGUAGES, Translator, catalog
from tests.fakes import FAKE_REFS, FastModule, SlowModule


def test_registry_basics() -> None:
    reg = ModuleRegistry([FastModule, SlowModule])
    assert reg.ids() == ["fake_fast", "fake_slow"]
    assert isinstance(reg.create("fake_fast"), FastModule)
    assert reg.for_profile(ScanProfile.QUICK) == ["fake_fast", "fake_slow"]
    with pytest.raises(KeyError, match="known"):
        reg.get("nope")


def test_duplicate_id_rejected() -> None:
    class Other(FastModule):
        pass

    reg = ModuleRegistry([FastModule])
    with pytest.raises(ValueError, match="duplicate"):
        reg.register(Other)


def test_load_builtin_with_extra_refs() -> None:
    reg = load_builtin(FAKE_REFS)
    assert "fake_fast" in reg.ids()


def test_builtin_modules_are_well_formed() -> None:
    for cls in load_builtin().classes():
        assert cls.title.tr
        assert cls.title.en
        assert cls.timeout_s > 0


def test_i18n_catalogs_have_same_keys() -> None:
    keys = [set(catalog(lang)) for lang in LANGUAGES]
    assert all(k == keys[0] for k in keys)


def test_i18n_placeholders_match() -> None:
    import re  # noqa: PLC0415

    tr, en = catalog("tr"), catalog("en")
    for key in tr:
        assert set(re.findall(r"{(\w+)}", tr[key])) == set(re.findall(r"{(\w+)}", en[key])), key


def test_translator_fallback_and_params() -> None:
    t = Translator("tr")
    assert t("status.finished", status="ok") == "Tarama bitti: ok"
    assert t("no.such.key") == "no.such.key"
