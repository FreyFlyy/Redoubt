import re

import pytest
from textual.theme import Theme

from redoubt import themes, ui

ALL = [v for v in vars(themes).values() if isinstance(v, Theme)]
COLOR_FIELDS = ["primary", "secondary", "accent", "background", "surface", "panel", "success", "warning"]


def test_every_theme_is_defined_and_uniquely_named():
    assert len(ALL) >= 4
    names = [t.name for t in ALL]
    assert len(names) == len(set(names))


@pytest.mark.parametrize("theme", ALL, ids=lambda t: t.name)
def test_theme_colors_are_valid_hex(theme):
    for field in COLOR_FIELDS:
        assert re.fullmatch(r"#[0-9A-Fa-f]{6}", getattr(theme, field)), (theme.name, field)


@pytest.mark.parametrize("theme", ALL, ids=lambda t: t.name)
def test_theme_surfaces_are_distinguishable(theme):
    assert len({theme.background, theme.surface, theme.panel}) == 3


def test_ui_registers_every_theme_and_cycles_through_all_of_them():
    registered = {t.name for t in ui.RedoubtApp.THEMES}
    order = ui.RedoubtApp.THEME_ORDER
    assert registered == {t.name for t in ALL}
    assert set(order) == registered and len(order) == len(set(order))
