### themes.py

from textual.theme import Theme

"""
Themes module for Redoubt
"""

# Rules for creating a new theme:
# 1. Add a Theme() object following the structure below
# 2. Add the theme to the imports in ui.py:imports, in the THEMES list and in the THEME_ORDER according to the wanted order in ui.py:RedoubtApp (ctrl+T cycles from first to last and loops)
# 3. Some general rules to what every variable changes in the UI:
# ------------------------------------------------------------------
# - primary -> vertical separator contacts/chat (chat focus), textbox outline (unfocused), selected contact box, "YOU" name in chat, right button in popups (clear history & quit app)
# - secondary -> vertical separator contacts/chat (contacts focus), textbox outline (focused), other-peer name in chat
# - accent -> ^X commands (bottom panel)
# - background -> chat portion background (right tab), popup background blur (i.e. background of popup background) | (ALSO HAS EFFECT ON SCREEN TEXT!!)
# - surface -> contacts portion background (left tab), textbox background, left button in popups (clear history & quit app)
# - panel -> bottom (command palette & status bar) and top panel ("Redoubt", current theme), popup background
# - success -> online dot, new message color
# - warning -> approaching max bytes per message (color of the text on the right of the textbox), currently 2300/2500


PYTHON = Theme(
    name="python",
    primary="#306998",
    secondary="#FFE873",
    accent="#4B8BBE",
    background="#0A0C10",
    surface="#141822",
    panel="#1E2530",
    success="#4BFCB1",
    warning="#FF5F56",
)

NORD = Theme(
    name="nord",
    primary="#5E81AC",
    secondary="#88C0D0",
    accent="#E5E9F0",
    background="#2E3440",
    surface="#242933",
    panel="#3B4252",
    success="#A3BE8C",
    warning="#D08770",
)

HELL = Theme(
    name="hell",
    primary="#B31010",
    secondary="#FF4D4D",
    accent="#FFA3A3",
    background="#0D0202",
    surface="#1A0808",
    panel="#2D0D0D",
    success="#00FF66",
    warning="#FFCC00",
)

AMETHYST = Theme(
    name="amethyst",
    primary="#9B66CC",
    secondary="#FF79C6",
    accent="#F8F8F2",
    background="#181424",
    surface="#0F0C18",
    panel="#28213B",
    success="#50FA7B",
    warning="#FF5555",
)
