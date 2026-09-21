### ui.py

"""
UI module for Redoubt
"""

import os
import time
import json
from datetime import datetime
from . import protocol as proto
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, RichLog, Static
from textual.screen import ModalScreen
from textual.widgets import Button
from textual.binding import Binding
from rich.markup import escape
from .themes import PYTHON, NORD, HELL, AMETHYST
from . import logger as logger_mod
logger = logger_mod.get_logger(__name__)


## Variables

SETTINGS_FILE = os.path.join(os.path.expanduser("~"), ".redoubt", "settings.json")

BYTE_COUNTER_WARNING_THRESHOLD = 2300   # threshold for "approaching max bytes"


## Settings

def load_settings() -> dict:
    """Load saved settings"""
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_settings(data: dict):
    """Save current settings"""
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError:
        logger.exception(f"Cannot save current settings ({SETTINGS_FILE})")


## Contact item class

class ContactItem(ListItem):
    def __init__(
        self,
        fingerprint,
        name,
        status="offline",
        preview="",
        preview_time="",
        unread_count=0,
    ):
        super().__init__()
        self.fingerprint = fingerprint
        self.contact_name = name
        self.status = status
        self.preview = preview
        self.preview_time = preview_time
        self.unread_count = unread_count

    def compose(self) -> ComposeResult:
        """Compose label for this contact"""
        yield Label(self.format_label(), id="contact_text")

    def format_label(self):
        """Format contact label (name, status, new message indicator and last message)"""
        dot = "●" if self.status == "online" else "○"

        theme = self.app.current_theme
        success_color = theme.success
        dot_color = success_color if self.status == "online" else "muted"

        unreceived_badge = (    # if has unread messages
            f" [b {success_color}][ NEW ][/]"
            if self.unread_count > 0 else ""
        )

        if self.preview:    # if has preview (i.e. sent messages)
            max_line_width = 28

            # Get badge string length
            if self.unread_count > 0:
                badge_str = f"({self.unread_count})"
                reserved_badge_len = len(badge_str) + 1 # +1 as padding
            else:
                badge_str = ""
                reserved_badge_len = 0

            # Calculate max left length for the message
            max_left_len = max_line_width - reserved_badge_len

            # Calculate time prefix length
            time_prefix = f"[{self.preview_time}] "
            prefix_len = len(time_prefix)

            # Calculate max text length
            max_text_len = max_left_len - prefix_len

            preview_text = self.preview
            if len(preview_text) > max_text_len:    # if the message would exceed max available length, shorten with ...
                truncated_len = max(0, max_text_len - 3)
                preview_text = preview_text[:truncated_len] + "..."

            # Escape content
            preview_text_safe = escape(preview_text)
            left_side = f"{time_prefix}{preview_text_safe}"

            if self.unread_count > 0:   # right-align the bubble
                left_side_formatted = f"[b {success_color}]{left_side}[/]"
                bubble = f"[b {success_color}]{badge_str}[/]"
                raw_len = len(left_side) + len(badge_str)
                spaces_needed = max(1, max_line_width - raw_len)
                spaces = " " * spaces_needed
                return (
                    f"[{dot_color}]{dot}[/] [b]{self.contact_name}[/]{unreceived_badge}\n"
                    f"   {left_side_formatted}{spaces}{bubble}"
                )
            else:
                return (
                    f"[{dot_color}]{dot}[/] [b]{self.contact_name}[/]\n"
                    f"   [dim]{left_side}[/]"
                )

        # if no messages were ever sent / cleared chat, only return first line
        return f"[{dot_color}]{dot}[/] [b]{self.contact_name}[/]{unreceived_badge}"

    def set_status(self, status):
        """Sets offline/online status for the contact"""
        self.status = status
        self.query_one("#contact_text", Label).update(self.format_label())

    def set_unread_count(self, count: int):
        """Sets the number of unread messages from a contact"""
        self.unread_count = count
        self.query_one("#contact_text", Label).update(self.format_label())


## Model CSS block for popups

MODAL_CSS = """
ConfirmClearScreen, ConfirmQuitScreen {
    align: center middle;
    background: $background 60%;
}

#dialog {
    width: 60;
    height: auto;
    min-height: 10;
    background: $panel;
    padding: 1 2;
    align: center middle;
}

#dialog Label {
    margin-bottom: 2;
    text-align: center;
    width: 100%;
}

#buttons_row {
    height: auto;
    align: center middle;
}

#buttons_row Button {
    margin: 0 1;
    width: 20;
}

#buttons_row Button.neutral {
    background: $surface;
    color: $text-muted;
}

#buttons_row Button.neutral:hover {
    background: $surface-lighten-1;
    color: $text;
}

#buttons_row Button.neutral:focus {
    text-style: none;           /* no highlight */
}
"""


## Confirm clear history class

class ConfirmClearScreen(ModalScreen):
    # Set CSS
    CSS = MODAL_CSS

    def compose(self) -> ComposeResult:
        """Compose the popup"""
        with Vertical(id="dialog"):
            yield Label("[b]Warning![/]\n\nDo you really want to clear all chat history for this contact?")
            with Horizontal(id="buttons_row"):
                # avoid highlighting the "dangerous" button
                yield Button("Yes", id="yes", classes="neutral")
                yield Button("No", id="no", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Set behaviour when pressing different buttons"""
        if event.button.id == "yes":
            self.dismiss(True)
        else:
            self.dismiss(False)


## Confirm quit app class

class ConfirmQuitScreen(ModalScreen):
    # Set CSS
    CSS = MODAL_CSS

    def compose(self) -> ComposeResult:
        """Compose the popup"""
        with Vertical(id="dialog"):
            yield Label("[b]Exit application[/]\n\nDo you want to quit Redoubt?")
            with Horizontal(id="buttons_row"):
                # avoid highlighting the "dangerous" button
                yield Button("Yes", id="yes", classes="neutral")
                yield Button("No", id="no", variant="primary")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Set behaviour when pressing different buttons"""
        if event.button.id == "yes":
            self.dismiss(True)
        else:
            self.dismiss(False)


## App class

class RedoubtApp(App):
    ENABLE_COMMAND_PALETTE = False

    ## Theme collection and order
    THEMES = [
        PYTHON,
        NORD,
        HELL,
        AMETHYST
    ]

    THEME_ORDER = [
        "python",
        "nord",
        "hell",
        "amethyst"
    ]

    ## CSS

    CSS = """
    Screen {
        color: $text;
    }

    #sidebar {
        width: 35;
        border-right: tall $primary-darken-2;
        background: $background-lighten-1;
    }

    #chat_area {
        height: 1fr;
    }

    #chatlog {
        height: 1fr;
        background: $background;
        padding: 1 2;
    }

    #msg_input {
        margin: 1 2;
        border: tall $primary-darken-1;
    }

    #input_row {
        height: auto;
    }

    #input_row #msg_input {
        width: 1fr;
    }

    #byte_counter {
        width: auto;
        margin: 1 2 1 0;
        content-align: right middle;
    }

    #statusbar {
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 2;
    }

    #sidebar:focus-within {
        border-right: tall $secondary;
    }

    #msg_input:focus {
        border: tall $secondary;
    }

    ListView > ListItem.--highlight {
        background: $secondary-darken-2;
        color: $text;
    }
    """

    BINDINGS = [    # define bindings
        Binding("ctrl+q", "request_quit", "(Q)uit", show=True),
        Binding("ctrl+l", "clear_chat", "C(L)ear chat", show=True),
        Binding("ctrl+t", "toggle_theme", "(T)heme", show=True),
    ]

    def __init__(self, identity, storage, network):
        super().__init__()
        self.identity = identity
        self.storage = storage
        self.network = network
        self.current_contact = None
        self._items = {}
        network.on_message = self.on_message
        network.on_status = self.on_status
        network.on_statusbar_message = self.on_statusbar_message
        network.on_ack = self.on_ack

    def compose(self) -> ComposeResult:
        """Compose full UI (sidebar, chat area, textbox and panels"""
        header = Header(show_clock=True)
        header.can_focus = False

        yield header
        with Horizontal():

            with Vertical(id="sidebar"):
                yield ListView(id="contacts")

            with Vertical(id="chat_area"):
                yield RichLog(id="chatlog", wrap=True, highlight=False, markup=True)

                with Horizontal(id="input_row"):
                    yield Input(placeholder="Write a message...", id="msg_input")
                    yield Static(f"0/{proto.MAX_MESSAGE_BYTES}", id="byte_counter")

                yield Static("", id="statusbar")

        yield Footer()

    def on_mount(self):
        """Textual function. Things to load on mount"""

        for theme in self.THEMES:
            self.register_theme(theme)

        saved = load_settings().get("theme")
        self.theme = saved if saved in self.THEME_ORDER else "python"
        self.update_theme_indicator()

        self.reload_contacts()
        self.title = "Redoubt"
        self.query_one("#msg_input").focus()


    ## Command actions

    def action_toggle_theme(self):
        """Textual action to toggle theme (cycles) | ctrl+T"""
        # Dynamically change theme
        i = self.THEME_ORDER.index(self.theme)
        self.theme = self.THEME_ORDER[(i + 1) % len(self.THEME_ORDER)]

        self.update_theme_indicator()

        for item in self._items.values():   # update label
            item.query_one("#contact_text", Label).update(item.format_label())

        if self.current_contact:    # update render history
            self.render_history(self.current_contact)

    def action_clear_chat(self):
        """Textual action to clear chat history | ctrl+L"""
        if not self.current_contact:
            return
        self.push_screen(ConfirmClearScreen(), self.clear_chat_confirmed)

    def action_request_quit(self):
        """Textual action to quit the app | ctrl+Q"""
        self.push_screen(ConfirmQuitScreen(), self.quit_confirmed)


    ## Theme

    def update_theme_indicator(self):
        """Update theme indicator on the top panel"""
        self.sub_title = self.theme.capitalize()


    ## Popup -> confirmed

    def quit_confirmed(self, confirmed):
        """Confirmed quitting status, save settings and exit"""
        if confirmed:
            save_settings({"theme": self.theme})
            self.exit()

    def clear_chat_confirmed(self, confirmed):
        """Confirmed clearing, clear history for current contact"""
        if not confirmed:
            return

        # Clear all messages
        self.storage.clear_history(self.current_contact)

        # Clear UI
        item = self._items.get(self.current_contact)
        if item:
            item.preview = ""
            item.preview_time = ""
            item.set_unread_count(0)
        self.render_history(self.current_contact)


    ## Contacts

    def reload_contacts(self):
        """Reload contacts on sidebar"""
        lv = self.query_one("#contacts", ListView)
        lv.clear()
        self._items.clear()

        for row in self.storage.list_contacts():    # for every contact, reload last message, label, preview and ContactItem
            fp, name = row[0:2]
            last = self.storage.get_last_message(fp)
            preview = ""
            preview_time = ""
            if last:    # if there is a last message
                preview = last["text"]
                preview_time = datetime.fromtimestamp(last["timestamp"] / 1000).strftime("%H:%M")

            unread_count = self.storage.count_unread_messages(fp)

            item = ContactItem(
                fp,
                name,
                preview=preview,
                preview_time=preview_time,
                unread_count=unread_count,
            )

            self._items[fp] = item
            lv.append(item)

    def on_list_view_selected(self, event: ListView.Selected):
        """To call when a contact is selected. Updates current contact, marks all messages as read and focuses on textbox"""
        item = event.item
        if not isinstance(item, ContactItem):
            return

        # Update current contact
        self.current_contact = item.fingerprint

        # Mark all messages as read
        self.storage.mark_messages_as_read(item.fingerprint)

        item.set_unread_count(0)
        self.render_history(item.fingerprint)

        # Focus on textbox
        self.query_one("#msg_input").focus()

    def update_preview(self, fingerprint, text, timestamp=None, unread_count=None):
        """Update contact preview (text, timestamp, unread count)"""
        item = self._items.get(fingerprint)
        if item:    # if the contact is in the sidebar
            item.preview = text
            if timestamp:   # if the text has a "sent timestamp"
                item.preview_time = datetime.fromtimestamp(timestamp / 1000).strftime("%H:%M")
            else:   # default to now
                item.preview_time = datetime.now().strftime("%H:%M")

            if unread_count is not None:    # update unread count
                item.unread_count = unread_count

            item.query_one("#contact_text", Label).update(item.format_label())


    ## Chat

    def render_history(self, fingerprint):
        """Render history for a specific contact"""
        log = self.query_one("#chatlog", RichLog)
        log.clear()

        # Get contact item, name and history
        history = self.storage.get_history(fingerprint)
        item = self._items[fingerprint]
        name = item.contact_name

        # Set colors
        primary = self.current_theme.primary
        secondary = self.current_theme.secondary

        # Set title and subtitle
        title = f"Chat with {name}"
        subtitle = "End-to-End encrypted"

        # Center title and subtitle
        width = self.query_one("#chatlog").size.width
        title_padding = max(0, (width - len(title)) // 2)
        subtitle_padding = max(0, (width - len(subtitle)) // 2)
        log.write(
            " " * title_padding +
            f"[bold]Chat with [bold {secondary}]{name}[/][/]\n"
            +
            " " * subtitle_padding +
            f"[dim]{subtitle}[/]\n"
        )

        # Keep track of all already-rendered messages (identified by their IDs)
        rendered_ids = set()

        # Outgoing messages still awaiting a MESSAGE_ACK (not yet confirmed received)
        pending_ids = self.storage.get_pending_ids(fingerprint)

        for m in history:
            if m["id"] in rendered_ids:
                continue
            rendered_ids.add(m["id"])

            ts = datetime.fromtimestamp(m["timestamp"] / 1000).strftime("%H:%M")
            if m["direction"] == "out": # show message as "You: ..."
                if m["id"] in pending_ids:   # not yet ACKed: render different
                    log.write(f"[bold {secondary}][{ts}] You: {escape(m['text'])}[/]")
                else:
                    log.write(f"[dim][{ts}][/] [bold {primary}]You:[/] {escape(m['text'])}")
            else:   # show message as "THEIR_NAME: ..."
                name = self._items[fingerprint].contact_name
                log.write(f"[dim][{ts}][/] [bold {secondary}]{name}[/]: {escape(m['text'])}")


    ## Textbox

    def on_input_changed(self, event: Input.Changed) -> None:
        """Update when text input changes (only byte counter as for now)"""
        if event.input.id != "msg_input":
            return
        self.update_byte_counter(event.value)

    def update_byte_counter(self, text: str):
        """Update byte counter and the allowed maximum"""
        n = len(text.encode("utf-8"))
        warning_color = self.current_theme.warning
        label = f"{n}/{proto.MAX_MESSAGE_BYTES}"

        if n > BYTE_COUNTER_WARNING_THRESHOLD:  # approaching max bytes
            self.query_one("#byte_counter", Static).update(f"[bold {warning_color}]{label}[/]")
        else:   # not close
            self.query_one("#byte_counter", Static).update(f"[dim]{label}[/]")

    def on_input_submitted(self, event: Input.Submitted):
        """Defines app behavior on submitted input (with Enter)"""
        if not self.current_contact or not event.value.strip(): # no contact selected, no one to send to
            return

        text = event.value.strip()
        byte_len = len(text.encode("utf-8"))
        if byte_len > proto.MAX_MESSAGE_BYTES:  # if exceedes max bytes, warn and do not send
            self.query_one("#statusbar", Static).update("⚠️ The message is too long. Divide into smaller messages")
            return

        # Get timestamp and random message ID
        timestamp_ms = int(time.time() * 1000)
        msg_id = proto.new_message_id()

        # Store message in the database
        self.storage.store_message(
            msg_id=msg_id,
            contact_fingerprint=self.current_contact,
            direction="out",
            timestamp=timestamp_ms,
            plaintext=text,
            unreceived=0
        )

        # Send message on the network
        self.network.send_text(self.current_contact, text, msg_id=msg_id)

        # Update UI (preview and history)
        self.update_preview(self.current_contact, text, timestamp_ms)
        self.render_history(self.current_contact)

        event.input.value = ""


    ## Network callbacks

    def on_message(self, fingerprint, text, timestamp_ms):
        """Define callback for a network contact message update """
        try:
            self.call_from_thread(
                self.on_message_ui,
                fingerprint,
                text,
                timestamp_ms
            )
        except RuntimeError:
            logger.exception("RuntimeError: on_message")

    def on_message_ui(self, fingerprint, text, timestamp_ms):
        """Define behaviour for a network contact message update"""
        if not self.is_running:
            return

        # Get contact item and if it is the current contact
        item = self._items.get(fingerprint)
        is_current = (fingerprint == self.current_contact)

        new_count = 0
        if is_current:  # if current contact, mark as read and render history
            self.storage.mark_messages_as_read(fingerprint)
            self.render_history(fingerprint)
            if item:
                item.set_unread_count(0)
        else:   # if off-focus, store as unread
            if item:
                new_count = self.storage.count_unread_messages(fingerprint)
                item.set_unread_count(new_count)

        if item:    # if the item exists, set peer as online
            item.set_status("online")

        # Update contact preview on the sidebar
        self.update_preview(fingerprint, text, timestamp_ms, unread_count=new_count if not is_current else 0)

    def on_status(self, fingerprint, status):
        """Define callback for a network contact status update"""
        try:
            self.call_from_thread(
                self.on_status_ui,
                fingerprint,
                status
            )
        except RuntimeError:
            logger.exception("RuntimeError: on_status")

    def on_status_ui(self, fingerprint, status):
        """Define behaviour for a network contact status update"""
        if not self.is_running:
            return

        # Get contact item
        item = self._items.get(fingerprint)

        if item and status in ("online", "offline"):    # if item exists and in legal states
            item.set_status(status)

    def on_ack(self, fingerprint, msg_id):
        """Define callback for a network message ACK update"""
        try:
            self.call_from_thread(
                self.on_ack_ui,
                fingerprint,
                msg_id
            )
        except RuntimeError:
            logger.exception("RuntimeError: on_ack")

    def on_ack_ui(self, fingerprint, msg_id):
        """Define behaviour for a network message ACK update: un-dim the message if its chat is open"""
        if not self.is_running:
            return

        if fingerprint == self.current_contact:   # only re-render if that chat is currently open
            self.render_history(fingerprint)

    def on_statusbar_message(self, fingerprint, message):
        """Define callback for a network status message update"""
        try:
            self.call_from_thread(
                self.on_statusbar_message_ui,
                fingerprint,
                message
            )
        except RuntimeError:
            logger.exception("RuntimeError: on_statusbar_message")

    def on_statusbar_message_ui(self, fingerprint, message):
        """Define behaviour for a network status message update"""
        if not self.is_running:
            return
        
        ts = datetime.now().strftime("%H:%M:%S")

        self.query_one("#statusbar", Static).update(f"[{ts}] {fingerprint[:16]}... [dim]{escape(message)}[/]")
