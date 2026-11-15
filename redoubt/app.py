"""
Entry point CLI of Redoubt
"""

import sys
import argparse

from . import __version__
from . import crypto
from . import secure_memory
from . import contact_validation
from . import identity as identity_mod
from . import network as network_mod
from . import onion_service as onion_service_mod
from . import protocol as protocol_mod
from . import storage as storage_mod
from .contact_validation import format_fingerprint, normalize_fingerprint  # re-exported (kept importable from app)
from .contact_validation import contact_id_for, contact_fingerprint, display_name, is_onion_contact_id, make_contact_id
from .ui import RedoubtApp


## Commands and helper functions

def cmd_show_card(ident, onion_address=None):
    """Show personal identity card: PubKey and fingerprint (=sha256 of the PubKey), plus the onion address if one was created"""
    print("\n=== Identity card (Share out-of-band only or on a secure channel) ===")
    print(f"Fingerprint : {format_fingerprint(ident.fingerprint)}")
    print(f"Public key  : {protocol_mod.b64(ident.public_key_raw)}")
    if onion_address:
        print(f"Onion address: {onion_address}")
    print("Verify the fingerprint with the contact BEFORE messaging.\n")

def cmd_add_contact(storage, ident):
    """Add contacts out-of-band (Name, IP or .onion address, PubKey and Fingerprint)"""
    print("\n=== Add contact (manual entry) ===")
    name = input("Name (only visible by you): ").strip()
    ip_input = input("IP or .onion address: ").strip()
    pubkey_b64 = input("Public key (base64): ").strip()
    fingerprint_input = normalize_fingerprint(input("Fingerprint (with or without spaces): "))

    try:
        name, ip, pubkey_b64, computed_fp = contact_validation.validate_new_contact(
            storage, ident, name, ip_input, pubkey_b64, fingerprint_input
        )
    except ValueError as e:
        print(f"[ERROR] {e} Contact was not added.")
        return

    confirm = input("Fingerprint matches Public Key. Add contact? (yes/no): ").strip().lower()
    verified = confirm in ("yes", "y")

    if verified:
        storage.add_contact(contact_id_for(computed_fp, ip), name, ip, network_mod.DEFAULT_PORT, pubkey_b64) # service port is default (60717)
        print(f"'{name}' added\n")
    else:
        print(f"ABORTING! '{name}' not added")

def cmd_list_contacts(storage):
    """List saved contacts"""
    contacts = storage.list_contacts()

    if not contacts:
        print("No saved contact.")
        return

    print("\n=== Saved contacts ===")
    for row in contacts:
        cid, name, ip, port, pubkey_b64 = row
        print(f"\n{display_name(cid, name)} ({ip}:{port})\n- PubKey (base64): {pubkey_b64}\n- Fingerprint: {format_fingerprint(contact_fingerprint(cid))}")
    print()

def cmd_remove_contact(storage):
    """Remove contact from storage.

    NOTE: the public key is requested as an anti-mistake confirmation, not as a security
    check (a public key is not a secret). Sessions already open in a running instance are
    not affected until it is restarted.
    """
    print("\n=== Remove contact (will eliminate all chat history and revoke trust. Will need to add them back to message again) ===")
    fingerprint_input = normalize_fingerprint(input("Fingerprint of the contact to remove: "))

    # The same key can be saved twice: as IP contact and as onion contact
    matches = [c for c in (storage.get_contact(make_contact_id(fingerprint_input)),
                           storage.get_contact(make_contact_id(fingerprint_input, onion=True))) if c is not None]
    if not matches:
        print("[ERROR] No contact with this fingerprint.")
        return
    if len(matches) == 2:
        choice = input("This fingerprint is saved as an IP contact and as an onion contact. Remove which one? (ip/onion): ").strip().lower()
        if choice not in ("ip", "onion"):
            print("[ERROR] Answer 'ip' or 'onion'. Contact was not removed.")
            return
        contact = matches[1] if choice == "onion" else matches[0]
    else:
        contact = matches[0]

    cid, name, ip, port, stored_pubkey_b64 = contact
    pubkey_b64 = input(f"Public key (base64) of '{name}' to confirm: ").strip()

    try:
        pubkey_raw = protocol_mod.unb64(pubkey_b64)
    except Exception:
        print("[ERROR] Public key is not a valid base64. Contact was not removed.")
        return

    if crypto.fingerprint_of(pubkey_raw) != fingerprint_input or pubkey_b64 != stored_pubkey_b64:
        print("[ERROR] Public key does not match Fingerprint. Contact was not removed.")
        return

    print(f"\nContact: {name} ({ip}:{port})")
    print(f"Public Key: {pubkey_b64}")
    print(f"Fingerprint: {format_fingerprint(fingerprint_input)}")
    confirm = input("Confirm removal? This will eliminate all chat history and revoke trust, and you will need to add them back to message again (yes/no): ").strip().lower()
    if confirm not in ("yes", "y"):
        print(f"ABORTING! '{name}' Not removed")
        return

    storage.delete_contact(cid)
    print(f"Contact '{display_name(cid, name)}' removed.\n")


## Main function

def _run() -> int:
    secure_memory.disable_core_dumps()  # Avoid information-leaking dumps

    parser = argparse.ArgumentParser(description="A peer-to-peer messaging app with end-to-end message encryption and hardened client runtime")
    # --version exits inside parse_args(), before the vault passphrase is requested
    parser.add_argument("--version", action="version", version=f"redoubt {__version__}", help="show app version and exit")
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument("--show-card", action="store_true", help="show personal identity card")
    commands.add_argument("--add-contact", action="store_true", help="add contact to trusted list")
    commands.add_argument("--remove-contact", action="store_true", help="remove contact from trusted list")
    commands.add_argument("--list-contacts", action="store_true", help="list contacts from trusted list")
    args = parser.parse_args()

    ident = identity_mod.load_or_create_identity_interactive()
    network = None
    onion = None
    network_running = False

    try:
        storage = storage_mod.Storage(ident.vault_key)

        if args.show_card:
            cmd_show_card(ident, onion_service_mod.stored_address(storage))
            return 0

        if args.add_contact:
            cmd_add_contact(storage, ident)
            return 0

        if args.remove_contact:
            cmd_remove_contact(storage)
            return 0

        if args.list_contacts:
            cmd_list_contacts(storage)
            return 0

        network = network_mod.NetworkManager(ident, storage)
        try:
            network.start_listener(port=network_mod.DEFAULT_PORT)
        except OSError as e:
            print(f"[ERROR] Cannot listen on port {network_mod.DEFAULT_PORT}: {e}")
            return 1
        network_running = True
        network.start_presence_worker()
        network.start_ack_watchdog()
        print("Starting...")

        onion = onion_service_mod.OnionService(storage, network)   # idle until the "Use Tor/Onion network" setting is on
        app = RedoubtApp(ident, storage, network, onion)
        app.run()
        return 0
    finally:    # at quit, on errors and after CLI commands
        if network_running:
            network.broadcast_presence("offline", wait=1.0)   # parallel, live sessions only, 1s global cap
            network.stop()
        if onion is not None:
            onion.disable()     # stops Tor (it would exit by itself anyway: it is bound to this process)
        ident.wipe()
        print("Closing...")


def main() -> int:
    try:
        return _run()
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
