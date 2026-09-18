### app.py

"""
Entry point CLI of Redoubt
"""

import time
import argparse
from . import crypto
from . import secure_memory
from . import identity as identity_mod
from . import network as network_mod
from . import protocol as protocol_mod
from . import storage as storage_mod
from .ui import RedoubtApp


## Commands and helper functions

def format_fingerprint(fp: str) -> str:
    """Format sha256 fingerprint into 4-char spaced blocks"""
    return " ".join(fp[i:i + 4] for i in range(0, len(fp), 4))

def cmd_show_card(ident):
    """Show personal identity card: PubKey and fingerprint (=sha256 of the PubKey)"""
    print("\n=== Identity card (Share out-of-band only or on a secure channel) ===")
    print(f"Fingerprint : {format_fingerprint(ident.fingerprint)}")
    print(f"Public key : {protocol_mod.b64(ident.public_key_raw)}")
    print("Verify the fingerprint with the contact BEFORE messaging.\n")

def cmd_add_contact(storage):
    """Add contacts out-of-band (Name, IP, PubKey and Fingerprint)"""
    print("\n=== Add contact (manual entry) ===")
    name = input("Name (only visible by you): ").strip()
    ip = input("IP: ").strip()
    pubkey_b64 = input("Public key (base64): ").strip()
    fingerprint_input = input("Fingerprint (with or without spaces): ").strip().replace(" ", "")

    try:
        pubkey_raw = protocol_mod.unb64(pubkey_b64)
    except Exception:
        print("[ERROR] Public key is not a valid base64. Contact was not added.")
        return

    computed_fp = crypto.fingerprint_of(pubkey_raw)
    if computed_fp != fingerprint_input:
        print("[ERROR] Fingerprint does not match Public key. Contact was not added. always share on a secure out-of-band channel.")
        return

    confirm = input("Fingerprint matches Public Key. Add contact? (yes/no): ").strip().lower()
    verified = confirm in ("yes", "y")

    if verified:
        storage.add_contact(computed_fp, name, ip, network_mod.DEFAULT_PORT, pubkey_b64) # service port is default (60717)
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
        fp, name, ip, port, pubkey_b64 = row
        print(f"\n{name} ({ip}:{port})\n- PubKey (base64): {pubkey_b64}\n- Fingerprint: {format_fingerprint(fp)}")
    print()

def cmd_remove_contact(storage):
    """Remove contact from storage"""
    print("\n=== Remove contact (will eliminate all chat history and revoke trust. Will need to add them back to message again) ===")
    fingerprint_input = input("Fingerprint of the contact to remove: ").strip().replace(" ", "")

    contact = storage.get_contact(fingerprint_input)
    if contact is None:
        print("[ERROR] No contact with this fingerprint.")
        return

    _fp, name, ip, port, stored_pubkey_b64 = contact
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

    storage.delete_contact(fingerprint_input)
    print(f"Contact '{name}' removed.\n")


## Main function

def main():
    secure_memory.disable_core_dumps()  # Avoid information-leaking dumps

    parser = argparse.ArgumentParser(description="A peer-to-peer messaging app with end-to-end message encryption and hardened client runtime")
    parser.add_argument("--show-card", action="store_true", help="show personal identity card")
    parser.add_argument("--add-contact", action="store_true", help="add contact to trusted list")
    parser.add_argument("--remove-contact", action="store_true", help="remove contact from trusted list")
    parser.add_argument("--list-contacts", action="store_true", help="list contacts from trusted list")
    args = parser.parse_args()

    ident = identity_mod.load_or_create_identity_interactive()
    storage = storage_mod.Storage(ident.vault_key)

    if args.show_card:
        cmd_show_card(ident)
        return

    if args.add_contact:
        cmd_add_contact(storage)
        return

    if args.remove_contact:
        cmd_remove_contact(storage)
        return

    if args.list_contacts:
        cmd_list_contacts(storage)
        return

    network = network_mod.NetworkManager(ident, storage)
    network.start_listener(port=network_mod.DEFAULT_PORT)
    network.start_presence_worker()
    network.start_ack_watchdog()
    print("Starting...")

    app = RedoubtApp(ident, storage, network)
    try:
        app.run()
    finally:    # at quit
        network.broadcast_presence("offline")
        time.sleep(0.5)
        network.stop()
        ident.wipe()
        print("Closing...")


if __name__ == "__main__":
    main()
