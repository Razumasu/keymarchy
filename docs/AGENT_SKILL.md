---
name: keykeep
description: List, name, add, and remove local Omarchy FIDO2 sudo registrations with Keykeep.
---
Use `keykeep list --json` before changes. Existing registrations have generated names and stable full IDs; do not assume a registration fingerprint is a device serial number. The list output includes connection status and matching device descriptions. Use these to help the user identify and name a plugged-in key. Never choose an ambiguous removal target.

- Add: `keykeep add "Backup key" --json`. Ask the user to connect only the new key and touch it when it flashes. The system authentication prompt authorizes saving.
- Rename: `keykeep rename FULL_ID "New name" --json`.
- Remove an explicitly requested key: `keykeep remove FULL_ID --yes --json`.
- GUI: `keykeep open`.

Use the installed command as the regular user, not root. Add/remove invoke pkexec themselves. Backups are under /etc/fido2/. Removing a registration also affects polkit or other services sharing that file, but never resets the physical key. Do not edit PAM or reset a key as a workaround. Test a newly added key with a fresh sudo authentication when requested; enrollment success alone is not an authentication test.
