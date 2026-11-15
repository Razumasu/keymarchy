# Changelog

## 0.4.0

- Enroll new keys inside the privileged helper, after authentication. The helper
  no longer accepts a registration from the calling program, and it only saves
  registrations that require a touch.
- Move the helper to `/usr/lib/keymarchy/keymarchy-helper`, a separate program
  that links QtCore only, with separate polkit prompts for adding and removing.
- Mark existing registrations that unlock sudo without a touch.
- List and remove resident registrations instead of rejecting the whole row.
- Refuse rows that pam-u2f would read differently than Keymarchy shows them.
- Check the polkit PAM rules as well, and list other readable PAM files that
  directly mention the registration file.
- Keep listing and removing keys when the names file is damaged.
- Keep the current operation's backup and the nine newest other backups, even
  after a clock correction, and leave none behind when a change is refused.
- Reject custom polkit authentication includes and substacks that could hide
  mandatory FIDO2 rules.
- Do not let Space start an enrollment while a button has focus.
- Show helper errors in the selected language and complete the Danish catalog.

## 0.3.1

- Reject additional or reordered sudo authentication rules before managing keys,
  including rules that could block password authentication after key removal.
- Detect legacy U2F registrations with URL-safe or unpadded credential handles
  without changing their saved registrations, fingerprints, or names.
- Ask users to verify password authentication before removing their last key.
- Add regression coverage for the supported PAM stack and legacy handles.

## 0.3.0

First public release of Keymarchy.

- List and name the FIDO2 registrations used by sudo on Omarchy.
- Add and remove registrations with administrator authentication and backups.
- Highlight connected keys automatically, including multiple registrations
  belonging to the same physical key.
- Use the desktop interface or command-line commands with JSON output.
- Follow Omarchy's theme and language, with English and Danish translations.
- Preserve names from the local Keykeep prototype.

Keymarchy requires the standard Omarchy FIDO2 setup. Enroll the first key through
Omarchy's security menu before using it. Custom PAM configurations are not
supported.
