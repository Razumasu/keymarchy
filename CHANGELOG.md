# Changelog

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
