![Keykeep showing three named security keys](docs/screenshot.png)

# Keykeep

A small native app for managing the FIDO2 security keys used by sudo on Omarchy.
List your registrations, give them memorable names, add a key with a touch, and
remove a selected registration without manually editing authentication files.

## Install

On Omarchy, from a checkout or extracted source archive:

```sh
./bin/install
```

This builds, tests, and installs an Arch package. Open **Keykeep** in the app
launcher (`Super + Space`), or run `keykeep open`.

Dependencies: Qt 6 base, declarative and Wayland, pam-u2f, libfido2, and polkit.
Building needs GCC, make, and qmake6. The PKGBUILD is in `pkgbuild/`.

## Use

- **Add key:** connect only the key to enroll, choose a name, touch it when it
  flashes, and approve the system authentication prompt to save it.
- **Rename:** use names such as Everyday, Travel, or Backup at home.
- **Remove:** choose a registration and confirm. Removing the last registration
  leaves password authentication in place.
- **Refresh:** reload registrations changed by another tool.

Keykeep manages the standard Omarchy FIDO2 setup, using `/etc/fido2/fido2`.
If FIDO2 has never been configured, first enroll a key through Omarchy's
**Setup > Security > FIDO2** menu. Keykeep then manages additional keys.
Custom PAM origins, authfile paths, and pam-u2f defaults are currently rejected
with an explanation, rather than guessed.

Existing registrations have no device name or serial number. They initially
appear as Key 1, Key 2, etc., in file order, with a stable registration fingerprint.
Those generated numbers can change after removal; assign names before relying
on them. A fingerprint identifies a *registration*, not a physical device.
The same physical key can have multiple registrations. Keykeep does not currently
detect that duplication or identify which existing entry matches a plugged-in key.

Adding a key enrolls it; it is not a sudo authentication test. To verify it,
leave only that key connected and run `sudo -k -v`, then touch it when prompted.

The registration file is also used by polkit on standard Omarchy installations.
Removing a registration affects every service using this file. It does not erase
passkeys, SSH credentials, or any other data on the physical YubiKey.

## Command line

```sh
keykeep list --json
keykeep add "Backup at home" --json
keykeep rename FULL_REGISTRATION_ID "Travel key" --json
keykeep remove FULL_REGISTRATION_ID --yes --json
```

Use the full ID returned by `list`. Commands run without a display; saving an
addition or removal invokes `pkexec`, which may use a graphical authentication
agent or a terminal prompt. Run as your regular user. Exit status is 0 on success,
1 on failure. With `--json`, stdout contains JSON and progress/errors go to stderr.

`keykeep skill install` installs the bundled agent instructions under
`~/.agents/skills/keykeep/`.

## Keyboard

| Key | Action |
| --- | --- |
| Space / Ctrl+N | Add key |
| Up / Down | Select a registration when the list has focus |
| F2 | Rename selected registration |
| Delete | Confirm removal of selected registration |
| Ctrl+R | Refresh |
| ? | Show shortcuts |
| Q | Quit |

Typing in a dialog does not activate these shortcuts. The window stays open
while an operation is in progress. Enrollment can be cancelled before saving;
close the system authentication prompt to decline a save.

## Storage and recovery

The GUI runs unprivileged. Only `/usr/bin/keykeep --helper`, launched through
`pkexec`, writes the registration file. It derives the requesting user from
`PKEXEC_UID`, restricts edits to that user's row, checks ownership and file types,
locks concurrent Keykeep changes, rejects stale revisions, and writes atomically.
It neither edits PAM nor grants new sudo privileges.

Each successful addition or removal creates a root-only backup named
`/etc/fido2/fido2.backup.XXXXXX`. The backup path appears after saving. Restoring
one restores the *entire* mapping file, including other users and keys, so an
administrator should inspect it before replacing the current file.

Names are stored separately in `~/.local/share/keykeep/labels.json`, keyed by
registration fingerprint. They are descriptive and have no authentication role.
Removal keeps the label so restoring a registration also restores its name.
There is no automatic undo of an authentication change.

## Development

```sh
./bin/build
./bin/test
QT_QPA_PLATFORMTHEME=basic QT_QPA_PLATFORM=offscreen QT_QUICK_BACKEND=software \
  ./build/keykeep --preview docs/screenshot.png
```

C++ owns registration parsing, processes, and disk operations. Qt Quick owns the
interface. Tests use temporary directories for write operations and exercise
the real QML dialogs offscreen. Preview mode uses fictional names and cannot
change registrations. Theme accent, window rounding, and language follow Omarchy;
English and Danish are included, with English fallback for other languages.

The security key integration uses [Yubico's pam-u2f](https://developers.yubico.com/pam-u2f/).
Atomic name storage uses [Qt QSaveFile](https://doc.qt.io/qt-6/qsavefile.html).
Theme and translation templates are adapted from the Omarchy app conventions
(MIT, David Heinemeier Hansson).
