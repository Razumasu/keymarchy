# Contributing

Build with `./bin/build` and run `./bin/test` on Arch Linux or Omarchy.
`./bin/install` also runs the tests before installing the package. The test
suite uses temporary files; it does not enroll or remove real security keys.
GitHub Actions builds, tests, installs, and inspects the package in a clean
Arch Linux container as well.

Keep registration writes in the privileged helper and run the interface as a
regular user. Changes to registration parsing, persistence, or device detection
need focused tests. Changes to dialogs should exercise the real QML offscreen.
Describe which keys or environments you used for hardware checks; automated
tests do not replace testing with real authenticators.

Use fictional names in screenshots. Do not attach your registration file,
labels file, authenticator serial numbers, or private authentication data to
issues or pull requests.

## Releasing

1. Update the version in `src/main.cpp` and `pkgbuild/PKGBUILD`, and describe
   user-facing changes in `CHANGELOG.md`.
2. Run the tests and package build. Check GitHub Actions for the exact commit.
3. Tag that commit `vVERSION` and publish a GitHub Release with release notes.
   Published tags are immutable; fixes get a new version.
4. In the separate AUR packaging checkout, update `pkgver`, reset `pkgrel` to
   `1`, and calculate the SHA-256 of the GitHub tag archive. Build from that
   archive in a clean environment before pushing. Generate `.SRCINFO` with
   `makepkg --printsrcinfo > .SRCINFO` and commit both files. Only packaging
   files belong in the AUR repository, not this source tree.
5. The Omarchy package recipe watches GitHub Releases after its submission
   is accepted. Verify that its update PR builds and that the package reaches
   the intended channel. A release or a merged PR alone does not mean the
   package is available in Omarchy stable.

`pkgbuild/PKGBUILD` builds a local source checkout for development. Distribution
recipes instead download the versioned release archive, verify its SHA-256,
and build inside `$srcdir/keymarchy-$pkgver`. Packaging fixes without an upstream
change increment `pkgrel`.
