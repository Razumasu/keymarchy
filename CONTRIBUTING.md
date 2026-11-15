# Contributing

Contributions are welcome through issues and pull requests. Work on a branch
or fork, describe the change and its validation, and wait for review.
[Razu (@Razumasu)](https://github.com/Razumasu) maintains Keymarchy and decides
which changes are merged and released. Opening a pull request or passing CI
does not mean the change has been accepted.

## Development

Build with `./bin/build` and run `./bin/test` on Arch Linux or Omarchy.
`./bin/install` also runs the tests before installing the package. The test
suite uses temporary files; it does not enroll or remove real security keys.
GitHub Actions builds, tests, installs, and inspects the package in a clean
Arch Linux container on x86_64 as well. Package recipes also declare aarch64,
but the current GitHub workflow does not validate that architecture.

Keep registration writes in the privileged helper and run the interface as a
regular user. The helper must not take a registration from its caller, and it
should link nothing beyond QtCore. Changes to registration parsing, persistence,
or device detection need focused tests. Changes to dialogs should exercise the
real QML offscreen.
Describe which keys or environments you used for hardware checks; automated
tests do not replace testing with real authenticators.

Use fictional names in screenshots. Do not attach your registration file,
labels file, authenticator serial numbers, or private authentication data to
issues or pull requests.

## Releasing

Releases require the maintainer's approval. Prepare and review the source and
packaging changes before merging, tagging, or publishing.

1. Update both the application version and help banner in `src/main.cpp`,
   update `pkgver` in `pkgbuild/PKGBUILD`, reset `pkgrel` to `1`, and describe
   user-facing changes in `CHANGELOG.md`.
2. Run the tests and package build. Check GitHub Actions for the exact commit.
3. Tag that commit `vVERSION` and publish a GitHub Release with release notes.
   Do not move published tags; fixes get a new version.
4. In the separate AUR packaging checkout, update `pkgver`, reset `pkgrel` to
   `1`, and calculate the SHA-256 of the GitHub tag archive. Build from that
   archive in a clean environment before pushing. Verify that the package
   contains the app, `/usr/lib/keymarchy/keymarchy-helper`, and its polkit policy.
   Generate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO` and commit both
   files. Only packaging files belong in the AUR repository, not this source tree.
5. The Omarchy package recipe watches GitHub Releases after its submission
   is accepted. Verify that its update PR builds and that the package reaches
   the intended channel. A release or a merged PR alone does not mean the
   package is available in Omarchy stable.
6. Check the README's installation status and links, GitHub description and
   release notes, and any pending package submission against the new release.
   Keep the bundled instructions in `docs/AGENT_SKILL.md` in sync with the CLI.

The AUR package has not been published, and the
[Omarchy submission](https://github.com/omacom/omarchy-pkgs/pull/2776) is still
pending review. Until it is accepted, update the recipe in that submission
when publishing a release; its release watcher is not active yet.

`pkgbuild/PKGBUILD` builds a local source checkout for development. Distribution
recipes instead download the versioned release archive, verify its SHA-256,
and build inside `$srcdir/keymarchy-$pkgver`. Packaging fixes without an upstream
change increment `pkgrel`.
