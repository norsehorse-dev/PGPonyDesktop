# Flathub packaging for PGPony Desktop

App ID: `app.pgpony.PGPony`. The ID has to name a domain we control, reversed: `app.pgpony`
is `pgpony.app`, which is what Flathub verifies (step 6). The earlier draft used
`org.pgpony.PGPony`, which would have needed `pgpony.org`.

Everything here is built and tested on a Linux x86_64 machine; macOS cannot run
flatpak-builder. The Flatpak is x86_64 only for now (`flathub.json`): the Skiko runtime in the
generated sources is the one for the machine that generated them. aarch64 means a second
generation run on an ARM Linux machine and `only-arches` entries per architecture.

## Files

- `app.pgpony.PGPony.yaml`: the manifest.
- `app.pgpony.PGPony.metainfo.xml`: AppStream metadata. A release entry per version.
- `app.pgpony.PGPony.desktop`: the desktop entry.
- `app.pgpony.PGPony.mime.xml`: the `.pgpony` backup type.
- `pgpony-launcher`: `/app/bin/pgpony`, preloads the runtime's FreeType (issue #1) and starts
  the app image.
- `pgpony-gpg`, `pgpony-sop`: the git signing shim and the SOP command line, as commands inside
  the Flatpak.
- `gradle.properties`: Gradle settings for the Flatpak build only.
- `generate-sources.init.gradle`: writes `gradle-sources.json` (step 2).
- `offline.init.gradle`: points the offline build at the downloaded artifacts.
- `gradle-sources.json`: generated, every Maven artifact the build resolves with its URL and
  checksum. Regenerate whenever Gradle or a dependency changes.
- `flathub.json`: the architectures Flathub builds.

## 1. One-time setup on the Linux machine

A JDK 17 on the host (for step 2 only; the Flatpak build uses the SDK extension), flatpak, and
the Flathub remote.

```
flatpak install -y flathub org.flatpak.Builder org.freedesktop.Platform//25.08 org.freedesktop.Sdk//25.08 org.freedesktop.Sdk.Extension.openjdk17//25.08
git clone https://github.com/norsehorse-dev/PGPonyDesktop.git
```

## 2. Generate the offline sources

The one step that needs the network. It resolves the project's real dependency graph and
writes `packaging/flathub/gradle-sources.json`.

```
cd PGPonyDesktop
./gradlew --no-configuration-cache --init-script packaging/flathub/generate-sources.init.gradle flatpakGradleGenerator
```

## 3. Build, install and run

The build and state directories live beside the checkout, not in it, so the `dir` source never
copies them into itself.

```
flatpak run org.flatpak.Builder --force-clean --user --install --install-deps-from=flathub --state-dir=../pgpony-flatpak-state --repo=../pgpony-flatpak-repo ../pgpony-flatpak-build packaging/flathub/app.pgpony.PGPony.yaml
flatpak run app.pgpony.PGPony
```

If the offline build stops on an artifact it cannot find, that artifact was resolved outside
the configurations the generator walks (a plugin marker or a detached configuration). The
error names it; it goes into `gradle-sources.json` as one more entry.

## 4. Test matrix

On a clean machine or user, not a development box with PGPony already set up:

- The window opens on an X11 session and on a Wayland session (through XWayland).
- Encrypt and decrypt a message and a file round-trip; the file chooser opens with its contents
  drawn (the FreeType preload).
- Hardware Keys lists a reader and a card (`--socket=pcsc` and the bundled pcsc-lite; the host
  needs `pcscd` running).
- Generate an ML-DSA key; sign and verify, encrypt to it and decrypt.
- Settings has no Updates section (Flathub delivers updates).
- The offline switch and a proxy both hold: with offline on, a keyserver search is refused.
- Import from GnuPG reads `~/.gnupg` and says secret keys need gpg outside the sandbox.
- Watch folders pick up a new file in a folder under home.
- The clipboard sentinel: note whether it sees copies made in native Wayland apps, not only X11
  ones, before the release notes say anything about it.
- The ssh-agent: turn it on in Settings. The socket it shows is under
  `~/.var/app/app.pgpony.PGPony/data/pgpony/agent/`, a host path, so a host shell can use it:

```
export SSH_AUTH_SOCK="$HOME/.var/app/app.pgpony.PGPony/data/pgpony/agent/agent.sock"
ssh-add -l
```

- The git signing shim: host git runs `gpg.program` as a single program, so it goes through a
  small host wrapper. Then a signed commit verifies:

```
mkdir -p ~/.local/bin
printf '#!/bin/sh\nexec flatpak run --command=pgpony-gpg app.pgpony.PGPony "$@"\n' > ~/.local/bin/pgpony-gpg
chmod +x ~/.local/bin/pgpony-gpg
git config --global gpg.program ~/.local/bin/pgpony-gpg
```

- SOP from the host:

```
flatpak run --command=pgpony-sop app.pgpony.PGPony version
```

## 5. Lint

```
flatpak run --command=flatpak-builder-lint org.flatpak.Builder manifest packaging/flathub/app.pgpony.PGPony.yaml
flatpak run --command=flatpak-builder-lint org.flatpak.Builder repo ../pgpony-flatpak-repo
```

The repo lint fetches the screenshots, so `docs/screenshots/keyring.png` and
`docs/screenshots/crypto.png` (taken from this build, around 1600x900) must be on `main` first.

## 6. Submit

1. Verify `pgpony.app` for the app ID: Flathub gives a token to publish at
   `https://pgpony.app/.well-known/org.flathub.VerifiedApps.txt`.
2. Fork `github.com/flathub/flathub` and branch from `new-pr`.
3. Add the manifest, `gradle-sources.json` and `flathub.json`. The other files the manifest
   installs come from the source tree at the tag, so only those three go in. In the submitted
   manifest, replace the `dir` source with the release:

```
      - type: git
        url: https://github.com/norsehorse-dev/PGPonyDesktop.git
        tag: v3.0.0
        commit: <the tag's commit>
```

4. Open the pull request against `new-pr`. Review looks hardest at the offline build and at
   `--filesystem=home`; the reason for the home grant is in the manifest beside it.
5. On acceptance, add the Flathub badge to the README and the download page.

## What is different under Flatpak

`Flatpak.kt` detects the sandbox. Inside it:

- Settings live in `~/.var/app/app.pgpony.PGPony/config`, beside the keyring in
  `~/.var/app/app.pgpony.PGPony/data`, so a Flatpak and an AppImage, AUR or .deb install on the
  same account do not share settings while keeping separate keyrings. Moving a keyring between
  them is a `.pgpony` backup and restore.
- javax.smartcardio uses the bundled `libpcsclite.so.1` from `/app/lib`.
- No update check; the Updates section is hidden.
- Import from GnuPG reads public keys and trust only; there is no gpg in the sandbox.
- "Until the screen locks" is not offered: there is no `loginctl` in the runtime to read the
  lock state, so the passphrase cache offers the timed choices and "until cleared".
- File manager context menus are out of scope: a Flatpak cannot install them into the host's
  file manager.
