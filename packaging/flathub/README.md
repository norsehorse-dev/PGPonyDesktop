# Flathub packaging for PGPony Desktop

App ID: `app.pgpony.PGPony`. The ID has to name a domain we control, reversed: `app.pgpony`
is `pgpony.app`, which is what Flathub verifies (step 6). The earlier draft used
`org.pgpony.PGPony`, which would have needed `pgpony.org`.

Everything here is built and tested on Linux (an aarch64 Debian VM so far); macOS cannot run
flatpak-builder. The Flatpak targets x86_64 and aarch64. `gradle-sources.json` covers both from
one run on either: the Skiko and Compose natives for the other architecture are added with
`only-arches`.

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
- `gradle-cache-sources.py`: writes `gradle-sources.json` from an online build's Gradle cache
  (step 2).
- `offline.init.gradle`: points the offline build at the downloaded artifacts.
- `gradle-sources.json`: generated, every Maven artifact the build downloads with its URL and
  checksum. Regenerate whenever Gradle or a dependency changes.

## 1. One-time setup on the Linux machine

flatpak, the Flathub remote, the builder, and the runtime, SDK and OpenJDK 17 extension. No
JDK on the host: step 2 runs Gradle inside the SDK with the same JDK the Flatpak build uses.

```
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install --user -y flathub org.flatpak.Builder org.freedesktop.Platform//26.08 org.freedesktop.Sdk//26.08 org.freedesktop.Sdk.Extension.openjdk17//26.08
git clone https://github.com/norsehorse-dev/PGPonyDesktop.git
```

## 2. Generate the offline sources

The one step that needs the network. A real `createDistributable` runs online, inside the SDK,
against an empty Gradle home; then `gradle-cache-sources.py` lists every file that build
downloaded, with the repository that serves it and its sha256. Listing what a build actually
fetched, rather than walking its configurations, also catches what Gradle resolves on the fly
(Compose's `checkRuntime` probe is one). The first run compiles the whole app, so it takes a
while.

```
cd PGPonyDesktop
mkdir -p ../pgpony-gradle-cache
cp packaging/flathub/gradle.properties ../pgpony-gradle-cache/
flatpak run --share=network --filesystem="$PWD" --filesystem="$(realpath ../pgpony-gradle-cache)" --env=JAVA_HOME=/usr/lib/sdk/openjdk17/jvm/openjdk-17 --env=GRADLE_USER_HOME="$(realpath ../pgpony-gradle-cache)" --command="$PWD/gradlew" org.freedesktop.Sdk//26.08 -p "$PWD" --no-daemon createDistributable
python3 packaging/flathub/gradle-cache-sources.py ../pgpony-gradle-cache > packaging/flathub/gradle-sources.json
```

The script prints how many sources it wrote and names any file no repository serves; that list
should be empty. To regenerate, empty `../pgpony-gradle-cache` first (keep its `wrapper/`
folder to skip downloading Gradle again), so the list holds only what the current build uses.

## 3. Build, install and run

The build and state directories live beside the checkout, not in it, so the `dir` source never
copies them into itself.

```
flatpak run org.flatpak.Builder --force-clean --user --install --install-deps-from=flathub --state-dir=../pgpony-flatpak-state --repo=../pgpony-flatpak-repo ../pgpony-flatpak-build packaging/flathub/app.pgpony.PGPony.yaml
flatpak run app.pgpony.PGPony
```

If the offline build stops on an artifact it cannot find, the online build in step 2 did not
download it: check that step 2 ran the same task (`createDistributable`) with the same
`gradle.properties`, then regenerate.

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

The screenshots, `docs/screenshots/keyring.png` and `docs/screenshots/crypto.png` (taken from
this build, around 1600x900, demo keys with example.com identities), must be on `main` first.

What a clean local run still reports, and why each is expected:

- `finish-args-home-filesystem-access` (both lints). An error until Flathub grants an exception
  for the app; the case for it goes in the submission (step 6).
- `appstream-external-screenshot-url` and `appstream-screenshots-not-mirrored-in-ostree` (repo
  lint only). Flathub's own build mirrors the screenshots to dl.flathub.org; a local build does
  not unless asked to. To check that part locally too, build with the mirror option and commit
  the screenshots into the repo before linting:

```
flatpak run org.flatpak.Builder --force-clean --user --install-deps-from=flathub --mirror-screenshots-url=https://dl.flathub.org/media/ --state-dir=../pgpony-flatpak-state --repo=../pgpony-flatpak-repo ../pgpony-flatpak-build packaging/flathub/app.pgpony.PGPony.yaml
flatpak run --command=ostree org.flatpak.Builder commit --repo=../pgpony-flatpak-repo --canonical-permissions --branch=screenshots/$(uname -m) ../pgpony-flatpak-build/screenshots
flatpak run --command=flatpak-builder-lint org.flatpak.Builder repo ../pgpony-flatpak-repo
```

## 6. Submit

1. Verify `pgpony.app` for the app ID: Flathub gives a token to publish at
   `https://pgpony.app/.well-known/org.flathub.VerifiedApps.txt`.
2. Fork `github.com/flathub/flathub` and branch from `new-pr`.
3. Add the manifest and `gradle-sources.json`. The other files the manifest installs come from
   the source tree at the tag, so only those two go in. In the submitted
   manifest, replace the `dir` source with the release:

```
      - type: git
        url: https://github.com/norsehorse-dev/PGPonyDesktop.git
        tag: v3.0.0
        commit: <the tag's commit>
```

4. Open the pull request against `new-pr`, and ask in it for the
   `finish-args-home-filesystem-access` exception. The case: PGPony encrypts, decrypts, signs and
   verifies files and whole folders the user picks, and watch folders process directories on
   their own as files arrive. Compose Desktop's file chooser is AWT's, which does not go through
   the file chooser portal, so a portal grant cannot reach the files; the pass store
   (`~/.password-store`) and GnuPG import (`~/.gnupg`) read fixed folders in home as well. Review
   also looks hard at the offline build.
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
