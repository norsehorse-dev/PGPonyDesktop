# Flathub packaging for PGPony Desktop

App ID: `org.pgpony.PGPony`. This directory holds the Flatpak manifest, the
AppStream metainfo, the desktop entry, and the launcher wrapper. None of it has
been built yet: this workspace has no flatpak-builder. Build and test on a Linux
machine with `flatpak-builder` before submitting to Flathub.

## Files

- `org.pgpony.PGPony.yaml` - the Flatpak manifest.
- `org.pgpony.PGPony.metainfo.xml` - AppStream metadata (needs a real screenshot URL).
- `org.pgpony.PGPony.desktop` - desktop entry under the app id.
- `pgpony-launcher` - launcher wrapper; preloads system FreeType (the AppRun fix).
- `gradle-sources.json` - GENERATED, not committed here. See below.

## 1. One-time prerequisites

```
flatpak install flathub org.flatpak.Builder
flatpak install flathub org.freedesktop.Platform//24.08 org.freedesktop.Sdk//24.08
flatpak install flathub org.freedesktop.Sdk.Extension.openjdk21//24.08
```

## 2. Generate the offline gradle sources

Flathub builds run with no network, so every gradle artifact (jars, POMs, the
Skiko native, and the Gradle distribution itself) must be listed with hashes and
pre-downloaded. Generate that list from the project's real dependency graph, with
network access, using the upstream generator:

```
git clone https://github.com/flatpak/flatpak-builder-tools
python3 flatpak-builder-tools/gradle/flatpak-gradle-generator.py \
  --output packaging/flathub/gradle-sources.json \
  ./gradlew createReleaseDistributable
```

Regenerate this file whenever the Gradle version or any dependency changes. It is
the one step that must run online; everything after it is offline.

Note: the generator resolves against a `--offline`-friendly build. If it struggles
with the Compose/Skiko native artifacts (they resolve per-OS), the fallback is to
pre-populate a local maven repo with `./gradlew ... --write-verification-metadata`
and point the manifest's `-Dmaven.repo.local` at it. Decide this before the first
Flathub PR; reviewers scrutinize the offline-ness of the build.

## 3. Build and test locally

```
flatpak run org.flatpak.Builder --force-clean --user --install \
  build-dir packaging/flathub/org.pgpony.PGPony.yaml
flatpak run org.pgpony.PGPony
```

Test matrix (a clean machine, not your dev box):

- The window opens; encrypt and decrypt a message round-trip.
- A smart card is seen (insert a reader; Cards tab enumerates it). If not, the
  `--socket=pcsc` grant or host `pcscd` is the suspect.
- The GTK file picker opens (the FreeType preload in `pgpony-launcher` is what
  keeps it from opening blank).
- The composite ML-DSA path: generate an ML-DSA key, sign and verify, encrypt a
  message to it and decrypt.
- The ssh-agent: enable it in Settings, confirm the `SSH_AUTH_SOCK` it prints is
  under `$XDG_RUNTIME_DIR/app/org.pgpony.PGPony/`, and that a host
  `SSH_AUTH_SOCK=... ssh-add -l` reaches it through the `--filesystem=xdg-run`
  grant. If the socket cannot be shared, ship the agent off by default on Flatpak
  and note it in the release.
- The git signing shim: point host git at it and confirm a signed commit verifies:

```
git config --global gpg.program "flatpak run --command=pgpony-gpg org.pgpony.PGPony"
```

## 4. Verify the AppStream and desktop files

```
flatpak run --command=flatpak-builder-lint org.flatpak.Builder manifest packaging/flathub/org.pgpony.PGPony.yaml
flatpak run --command=flatpak-builder-lint org.flatpak.Builder appstream packaging/flathub/org.pgpony.PGPony.metainfo.xml
```

Replace the placeholder screenshot URL in the metainfo with a real hosted PNG
(a `raw.githubusercontent.com` path under `docs/screenshots/` works) before this
passes.

## 5. Submit

1. Verify domain ownership of `pgpony.app` for the `org.pgpony.PGPony` id: add the
   Flathub `.well-known` file or DNS TXT record Flathub asks for.
2. Fork `github.com/flathub/flathub`, branch `org.pgpony.PGPony`.
3. Add the manifest (with a `git` source pinned to the release tag, not the local
   `dir` source) plus `gradle-sources.json`.
4. Open the new-app pull request; respond to the review (the build offline-ness and
   the finish-args breadth get the most scrutiny).
5. On acceptance, add a Flathub badge to the README beside the AUR and AppImage.

## Open decisions carried from FLATHUB_PLAN.md

- The `--filesystem=home` grant is broad; a portal-based file picker would narrow
  it, but Compose Desktop uses an AWT chooser today.
- The agent socket path must match what the app actually writes; confirm the app
  puts it under `$XDG_RUNTIME_DIR/app/org.pgpony.PGPony/` under Flatpak, and adjust
  the app or the `--filesystem` grant if not.
