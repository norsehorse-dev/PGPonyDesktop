# Flathub distribution plan for PGPony Desktop

Status: superseded in 3.0.0 (stage 5c) by `packaging/flathub/README.md`, which holds the
decisions and the procedure. Kept for the reasoning. Two things changed from this draft: the app
ID is `app.pgpony.PGPony` (it has to reverse a domain we control, pgpony.app), and the sandbox
takes `--socket=x11` rather than Wayland, because Compose Desktop on JDK 17 draws through AWT,
which is X11 only.

Target: publish PGPony to Flathub as a third Linux channel beside the AppImage and the AUR
package.

PGPony Desktop is a Compose Desktop (Skiko) app packaged today by jpackage with
a bundled jlink runtime. It talks to smart cards through javax.smartcardio and
libpcsclite, serves an ssh-agent and a git signing shim (2.0.x), and watches the
clipboard. Each of those is a Flatpak sandbox question, so the plan is as much
about finish-args as about the build.

## 1. The build is the hard part: no network at build time

Flathub builds run offline. A gradle build that resolves dependencies from the
network will fail. The options, in order of preference:

- Pre-generate a Flatpak sources manifest for every gradle artifact (jars, POMs,
  Skiko native, Room, BouncyCastle, Compose) with hashes, using a gradle sources
  generator, and run gradle in the build sandbox with --offline against a local
  maven repo assembled from those sources. This is the Flathub-idiomatic path and
  the one reviewers expect.
- Fallback: build the jlink image in CI outside Flathub and have the Flatpak
  manifest consume that prebuilt tarball as a source. Flathub discourages
  bundling prebuilt binaries and will push back in review, so treat this as a
  stopgap only.

Decision needed: commit to the offline-gradle path before writing the manifest.

## 2. Runtime and SDK

- Base: org.freedesktop.Platform / Sdk, current stable runtime.
- Java: org.freedesktop.Sdk.Extension.openjdk, or build our own jlink runtime in
  the build step from that extension's JDK so the shipped image matches jpackage.
  Match the JDK major the repo already builds against (17+).
- Native libraries the app needs at runtime and that the manifest must ensure are
  present: fontconfig and freetype (Skiko and the GTK file chooser, same
  freetype-sharing issue the AppRun script solves with LD_PRELOAD, revisit under
  Flatpak where the runtime provides one freetype), Mesa/dri for GL, and
  libpcsclite for smart cards.

## 3. finish-args (the sandbox holes, each justified)

- --share=network. Keyserver, WKD, VKS lookups and Tor proxy.
- --socket=wayland and --socket=fallback-x11. Compose/Skiko UI.
- --socket=pcsc. Reaches the host pcscd socket so javax.smartcardio sees readers.
  Without it every hardware-key feature is dead, the same reason pcsclite is a
  hard depend in the AUR and .deb packages.
- --device=dri. GPU for Skiko.
- --socket=session-bus with a scoped talk name, or portal use, for tray and
  notifications.
- --filesystem for user documents through the portal where possible; the file
  picker should go through the desktop portal rather than a broad home grant.

## 4. Sandbox tensions that need a real answer, not a flag

These are the parts a phone never had and that the sandbox fights:

- The served ssh-agent (2.0.x pillar 1a). PGPony creates a unix socket and prints
  SSH_AUTH_SOCK for host ssh and git to use. A socket created inside the sandbox
  is not visible to host tools unless it lands on a shared path. Plan: place the
  agent socket under a host-visible directory the app is granted
  (for example --filesystem=xdg-run/pgpony), document the exact SSH_AUTH_SOCK
  path, and verify a host ssh actually connects. If the socket cannot be shared
  cleanly, the agent ships disabled on Flatpak and the AppImage/AUR remain the
  channel for it.
- The git signing shim pgpony-gpg (2.0.x pillar 1b). Host git runs whatever
  gpg.program names. A Flatpak app is invoked as `flatpak run`, so the shim on
  Flatpak means documenting a gpg.program wrapper that calls
  `flatpak run --command=pgpony-gpg org.pgpony.PGPony`, and confirming stdin and
  the status fd survive that hop.
- File-manager context menus (2.0.x pillar 2a). Flatpak cannot install host
  Nautilus/KDE service menus from inside the sandbox. This pillar is host-package
  only; on Flatpak it is out of scope, state that plainly in the release notes.
- Clipboard sentinel (2.0.x pillar 2b). Works under X11; Wayland clipboard
  polling is restricted, so the sentinel may be X11-only under Flatpak. Verify
  before claiming it.

## 5. Metadata and assets

- App ID: org.pgpony.PGPony (confirm domain ownership for the reverse-DNS id, or
  choose an id we can defend in review).
- AppStream metainfo XML: summary, description, screenshots, release entries,
  content rating. Reuse the existing packaging/pgpony.desktop and pgpony.png,
  add a 128 and 256 icon set.
- Desktop file and icons already exist under packaging/; adapt the .desktop for
  the Flatpak app id.

## 6. Submission steps

1. Land the offline-gradle build locally and produce a reproducible jlink image.
2. Write org.pgpony.PGPony.yaml (manifest) plus the generated sources file.
3. Build and test in a clean flatpak-builder run: UI opens, a smart card is seen,
   encrypt/decrypt round-trips, the file portal works.
4. Resolve the ssh-agent and git-shim questions in section 4, or ship them
   disabled with a documented reason.
5. Fork flathub/flathub, open a new-app pull request with the manifest, respond
   to reviewer feedback (they will scrutinize the build offline-ness and the
   finish-args breadth).
6. On acceptance, add a Flathub badge to the README beside the AUR and AppImage,
   and fold the metainfo release entries into the release process.

## Open questions

- App id and domain for the reverse-DNS identifier.
- Whether the ssh-agent and git shim ship enabled on Flatpak or wait for a follow
  up once the socket sharing is proven.
- Whether to maintain the manifest in this repo or in the flathub org repo only.
