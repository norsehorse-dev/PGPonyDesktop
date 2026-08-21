# Releasing PGPony Desktop from a Claude session

Session-facing summary of the release process, written after cutting v1.1.0 (Aug 2026).
The authoritative procedure is `RELEASING.md` in this repo; the site half is
`~/Apps/PonyHTML/DEPLOY.md`. This file records the sequence plus what a Claude session
can and cannot do, so the next release doesn't relearn it. Read `CLAUDE.md` first; its
rules (no AI attribution, command blocks with only runnable commands) apply throughout.

## The sequence

1. **Version bump.** `AppVersion.VERSION` in `src/main/kotlin/com/pgpony/desktop/Config.kt`
   (the const lives in `object AppVersion`, not `object Config`) and `packageVersion` in
   `build.gradle.kts` move together. `VersionDriftTest` enforces agreement since 1.1.0.
2. **Tests, then commit and push.** The push is a prerequisite of the tag, not optional:
   CI builds from the pushed tree, and a tag on uncommitted work releases without it.
3. **Tag** `vX.Y.Z`, push the tag, watch CI (`RELEASING.md` §2; keep the `sleep 15` before
   `gh run list` or you watch the previous run). Three jobs produce six Linux artifacts and
   the msi into a **draft** release.
4. **On the Mac:** `source ~/.pgpony-release-env`, `./gradlew clean notarizeDmg` with the
   teamID property, `stapler validate`, then `spctl -a -t exec` on the app inside the
   mounted dmg. Must say `Notarized Developer ID`. Minutes of silence at notarization is
   Apple, not a hang. Gotchas in §3 (identity by name, single cert in keychain).
5. **Assemble and publish** in `~/pgpony-release` (§4): download the draft assets, copy the
   dmg in as `PGPony-macOS.dmg`, build the 8-name `FILES` **zsh array** (never a string),
   `shasum -a 256` into `SHA256SUMS`, sign all nine with
   `gpg -u A0CBC8F65AACE56F1C5B767753F9798E4919DE62`, verify nine Good signatures, upload,
   then `gh release edit --draft=false --latest`. `--latest` is load-bearing: the stable
   `releases/latest/download/` URLs follow the flag, not the newest tag.
6. **Release notes** are drafted to `_to_delete/RELEASE_NOTES_X_Y_Z.md` and passed via
   `--notes-file`. Draft them per the `my-writing-style` skill (hard rule: no em dashes).
7. **The site:** update `PonyHTML/pgpony/downloads/desktop.json` (drives `/desktop`, the
   download buttons, the checksums, and the app's own update check). Readiness gate: every
   `sha256` must be 64 hex chars or the page shows holding text. Prepend the outgoing
   version to `previous`. Then the onion/i2p mirror: all installers, `.asc` files and
   `SHA256SUMS` (~300 MB) into `/var/www/pgpony/downloads/` via the `/tmp` + `sudo`
   pattern. Full site procedure: `PonyHTML/DEPLOY.md`.
8. **winget** manifests in `winget/<version>/`: `InstallerSha256` from `SHA256SUMS`, and
   `ProductCode` read from the built msi (it is NOT the `upgradeUuid` in build.gradle.kts).
9. **AUR last** (§7): bump `packaging/aur/PKGBUILD` and `.SRCINFO`, push to the AUR repo's
   **master** branch. Last because the PKGBUILD 404s while the release is a draft.
   `pcsclite` is a hard dependency there.

## What a Claude session can and cannot do (learned on 1.1.0)

- **The cloud sandbox cannot build.** Maven Central and the Gradle distribution are
  unreachable from it, so no `gradlew` anything in the cloud. `git clone` from github.com
  works, and ktlint (downloaded from GitHub releases) works as a parse check. Real compile
  and test runs happen on Kevin's Mac, by Kevin.
- **`device_bash` runs in a local Linux VM**, not on the Mac: no network, no JDK
  guarantees, no keychain, and it cannot delete files. It CANNOT run git cleanly: a bare
  `git status` leaves a stale `.git/index.lock` it cannot unlink. If that happens, `mv` the
  lock into `_to_delete/`. Prefer read-only use.
- **Kevin runs every git, gh, gradle, gpg and ssh command himself.** The session's job is
  to prepare files and hand over paste-ready blocks (no comments inside blocks, zsh
  semantics, arrays not strings).
- **Files written to the Mac via the bridge land as mode 0600.** Anything server-bound gets
  an explicit `chmod 644` on the server side. This has caused real 403s.
- Real checksums can be fetched in the cloud once the release is published:
  `https://github.com/norsehorse-dev/PGPonyDesktop/releases/download/vX.Y.Z/SHA256SUMS`.
  Verify all eight names against the artifact list before writing them anywhere.

## After publishing

`curl https://pgpony.app/downloads/desktop.json` parses and shows the new version;
`/desktop` shows buttons and checksums, not holding text; then the `RELEASING.md` §6
verification checklist (stapler, spctl, clean-machine installs, CLI prints on every OS,
file associations route, hardware key still works).
