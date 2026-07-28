# Releasing PGPony Desktop

Each release ships eight artifacts — a signed and notarized **`.dmg`** (macOS, arm64), an
**`.msi`** (Windows, x64), and six for Linux: a **`.deb`**, a portable **`.tar.gz`** and an
**`.AppImage`**, each for both **x86_64** and **ARM64** — plus a detached `.asc` for every one of
them and a signed `SHA256SUMS` covering the lot. Arch Linux is served separately by the
`pgpony-bin` AUR package, which pulls the tarballs (see §7).

The x86_64 `.deb` keeps its historic asset name, `PGPony-linux.deb`. Only the ARM one carries an
architecture suffix, so links published before 1.0.3 keep working.

`jpackage` only builds for the OS it runs on, so the work is split:

| Where | What |
| --- | --- |
| **CI**, on a tag push | the six Linux artifacts + the `.msi`, into a **draft** release |
| **Your Mac** | the `.dmg`, notarization, every PGP signature, and publishing the draft |

**This repository holds no secrets.** The Developer ID certificate never reaches a hosted
runner, and neither does the PGP release key — which, for an OpenPGP application signing its own
releases, is the point. This is also the plan of record (§D0-5: "CI producing unsigned
artifacts, signing done locally at release time").

## 1. Before tagging

Bump **both** version numbers, and check they agree:

- `AppVersion.VERSION` in `src/main/kotlin/com/pgpony/desktop/Config.kt`
- `packageVersion` in `build.gradle.kts`

They had silently drifted before D13 — the bundle said `1.0.0` while the app reported
`1.0.0-dev.D1`, and that string is also written into every `.pgpony` backup as `appVersion`
metadata. Nothing warns you; it is visible only in a built `Info.plist`.

Then make sure everything is committed and pushed. A tag on a tree with uncommitted work
produces a release that does not contain it.

```sh
git status --short
git push
```

## 2. Tag — CI builds the Linux artifacts and the msi

```sh
git tag v1.0.3
git push origin v1.0.3
sleep 15
gh run watch $(gh run list --workflow=release.yml --limit 1 \
  --json databaseId --jq '.[0].databaseId')
```

The `sleep` matters: `gh run list` fires before the new run registers and happily hands you the
*previous* run's id, which then reports success for work you are not watching.

Three build jobs now — `linux (x86_64)`, `linux (aarch64)` and `windows`. The two Linux legs are
one matrix job, deliberately: an ARM lane maintained as a copy of the x86_64 lane drifts, and a
lane that drifts is a lane whose assertions quietly stop covering it.

`ubuntu-24.04-arm` runners are GA and free on public repositories. jpackage cannot cross-compile,
so the ARM artifacts genuinely require an ARM machine — there is no flag that avoids this.

This opens a **draft** release with the two installers attached. Draft is deliberate: a release
published with one installer missing, no signatures and no `SHA256SUMS` is visible to anyone
watching the repo, and `/desktop` would start linking assets that are not there.

CI also runs two checks whose failure a green build would otherwise hide:

- `dpkg-deb -f … Depends` must mention `pcsc`. The dependency is injected through the jpackage
  task's `freeArgs` because Compose's `linux {}` block has no dependency field, and that lookup
  degrades to a silent no-op if the property ever moves. Hardware keys are dead without it.
- the `.desktop` entry must carry a `MimeType` line — the OS half of the D9 file-association
  work, without which `DesktopFileRouter` never gets handed a file.

## 3. On the Mac — the dmg

Keep the four notarization values in a file outside the repo, `chmod 600`:

```sh
source ~/.pgpony-release-env
./gradlew clean notarizeDmg -Pcompose.desktop.mac.notarization.teamID="$NOTARIZATION_TEAM_ID"
xcrun stapler validate build/compose/binaries/main/dmg/PGPony-*.dmg
```

Expect several minutes of apparent inactivity at the notarization step. That is Apple's service,
not a hang.

Gotchas, all three learned the hard way and all three still current:

- `MACOS_SIGN_IDENTITY` must be the certificate **name**, not its SHA-1 hash — Compose looks it
  up by name and fails with "Could not find certificate for …" otherwise.
- Only **one** `Developer ID Application` certificate may be in the keychain, or codesign reports
  "multiple matching certificates". List them with `security find-identity -v -p codesigning`
  and delete keyless extras with `security delete-certificate -Z <hash>`.
- The team ID goes through `-Pcompose.desktop.mac.notarization.teamID=…`. The DSL `teamId`
  property does not exist in Compose 1.11.1.

**The dmg container is deliberately unsigned.** Compose signs the `.app`, notarizes it, and
staples the ticket to the disk image without signing the wrapper. That is why
`spctl -a -t open --context context:primary-signature` **rejects** a perfectly good release with
`source=no usable signature` — it is asking an unsigned container a signature question. The
checks that mean something are the app inside it, and a quarantined open:

```sh
hdiutil attach build/compose/binaries/main/dmg/PGPony-*.dmg -nobrowse -mountpoint /tmp/pgponydmg
spctl -a -t exec -vv /tmp/pgponydmg/PGPony.app
hdiutil detach /tmp/pgponydmg
```

That must print `accepted` and `source=Notarized Developer ID`.

## 4. Assemble, sign, publish

Pull CI's two installers down beside your dmg, then sign all three together so `SHA256SUMS`
covers the exact bytes that ship.

```sh
mkdir -p ~/pgpony-release && cd ~/pgpony-release
gh release download v1.0.3 --repo norsehorse-dev/PGPonyDesktop --dir .
cp /Users/kevinstewart/Apps/PGPonyDesktop/build/compose/binaries/main/dmg/PGPony-*.dmg \
   PGPony-macOS.dmg

FILES="PGPony-macOS.dmg PGPony-linux.deb PGPony-linux-x86_64.tar.gz PGPony-x86_64.AppImage \
PGPony-linux-arm64.deb PGPony-linux-aarch64.tar.gz PGPony-aarch64.AppImage PGPony-windows.msi"

shasum -a 256 $FILES > SHA256SUMS
cat SHA256SUMS
for f in $FILES SHA256SUMS; do
  gpg -u A0CBC8F65AACE56F1C5B767753F9798E4919DE62 --armor --detach-sign "$f"
done
for f in $FILES SHA256SUMS; do
  gpg --verify "$f.asc" "$f"
done
shasum -a 256 -c SHA256SUMS
```

The explicit `-u` is not decoration: a bare `gpg --detach-sign` failed with "no default secret
key" during the 1.0.1 cycle. Nine signatures now, not four — check the `gpg --verify` loop
printed nine `Good signature` lines before going any further.

Verify before publishing, not after. A signature that does not check out is worse than none.

```sh
gh release upload v1.0.3 PGPony-macOS.dmg *.asc SHA256SUMS \
  --repo norsehorse-dev/PGPonyDesktop
gh release edit v1.0.3 --draft=false --latest --repo norsehorse-dev/PGPonyDesktop
```

`--latest` is load-bearing. `releases/latest/download/…` — the stable, versionless URLs handed
out in the README and used by anyone scripting an install — resolve to whichever release carries
the "latest" flag, not to the newest tag. A release published without it leaves those links
pointing at the previous version, silently and indefinitely.

Keep `~/pgpony-release` until the site steps below are done — the checksums are needed there.

## 5. After the release — the site

None of this is automated, and all of it is easy to forget. `/desktop` shows "publishing in
progress" until the checksums land, so the page stays honest if you stop halfway.

1. **Fill `downloads/desktop.json`** — `version`, `released`, `tag`, `notes`, and the three
   `sha256` values, copied out of `SHA256SUMS`. The readiness gate keys on those being 64 hex
   characters; anything else and the page keeps showing the holding text. `tag` is what builds
   the GitHub download URLs, so a stale `tag` means dead links.
2. **Upload the mirror.** Clearnet visitors get GitHub, but the `.onion` and `.i2p` front doors
   are served local copies, because sending a Tor user to a clearnet host defeats the point.
   Copy all three installers, their `.asc` files and `SHA256SUMS` into
   `/var/www/pgpony/downloads/`. Roughly 300 MB per release.
3. **Deploy.** The local `PonyHTML/pgpony` tree is a clone, not the server:

```sh
chmod 644 downloads/desktop.json
scp downloads/desktop.json apps:/tmp/
ssh apps 'sudo cp /tmp/desktop.json /var/www/pgpony/downloads/desktop.json \
  && sudo chmod 644 /var/www/pgpony/downloads/desktop.json \
  && rm -f /tmp/desktop.json'
```

4. **Check `/desktop`** flips from the holding text to three working download buttons with
   checksums beneath them.
5. **Update the winget manifests** in `winget/<version>/` — `InstallerSha256` from `SHA256SUMS`,
   and `ProductCode` from the built msi. `ProductCode` is NOT the `upgradeUuid` in
   `build.gradle.kts`; that is the UpgradeCode, a different GUID. Run `winget validate` and a
   real `winget install --manifest` before opening the PR to `microsoft/winget-pkgs`.

## 6. Verification checklist

Artifacts:

- [ ] `gpg --verify` each `.asc`, and `SHA256SUMS.asc` against `SHA256SUMS`
- [ ] `shasum -a 256 -c SHA256SUMS` passes (macOS has no `sha256sum`; the format is identical,
      so Linux users verifying later can still use `sha256sum -c`)
- [ ] the published checksums match what `downloads/desktop.json` claims
- [ ] `dpkg-deb -f PGPony-linux.deb Depends` mentions `pcsc` — and the same for
      `PGPony-linux-arm64.deb`. CI asserts both, but the ARM lane is the newer one
- [ ] the portable tarball extracts and `PGPony/bin/PGPony version` prints (CI asserts this on
      both arches; do it once by hand on a real machine before the first ARM release)
- [ ] the AppImage is executable and runs — `chmod +x` then `./PGPony-x86_64.AppImage version`.
      On a desktop with FUSE it should also launch the GUI by double-click
- [ ] a CLI verb PRINTS on every OS — `pgpony version`, and `pgpony-cli version` on Windows.
      1.0.0 shipped a Windows build whose only launcher was GUI-subsystem, so the whole CLI was
      silent there and no check noticed
- [ ] `pgpony card-info` (`pgpony-cli card-info` on Windows) reports the expected readers

macOS:

- [ ] `xcrun stapler validate` on the dmg
- [ ] `spctl -a -t exec -vv` on the app inside the mounted dmg says `Notarized Developer ID`
- [ ] a quarantined dmg opens with no dialog, and the app launches from `/Applications`
      without a prompt
- [ ] a hardware key still works — the hardened runtime restricts library loading at runtime, so
      this cannot be inferred from a clean notarization

Every OS:

- [ ] clean-machine install with **no JDK present**
- [ ] double-clicking a `.pgpony`, a `.asc` and a `.gpg` opens PGPony and routes to the right
      screen — the runtime routing shipped in D9, this proves the OS registration from D13
- [ ] Gatekeeper / SmartScreen behaviour recorded for the release notes

Site:

- [ ] each of the four download links on `/desktop` files the right value in the daily click
      report: `desktop_macos`, `desktop_linux`, `desktop_windows`, `desktop_sig`
- [ ] the Desktop badge on the homepage files `desktop`

## 7. Arch Linux — the AUR package

`pgpony-bin` is published separately from the GitHub release and **must go out after it**. The
PKGBUILD fetches the release tarballs by tag, and PGPony's releases open as drafts: push to the
AUR while the release is still a draft and every user's `makepkg` gets a 404.

Sources live in `packaging/aur/` (`PKGBUILD`, `.SRCINFO`, `pgpony.desktop`, plus `README.md`
explaining the dependencies). The AUR repository itself holds only `PKGBUILD` and `.SRCINFO`.

```sh
cd ~/pgpony-release
git clone ssh://aur@aur.archlinux.org/pgpony-bin.git
cp /Users/kevinstewart/Apps/PGPonyDesktop/packaging/aur/PKGBUILD pgpony-bin/
cp /Users/kevinstewart/Apps/PGPonyDesktop/packaging/aur/.SRCINFO pgpony-bin/
cd pgpony-bin
git add PKGBUILD .SRCINFO
git commit -m "pgpony-bin 1.0.3"
git push origin master
```

The AUR's default branch is **`master`**. A push to `main` is rejected outright.

Two things that are easy to get wrong here:

- **`pcsclite` is a hard dependency, not a nicety.** `javax.smartcardio` dlopens `libpcsclite` at
  runtime, so without it the app installs cleanly, starts, and every hardware-key feature fails
  with a PC/SC error that looks like a broken security key. This is the same reason the `.deb`
  declares `pcscd,libpcsclite1`. RelayPony's PKGBUILD needs only `fontconfig`; copying it
  verbatim would have shipped exactly that bug.
- **`.SRCINFO` is hand-written**, because it is maintained from a Mac with no Arch environment.
  `makepkg --printsrcinfo` is authoritative — if you have a container, regenerate and diff before
  pushing. `SKIP` checksums are acceptable for a first push; `updpkgsums` fills in real ones once
  the release assets exist.
