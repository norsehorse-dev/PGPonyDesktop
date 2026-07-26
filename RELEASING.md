# Releasing PGPony Desktop

Each release ships three installers — a signed and notarized **`.dmg`** (macOS, arm64), a
**`.deb`** (Linux, amd64) and an **`.msi`** (Windows, x64) — plus a detached `.asc` for each and
a signed `SHA256SUMS` covering all three. `jpackage` only builds for the OS it runs on, so each
installer is built on its own platform, or all three at once via CI (Option A).

Bump **both** version numbers before tagging, and check they agree:

- `AppVersion.VERSION` in `src/main/kotlin/com/pgpony/desktop/Config.kt`
- `packageVersion` in `build.gradle.kts`

They had silently drifted before D13 — the bundle said `1.0.0` while the app reported
`1.0.0-dev.D1`. The mismatch is only visible in a built `Info.plist`, so nothing warns you.

## Option A — CI (recommended)

Push a version tag. `.github/workflows/release.yml` builds all three installers on their own
runners, signs everything with the release key, verifies its own signatures, and publishes the
GitHub Release.

```sh
git tag v1.0.0
git push origin v1.0.0
gh run watch $(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')
```

The workflow triggers **only** on tag pushes. There is no `pull_request` trigger, and that is
what keeps the signing secrets unreachable from a fork PR — do not add one.

### Repository secrets

Settings → Secrets and variables → Actions.

| Secret | What it is |
| --- | --- |
| `MACOS_CERT_P12_BASE64` | Developer ID Application cert + key, exported `.p12`, base64 |
| `MACOS_CERT_PASSWORD` | The password set when exporting that `.p12` |
| `KEYCHAIN_PASSWORD` | Any throwaway string — password for the temporary CI keychain |
| `MACOS_SIGN_IDENTITY` | The certificate's full **name**, e.g. `Developer ID Application: …` |
| `NOTARIZATION_APPLE_ID` | Apple ID email |
| `NOTARIZATION_PASSWORD` | App-specific password from appleid.apple.com — no trailing spaces |
| `NOTARIZATION_TEAM_ID` | Team ID |
| `PGP_RELEASE_KEY_BASE64` | The release **signing subkey**, exported alone, base64 |
| `PGP_RELEASE_PASSPHRASE` | That subkey's passphrase |

Export the `.p12` once, on the Mac holding the certificate:

- Keychain Access → **login** → **My Certificates** → right-click the `Developer ID Application`
  certificate → **Export**, saving as `cert.p12` with a password (that password is
  `MACOS_CERT_PASSWORD`).
- `base64 -i cert.p12 | pbcopy`, then paste into `MACOS_CERT_P12_BASE64`.

Export the PGP **subkey only** — never the primary. The primary stays offline, so what a hosted
runner can reach stays revocable without burning the identity:

```sh
gpg --export-secret-subkeys --armor <SUBKEY_ID>! | base64 | pbcopy
```

The trailing `!` is not optional: without it gpg exports the whole secret key rather than that
one subkey.

## Option B — manual

### macOS (signed + notarized), on a Mac

Keep the four values in a file outside the repo, `chmod 600`:

```sh
source ~/.pgpony-release-env
./gradlew notarizeDmg -Pcompose.desktop.mac.notarization.teamID="$NOTARIZATION_TEAM_ID"
xcrun stapler validate build/compose/binaries/main/dmg/PGPony-*.dmg
```

Gotchas, all three learned the hard way and all three still current:

- `MACOS_SIGN_IDENTITY` must be the certificate **name**, not its SHA-1 hash — Compose looks it
  up by name and fails with "Could not find certificate for …" otherwise.
- Only **one** `Developer ID Application` certificate may be in the keychain, or codesign reports
  "multiple matching certificates". List them with
  `security find-identity -v -p codesigning` and delete keyless extras with
  `security delete-certificate -Z <hash>`.
- The team ID goes through `-Pcompose.desktop.mac.notarization.teamID=…`. The DSL `teamId`
  property does not exist in Compose 1.11.1.

**The dmg container is deliberately unsigned.** Compose signs the `.app`, notarizes it, and
staples the ticket to the disk image without signing the wrapper. That is why
`spctl -a -t open --context context:primary-signature` **rejects** the dmg with
`source=no usable signature` — it is asking an unsigned container a signature question. The
checks that mean something are the app inside it, and a quarantined open:

```sh
hdiutil attach build/compose/binaries/main/dmg/PGPony-*.dmg -nobrowse -mountpoint /tmp/pgponydmg
spctl -a -t exec -vv /tmp/pgponydmg/PGPony.app
hdiutil detach /tmp/pgponydmg
```

That must print `accepted` and `source=Notarized Developer ID`.

### Linux (`.deb`), on a Linux host

```sh
sudo apt install -y openjdk-17-jdk fakeroot
./gradlew packageDeb
dpkg-deb -f build/compose/binaries/main/deb/pgpony_*_amd64.deb Depends
```

That last line must mention `pcsc`. The dependency is injected through the jpackage task's
`freeArgs` because Compose's `linux {}` block has no dependency field, and `freeArgs` degrades to
a silent no-op if it ever disappears — so this check, not the absence of a build error, is what
proves hardware keys will work on a fresh install.

### Windows (`.msi`), on a Windows host

Install a JDK 17 and **WiX Toolset 3.x** — jpackage shells out to WiX's `candle.exe` and
`light.exe`, and WiX 4/5 will not work. `choco install wixtoolset` gets 3.14. Then:

```bat
gradlew.bat packageMsi
```

The installer is **not** code-signed, so SmartScreen warns on first run and users must click
**More info → Run anyway**. `/desktop` says so plainly rather than letting it surprise anyone.
Signing needs a separate Windows code-signing certificate.

### Signing and publishing by hand

```sh
sha256sum PGPony-macOS.dmg PGPony-linux.deb PGPony-windows.msi > SHA256SUMS
for f in PGPony-macOS.dmg PGPony-linux.deb PGPony-windows.msi SHA256SUMS; do
  gpg --armor --detach-sign "$f"
done
gh release create v1.0.0 PGPony-*.dmg PGPony-*.deb PGPony-*.msi *.asc SHA256SUMS \
  --repo norsehorse-dev/PGPonyDesktop --title "PGPony Desktop 1.0.0" --generate-notes
```

## After the release — the site

None of this is automated, and all of it is easy to forget. `/desktop` shows "publishing in
progress" until the checksums land, so the page stays honest if you stop halfway.

1. **Fill `downloads/desktop.json`** — `version`, `released`, `tag`, `notes`, and the three
   `sha256` values, copied out of the published `SHA256SUMS`. The page's readiness gate keys on
   those checksums being 64 hex characters; anything else and it keeps showing the holding text.
   `tag` is what builds the GitHub download URLs, so a stale `tag` means dead links.
2. **Upload the mirror.** Clearnet visitors get GitHub, but the `.onion` and `.i2p` front doors
   are served the local copies, because sending a Tor user to a clearnet host defeats the point.
   Copy all three installers, their `.asc` files and `SHA256SUMS` into
   `/var/www/pgpony/downloads/`. Roughly 300 MB per release.
3. **Extend `downloads/.htaccess`** with `AddType` lines for `.dmg`, `.deb` and `.msi`, the way
   it already declares `.apk`, `.asc` and `.sha256`.
4. **Deploy.** The local `PonyHTML/pgpony` tree is a clone, not the server:

```sh
chmod 644 downloads/desktop.json
scp downloads/desktop.json apps:/tmp/
ssh apps 'sudo cp /tmp/desktop.json /var/www/pgpony/downloads/desktop.json \
  && sudo chmod 644 /var/www/pgpony/downloads/desktop.json \
  && rm -f /tmp/desktop.json'
```

5. **Check `/desktop`** flips from the holding text to three working download buttons with
   checksums beneath them.

## Verification checklist

Artifacts:

- [ ] `gpg --verify` each `.asc` against its artifact, and `SHA256SUMS.asc` against `SHA256SUMS`
- [ ] `sha256sum -c SHA256SUMS` passes
- [ ] the published checksums match what `downloads/desktop.json` claims
- [ ] `dpkg-deb -f PGPony-linux.deb Depends` mentions `pcsc`

macOS:

- [ ] `xcrun stapler validate` on the dmg
- [ ] `spctl -a -t exec -vv` on the app inside the mounted dmg says `Notarized Developer ID`
- [ ] a quarantined dmg (`xattr -w com.apple.quarantine …`) opens with no dialog, and the app
      launches from `/Applications` with no prompt
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
