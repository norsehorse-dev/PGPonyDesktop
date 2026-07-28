# AUR package (pgpony-bin)

`pgpony-bin` installs the prebuilt Linux desktop app — the same portable tarball attached to
each GitHub release — into `/opt/pgpony`, with a `pgpony` launcher on `PATH`, a desktop entry
and an icon. The bundled jlink runtime means there is no `jre`/`jdk` dependency.

Both architectures are covered from one PKGBUILD: `source_x86_64` and `source_aarch64` pull the
matching tarball, so `makepkg` on an ARM machine fetches the ARM build.

## Why `pcsclite` is a hard dependency

`javax.smartcardio` dlopens `libpcsclite` at runtime. Without it the app starts, the UI works,
and every hardware-key feature fails with a PC/SC error — a failure that looks like a broken
security key rather than a missing package. That is the same reason the `.deb` declares
`pcscd,libpcsclite1`. The `ccid` optdepend is the USB reader driver: `pcscd` runs without it and
enumerates nothing.

## Publishing / updating on the AUR

The AUR repo holds only `PKGBUILD` and `.SRCINFO`; the tarball, `.desktop` and icon are fetched
from the matching tagged release.

**Publish the GitHub release first.** PGPony's releases open as drafts and are published by hand
once the dmg is notarized and everything is signed. A tag alone is not enough — the release
assets 404 until the draft is published, and every `makepkg` fails.

1. Bump `pkgver` to the release version (no leading `v`).
2. Fill in real checksums now that the assets exist: `updpkgsums`. `SKIP` is fine for a first
   push; real sums are better once the bytes are final.
3. Regenerate metadata and test a clean build: `makepkg --printsrcinfo > .SRCINFO && makepkg -si`
4. Push:

```sh
git clone ssh://aur@aur.archlinux.org/pgpony-bin.git
cp PKGBUILD .SRCINFO pgpony-bin/
cd pgpony-bin && git add PKGBUILD .SRCINFO && git commit -m "pgpony-bin 1.0.3" && git push
```

The AUR's default branch is `master`, not `main`. A push to `main` is rejected.

`.SRCINFO` in this directory is hand-written to match the PKGBUILD, because it is maintained
from a Mac with no Arch environment. If you have a container, `makepkg --printsrcinfo` is
authoritative — regenerate and diff before pushing.
