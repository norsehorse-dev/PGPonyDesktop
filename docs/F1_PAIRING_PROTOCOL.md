# PGPony pairing protocol: moved upstream

The pairing protocol is shared by desktop, Android and iOS, so its specification now lives with
its Kotlin code in PGPonyAndroid: `docs/PAIRING_PROTOCOL.md`, next to
`app/src/main/java/com/pgpony/android/pair/` and the test vectors in
`app/src/test/resources/pairing/`.

Desktop vendors all three with `tools/sync-vendor.sh`: the code and a copy of the specification
into `vendor/app-pair/` (read `vendor/app-pair/PAIRING_PROTOCOL.md` there), the tests and
vectors with the rest of the vendored test suite. Change the protocol upstream, never here.

Desktop's part is the UI and the glue: `src/main/kotlin/com/pgpony/desktop/PairDialog.kt` and
`PairController.kt` (candidates, prepare, apply, the host window, and the invite QR code a phone
scans or another computer pastes).
