// QrDetectionRegressionTest.kt
// D12 Fix4 regression — the QR detection failure that made QrCodeTest look flaky since D9.
//
// QrCodeTest generates a fresh key every run, so it caught this only when it happened to draw an
// affected one, which read as flakiness and got treated as noise. This test pins the exact
// certificate that failed, so the regression is deterministic and costs no key generation.
//
// The symptom: this armor encodes to a symbol ZXing's photo detector cannot LOCATE —
// NotFoundException from both binarizers, at every render size from 640 to 2048, with a 1-module
// and with a spec-conformant 4-module quiet zone, at every error-correction level. The same image
// decodes under DecodeHintType.PURE_BARCODE every time, which is what proves the symbol is correct
// and the failure is one of detection rather than of encoding. QrCode.decodeFromImage therefore
// falls back to the grid reader; this test is what holds that fallback in place.

package com.pgpony.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class QrDetectionRegressionTest {

    /**
     * A real Ed25519 public certificate whose symbol ZXing's photo detector could not locate.
     * Kept verbatim; regenerate nothing here — the point is that these exact bytes used to fail.
     */
    private val undetectableAtLevelL = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEamVAFxYJKwYBBAHaRw8BAQdAj5daz3eyIFdCYSBKir98cOFMZ7f1JWJa3ALw
ksO86DC0F1FSIFRlc3QgPHFyQHBncG9ueS5hcHA+woIEExYIACoFgmplQBcCGwME
CwkIBwQVCAkKFiEEc1yUerD0DJvTAGkv7Wwo/g24+ugACgkQ7Wwo/g24+ugSSgD/
UvEF27VKhGA24D+SxGlGA3/0+TA9YPvP5OmQ6MJAj9QA/ivB2xxV5NUSw/In3cSZ
ybtzMMTijaxcC19QtpcG6r4IuDgEamVAFxIKKwYBBAGXVQEFAQEHQGAphPTiPRq0
rAsRyVEVKy83Y4sks/a0bZy6aAKfUJtlAwEIB8JhBBgWCAAJBYJqZUAXAhsMAAoJ
EO1sKP4NuProvAMA/j+ob+7PsmcBrA1HaHLxcpPBfyrFCX5sH6/annroSK+uAP9u
ac9rkx/g51LTWUq15y3rGg5ChIpYpchUsi6LgU3mBw==
=R2Hn
-----END PGP PUBLIC KEY BLOCK-----
""".trimStart()

    @Test
    fun theCertificateThatUsedToBeUndetectableRoundTrips() {
        val png = assertNotNull(
            QrCode.encodeToPng(undetectableAtLevelL),
            "a 579-byte Ed25519 certificate must fit a QR"
        )
        val file = File.createTempFile("pgpony-qr-regression", ".png")
            .apply { writeBytes(png); deleteOnExit() }

        val decoded = assertNotNull(
            QrCode.decodeFromImage(file),
            "this certificate's symbol cannot be found by ZXing's photo detector; if this is " +
                "null again, the PURE_BARCODE fallback in QrCode.decodeFromImage is gone"
        )
        assertEquals(undetectableAtLevelL, decoded)
    }

    /**
     * The round trip has to survive re-rendering at the sizes the UI and any export path use.
     * Detection failures in this family were size-independent, so a size sweep is the cheap way
     * to notice if that ever stops being true.
     */
    @Test
    fun roundTripsAtEveryRenderSizeTheUiUses() {
        for (size in intArrayOf(320, 640, 1024)) {
            val png = assertNotNull(
                QrCode.encodeToPng(undetectableAtLevelL, size),
                "encode failed at size $size"
            )
            val file = File.createTempFile("pgpony-qr-$size", ".png")
                .apply { writeBytes(png); deleteOnExit() }
            assertEquals(
                undetectableAtLevelL,
                QrCode.decodeFromImage(file),
                "round trip failed at size $size"
            )
        }
    }
}
