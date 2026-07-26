// QrCodeTest.kt
// D9 validation — QR encode/decode round-trips (an armored public key survives the trip), and
// oversized content fails soft (null, not an exception) so the UI can show the "share the .asc"
// fallback.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class QrCodeTest {

    @Test
    fun encodeDecodeRoundTripsText() {
        val text = "https://keys.pgpony.app — round trip 12345 ABCDEF"
        val png = assertNotNull(QrCode.encodeToPng(text), "encode should succeed")
        val file = File.createTempFile("pgpony-qr", ".png").apply { writeBytes(png); deleteOnExit() }
        assertEquals(text, QrCode.decodeFromImage(file))
    }

    @Test
    fun encodeDecodeRoundTripsAnEd25519PublicKey() {
        // An Ed25519 public certificate is small enough to fit a QR; RSA-4096 would not (that's
        // the too-large path below).
        val gen = PGPCryptoService.shared.generateKeyPair(
            name = "QR Test", email = "qr@pgpony.app",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "pw"
        )
        val png = QrCode.encodeToPng(gen.armoredPublicKey)
        assertNotNull(png, "an Ed25519 public key should fit a QR")
        val file = File.createTempFile("pgpony-key-qr", ".png").apply { writeBytes(png); deleteOnExit() }
        val decoded = assertNotNull(QrCode.decodeFromImage(file))
        assertTrue(decoded.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        // The decoded armor imports as the same key.
        val parsed = PGPCryptoService.shared.importArmoredKey(decoded)
        assertEquals(gen.fingerprint, parsed.fingerprint)
    }

    @Test
    fun oversizedContentReturnsNullNotThrows() {
        // Well beyond any QR version's byte capacity (~3KB) → soft failure.
        val huge = "A".repeat(8000)
        assertNull(QrCode.encodeToPng(huge), "oversized content must return null, not throw")
    }

    @Test
    fun decodingANonQrImageReturnsNull() {
        // A blank white PNG has no QR to find.
        val img = java.awt.image.BufferedImage(64, 64, java.awt.image.BufferedImage.TYPE_INT_RGB)
        val g = img.createGraphics(); g.color = java.awt.Color.WHITE; g.fillRect(0, 0, 64, 64); g.dispose()
        val file = File.createTempFile("pgpony-blank", ".png").apply { deleteOnExit() }
        javax.imageio.ImageIO.write(img, "PNG", file)
        assertNull(QrCode.decodeFromImage(file))
        Files.deleteIfExists(file.toPath())
    }
}
