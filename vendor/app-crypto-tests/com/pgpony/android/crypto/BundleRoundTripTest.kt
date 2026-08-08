// BundleRoundTripTest.kt
// PGPony Android — 4.1.0
//
// The one link in the Bundle chain nothing covered. MimeRoundTripTest proves
// MimeBuilder -> MimeParser, and the crypto tests prove encrypt -> decrypt,
// but the FULL path a Bundle actually takes was untested:
//
//   MimeBuilder.buildMixed -> encrypt(armor = true)
//     -> decryptArmored -> MimeParser.parse(result.data) -> hasAttachments
//
// That last step is what the Decrypt tab routes on
// (EncryptDecryptViewModel.mimeRouteWithAttachments): mime == null sends the
// result to the plain text path instead of the structured attachment sheet,
// which is exactly the reported symptom "decrypting as single message file,
// not files which were actually encrypted".
//
// Written to answer a regression report against 4.1.0-rc1, so it deliberately
// asserts on the routing predicate and not just on the bytes.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.mime.MimeAttachment
import com.pgpony.android.crypto.mime.MimeBuilder
import com.pgpony.android.crypto.mime.MimeParser
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import kotlin.random.Random

class BundleRoundTripTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    private class Party(val pub: PGPPublicKeyRing, val sec: PGPSecretKeyRing)

    private fun party(): Party {
        val r = svc.generateKeyPair(
            name = "Bundle Tester",
            email = "bundle@example.test",
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = pass
        )
        return Party(
            PGPPublicKeyRing(ByteArrayInputStream(r.publicKeyData), JcaKeyFingerprintCalculator()),
            PGPSecretKeyRing(ByteArrayInputStream(r.privateKeyData), JcaKeyFingerprintCalculator())
        )
    }

    /** Exactly what EncryptDecryptViewModel.mimeRouteWithAttachments does. */
    private fun routes(data: ByteArray?): Boolean {
        val bytes = data ?: return false
        return try {
            MimeParser.parse(bytes)?.takeIf { it.hasAttachments } != null
        } catch (_: Exception) {
            false
        }
    }

    /** The Bundle pipeline, verbatim from encryptBundle(). */
    private fun encryptBundle(
        p: Party,
        body: String?,
        attachments: List<MimeAttachment>
    ): String {
        val mime = MimeBuilder.buildMixed(body = body?.takeIf { it.isNotBlank() }, attachments = attachments)
        val encrypted = svc.encrypt(
            data = mime,
            recipientPublicKeys = listOf(p.pub),
            signingSecretKey = null,
            passphrase = null,
            filename = null,
            armor = true
        )
        return String(encrypted, Charsets.UTF_8)
    }

    // ── the reported case ────────────────────────────────────────────────

    @Test
    fun bodyAndTwoAttachments_routeToStructuredSheet() {
        val p = party()
        val pdf = MimeAttachment("report.pdf", "application/pdf", Random(1).nextBytes(5000))
        val jpg = MimeAttachment("photo.jpg", "image/jpeg", Random(2).nextBytes(12345))
        val body = "Here are the files we talked about."

        val armored = encryptBundle(p, body, listOf(pdf, jpg))
        val result = svc.decryptArmored(armored, listOf(p.sec), pass)

        assertTrue(
            "decrypted bundle must route to the structured attachment sheet",
            routes(result.data)
        )
        val parsed = MimeParser.parse(result.data)
        assertNotNull(parsed)
        assertEquals(body, parsed!!.body)
        assertEquals(2, parsed.attachments.size)
        assertEquals("report.pdf", parsed.attachments[0].filename)
        assertArrayEquals(pdf.data, parsed.attachments[0].data)
        assertEquals("photo.jpg", parsed.attachments[1].filename)
        assertArrayEquals(jpg.data, parsed.attachments[1].data)
    }

    @Test
    fun attachmentsOnly_noBody_stillRoutes() {
        val p = party()
        val bin = MimeAttachment("data.bin", "application/octet-stream", Random(3).nextBytes(2048))

        val armored = encryptBundle(p, null, listOf(bin))
        val result = svc.decryptArmored(armored, listOf(p.sec), pass)

        assertTrue("attachments-only bundle must still route", routes(result.data))
        val parsed = MimeParser.parse(result.data)!!
        assertEquals(1, parsed.attachments.size)
        assertArrayEquals(bin.data, parsed.attachments[0].data)
    }

    @Test
    fun singleSmallAttachment_routes() {
        val p = party()
        val txt = MimeAttachment("note.txt", "text/plain", "hello".toByteArray(Charsets.UTF_8))

        val armored = encryptBundle(p, "body", listOf(txt))
        val result = svc.decryptArmored(armored, listOf(p.sec), pass)

        assertTrue("a one-attachment bundle must route", routes(result.data))
    }

    /**
     * A large-ish bundle, because the plaintext travels through the compressed
     * literal-data reader and a short read there would truncate the final
     * boundary and silently drop the routing to the text path.
     */
    @Test
    fun largeAttachment_survivesTheLiteralDataReader() {
        val p = party()
        val big = MimeAttachment("big.bin", "application/octet-stream", Random(4).nextBytes(600_000))

        val armored = encryptBundle(p, "big one", listOf(big))
        val result = svc.decryptArmored(armored, listOf(p.sec), pass)

        assertTrue("large bundle must route", routes(result.data))
        val parsed = MimeParser.parse(result.data)!!
        assertEquals(1, parsed.attachments.size)
        assertArrayEquals(big.data, parsed.attachments[0].data)
    }

    /**
     * The MIME entity must survive as BYTES. result.plaintext is a String
     * decode and is not what the router sees; asserting on data catches any
     * charset round-tripping that would corrupt base64 or CRLF.
     */
    @Test
    fun decryptedBytesAreTheMimeEntityVerbatim() {
        val p = party()
        val att = MimeAttachment("a.bin", "application/octet-stream", Random(5).nextBytes(4096))
        val boundary = MimeBuilder.randomBoundary()
        val mime = MimeBuilder.buildMixed("body", listOf(att), boundary)

        val armored = String(
            svc.encrypt(
                data = mime,
                recipientPublicKeys = listOf(p.pub),
                signingSecretKey = null,
                passphrase = null,
                filename = null,
                armor = true
            ),
            Charsets.UTF_8
        )
        val result = svc.decryptArmored(armored, listOf(p.sec), pass)

        assertArrayEquals("decrypt must return the MIME entity byte-for-byte", mime, result.data)
    }

    /**
     * Signed bundles take the same route but the decrypted stream also carries
     * signature packets, which is a different reader path.
     */
    @Test
    fun signedBundle_routes() {
        val p = party()
        val att = MimeAttachment("s.txt", "text/plain", "signed".toByteArray(Charsets.UTF_8))
        val mime = MimeBuilder.buildMixed("signed body", listOf(att))

        val armored = String(
            svc.encrypt(
                data = mime,
                recipientPublicKeys = listOf(p.pub),
                signingSecretKey = p.sec,
                passphrase = pass,
                filename = null,
                armor = true
            ),
            Charsets.UTF_8
        )
        val result = svc.decryptArmored(armored, listOf(p.sec), pass, listOf(p.pub))

        assertTrue("signed bundle must route", routes(result.data))
        assertTrue("signature should verify", result.signatureVerified)
    }
}
