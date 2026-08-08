// BundleEmlRoundTripTest.kt
// PGPony Android — 4.1.0 Phase 6, extended in Phase 7
//
// The seam BundleRoundTripTest does not reach.
//
// BundleRoundTripTest proves:
//   MimeBuilder.buildMixed -> encrypt -> decrypt -> MimeParser.parse
//
// This proves the layer wrapped around that by the Bundle result sheet's
// "Share as Email (.eml)" button, which is the most likely way a bundle
// actually leaves the app:
//
//   buildMixed -> encrypt -> wrapEncrypted (RFC 3156 multipart/encrypted)
//     -> [.eml leaves and comes back] -> MimeEnvelope.unwrap -> decrypt
//     -> MimeParser.parse -> hasAttachments
//
// If the unwrap hands the decryptor the wrong layer, the inner MIME never
// gets parsed and the result lands on the plain text path. That is the shape
// of the issue #10 report, "encrypting as message and decrypting as single
// message file", and nothing covered it.
//
// WHAT THIS FOUND, 30 July 2026. The envelope unwrap scanned only a fixed
// 8192-byte prefix for "multipart/encrypted", and wrapEncrypted wrote the
// optional Autocrypt header ABOVE the Content-Type line. keydata carries a
// whole certificate as base64, so a photo UID, extra subkeys or accumulated
// third-party certifications pushed Content-Type out of the prefix. The
// unwrap then silently returned the raw envelope, and the decrypt did not
// merely misroute, it failed outright with DecryptionFailed. Reachable today
// on classic algorithms, not only with PQC certs.
//
// Phase 6 moved Autocrypt below Content-Type and widened the prefix to 65536.
// Phase 7 extracted the unwrap into MimeEnvelope and removed the fixed prefix
// altogether, so this class of bug has no threshold left to cross. These
// tests now call MimeEnvelope directly rather than reproducing its body, which
// is the point of the extraction: there is one implementation and the tests
// exercise it, not a copy of it.

package com.pgpony.android.crypto

import com.pgpony.android.crypto.mime.MimeAttachment
import com.pgpony.android.crypto.mime.MimeBuilder
import com.pgpony.android.crypto.mime.MimeEnvelope
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

class BundleEmlRoundTripTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    private class Party(val pub: PGPPublicKeyRing, val sec: PGPSecretKeyRing)

    private fun party(): Party {
        val r = svc.generateKeyPair(
            name = "Eml Tester",
            email = "eml@example.test",
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
        attachments: List<MimeAttachment>,
        armor: Boolean = true
    ): ByteArray {
        val mime = MimeBuilder.buildMixed(
            body = body?.takeIf { it.isNotBlank() },
            attachments = attachments
        )
        return svc.encrypt(
            data = mime,
            recipientPublicKeys = listOf(p.pub),
            signingSecretKey = null,
            passphrase = null,
            filename = null,
            armor = armor
        )
    }

    private fun encryptBundleArmored(
        p: Party,
        body: String?,
        attachments: List<MimeAttachment>
    ): String = String(encryptBundle(p, body, attachments), Charsets.UTF_8)

    /** Decrypt whatever MimeEnvelope handed back. */
    private fun decryptUnwrapped(p: Party, eml: ByteArray) =
        svc.decryptArmored(
            String(MimeEnvelope.unwrapBytes(eml), Charsets.UTF_8),
            listOf(p.sec),
            pass
        )

    // ── the path the Share as Email button actually takes ────────────────

    /**
     * The headline case. A bundle shared as .eml and opened back as a FILE
     * must still reach the structured attachment sheet.
     */
    @Test
    fun emlFileRoundTrip_bodyAndTwoAttachments_stillRoutes() {
        val p = party()
        val pdf = MimeAttachment("report.pdf", "application/pdf", Random(11).nextBytes(5000))
        val jpg = MimeAttachment("photo.jpg", "image/jpeg", Random(12).nextBytes(12345))
        val body = "Here are the files we talked about."

        val armored = encryptBundleArmored(p, body, listOf(pdf, jpg))
        val result = decryptUnwrapped(p, MimeBuilder.wrapEncrypted(armored))

        assertTrue(
            "a bundle shared as .eml and reopened must route to the structured sheet",
            routes(result.data)
        )
        val parsed = MimeParser.parse(result.data)
        assertNotNull(parsed)
        assertEquals(body, parsed!!.body)
        assertEquals(2, parsed.attachments.size)
        assertArrayEquals(pdf.data, parsed.attachments[0].data)
        assertArrayEquals(jpg.data, parsed.attachments[1].data)
    }

    /**
     * The paste path. Same envelope, arriving as text in the Decrypt tab
     * rather than as a file, which is the other MimeEnvelope entry point.
     */
    @Test
    fun emlPasted_asText_stillRoutes() {
        val p = party()
        val att = MimeAttachment("note.txt", "text/plain", "hello".toByteArray(Charsets.UTF_8))

        val armored = encryptBundleArmored(p, "body", listOf(att))
        val eml = String(MimeBuilder.wrapEncrypted(armored), Charsets.UTF_8)

        val result = svc.decryptArmored(MimeEnvelope.unwrapText(eml), listOf(p.sec), pass)

        assertTrue("a pasted .eml bundle must route", routes(result.data))
    }

    /**
     * The envelope must be transparent. Wrapping and unwrapping cannot change
     * what comes out of the decryptor, so the .eml route and the bare-armor
     * route must produce identical MIME bytes. This is the assertion that
     * would catch a CRLF or trailing-whitespace change inside wrapEncrypted,
     * which normalizes line endings on the way in.
     */
    @Test
    fun envelopeIsTransparent_emlAndBareArmorAgree() {
        val p = party()
        val att = MimeAttachment("a.bin", "application/octet-stream", Random(13).nextBytes(4096))
        val armored = encryptBundleArmored(p, "body", listOf(att))

        val direct = svc.decryptArmored(armored, listOf(p.sec), pass)
        val viaEml = decryptUnwrapped(p, MimeBuilder.wrapEncrypted(armored))

        assertArrayEquals(
            "the RFC 3156 envelope must not change the decrypted MIME entity",
            direct.data,
            viaEml.data
        )
    }

    /**
     * A real mail client prepends its own headers before the Content-Type,
     * and the unwrap promises to handle that case ("with or without leading
     * email headers").
     */
    @Test
    fun emlWithLeadingMailHeaders_stillRoutes() {
        val p = party()
        val att = MimeAttachment("x.bin", "application/octet-stream", Random(14).nextBytes(1024))
        val armored = encryptBundleArmored(p, "body", listOf(att))

        val headers = buildString {
            append("From: sender@example.test\r\n")
            append("To: recipient@example.test\r\n")
            append("Subject: files\r\n")
            append("Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n")
            append("Message-ID: <test@example.test>\r\n")
        }
        val eml = (headers + String(MimeBuilder.wrapEncrypted(armored), Charsets.UTF_8))
            .toByteArray(Charsets.UTF_8)

        assertTrue(
            "leading mail headers must not defeat the unwrap",
            routes(decryptUnwrapped(p, eml).data)
        )
    }

    // ── the detection-window class of bug, Phase 6 found, Phase 7 removed ──

    /**
     * THE REGRESSION TEST. This is the shape that failed before Phase 6.
     *
     * Another client is free to put a large Autocrypt header above the
     * Content-Type line, and PGPony itself did so until Phase 6. keydata is a
     * whole certificate in base64, so this is not exotic: a photo UID or a
     * well-signed key gets there on classic algorithms.
     *
     * The header is 200,000 characters, which is past BOTH the original 8192
     * prefix and the 65536 one Phase 6 widened it to. It passes only because
     * Phase 7 removed the fixed prefix entirely. If someone reintroduces a
     * prefix scan of any size, this fails.
     */
    @Test
    fun foreignEmlWithHugeAutocryptHeader_stillReachesTheMessage() {
        val p = party()
        val att = MimeAttachment("y.bin", "application/octet-stream", Random(15).nextBytes(2048))
        val armored = encryptBundleArmored(p, "body", listOf(att))

        val autocrypt = "Autocrypt: addr=eml@example.test; keydata=" + "A".repeat(200_000)
        val marker = "MIME-Version: 1.0\r\n"
        val foreign = String(MimeBuilder.wrapEncrypted(armored), Charsets.UTF_8)
            .replaceFirst(marker, marker + autocrypt + "\r\n")

        assertTrue(
            "precondition: Content-Type must sit past every prefix window this " +
                "code has ever used",
            foreign.indexOf("multipart/encrypted") > 65_536
        )

        assertTrue(
            "a huge Autocrypt header must not strand the bundle",
            routes(decryptUnwrapped(p, foreign.toByteArray(Charsets.UTF_8)).data)
        )
    }

    /**
     * The other half of the Phase 6 fix: whatever PGPony writes itself must
     * keep the marker near the front no matter how large keydata grows, so
     * our own .eml never depended on the unwrap's tolerance in the first
     * place.
     */
    @Test
    fun wrapEncryptedKeepsContentTypeEarly_regardlessOfAutocryptSize() {
        val p = party()
        val att = MimeAttachment("w.bin", "application/octet-stream", Random(17).nextBytes(256))
        val armored = encryptBundleArmored(p, "body", listOf(att))

        val autocrypt = "Autocrypt: addr=eml@example.test; keydata=" + "A".repeat(40_000)
        val eml = String(
            MimeBuilder.wrapEncrypted(armored, autocryptHeader = autocrypt),
            Charsets.UTF_8
        )

        assertTrue(
            "wrapEncrypted must emit Content-Type before the Autocrypt header",
            eml.indexOf("multipart/encrypted") < 200
        )
        assertTrue(
            "the Autocrypt header must still be present",
            eml.contains("Autocrypt: addr=eml@example.test")
        )
    }

    /** And our own huge-header .eml must still decrypt, not merely parse. */
    @Test
    fun ourOwnEmlWithHugeAutocryptHeader_stillRoutes() {
        val p = party()
        val att = MimeAttachment("v.txt", "text/plain", "vv".toByteArray(Charsets.UTF_8))
        val armored = encryptBundleArmored(p, "body", listOf(att))

        val autocrypt = "Autocrypt: addr=eml@example.test; keydata=" + "A".repeat(40_000)
        val eml = MimeBuilder.wrapEncrypted(armored, autocryptHeader = autocrypt)

        assertTrue(
            "our own .eml must route regardless of header size",
            routes(decryptUnwrapped(p, eml).data)
        )
    }

    /**
     * A normally sized Autocrypt header, which is what the sheet actually
     * emits today, must be transparent.
     */
    @Test
    fun ordinaryAutocryptHeader_stillRoutes() {
        val p = party()
        val att = MimeAttachment("z.txt", "text/plain", "zz".toByteArray(Charsets.UTF_8))
        val armored = encryptBundleArmored(p, "body", listOf(att))

        val autocrypt = "Autocrypt: addr=eml@example.test; keydata=" + "A".repeat(1200)
        val eml = MimeBuilder.wrapEncrypted(armored, autocryptHeader = autocrypt)

        assertTrue(
            "an ordinary Autocrypt header must not affect routing",
            routes(decryptUnwrapped(p, eml).data)
        )
    }

    // ── what must NOT be treated as an envelope ──────────────────────────

    /**
     * A bare armored bundle is NOT an envelope and must pass through both
     * entry points unchanged. If the unwrap ever started rewriting
     * non-envelope input, every ordinary decrypt in the app would go through
     * the change unnoticed.
     */
    @Test
    fun bareArmoredBundle_passesThroughUnwrapUnchanged() {
        val p = party()
        val att = MimeAttachment("b.bin", "application/octet-stream", Random(16).nextBytes(512))
        val armored = encryptBundleArmored(p, "body", listOf(att))

        assertEquals(
            "a bare armored block is not an envelope and must pass through as-is",
            armored,
            MimeEnvelope.unwrapText(armored)
        )
        assertArrayEquals(
            "bare armored bytes must pass through the file path as-is",
            armored.toByteArray(Charsets.UTF_8),
            MimeEnvelope.unwrapBytes(armored.toByteArray(Charsets.UTF_8))
        )
    }

    /**
     * Phase 7 replaced the prefix marker scan with an "is this text at all"
     * probe, so binary ciphertext is now what the cheap rejection path is
     * tuned for. Real binary OpenPGP output, not synthetic bytes, because the
     * guard keys on NUL bytes appearing early and that is an empirical claim
     * about packet framing.
     */
    @Test
    fun binaryCiphertext_passesThroughUnwrapUntouched() {
        val p = party()
        val att = MimeAttachment("c.bin", "application/octet-stream", Random(18).nextBytes(8192))
        val binary = encryptBundle(p, "body", listOf(att), armor = false)

        assertArrayEquals(
            "binary ciphertext must not be decoded or rewritten by the unwrap",
            binary,
            MimeEnvelope.unwrapBytes(binary)
        )
    }

    /**
     * Prose that happens to contain a colon is not a header block, and even if
     * the probe were fooled the result must still be identity rather than
     * damage.
     */
    @Test
    fun plainTextWithoutHeaders_passesThroughUnwrapUntouched() {
        val text = "Hello there: this is not an email.\nJust some notes.\n"
        val bytes = text.toByteArray(Charsets.UTF_8)

        assertArrayEquals(
            "non-envelope text must pass through untouched",
            bytes,
            MimeEnvelope.unwrapBytes(bytes)
        )
        assertEquals(text, MimeEnvelope.unwrapText(text))
    }
}
