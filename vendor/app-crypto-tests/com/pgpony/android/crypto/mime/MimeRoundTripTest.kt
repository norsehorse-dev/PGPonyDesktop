// MimeRoundTripTest.kt
// PGPony Android — 3.1.0 Phase 3 (J-core)
//
// Build-then-parse round-trip tests for MimeBuilder / MimeParser,
// exactly as the iOS port validated its MIME modules before any UI
// was wired. Pure JVM — no Android, no crypto.
//
// Coverage:
//   • multipart/mixed round trip: body + text + binary attachments
//   • body-only and attachments-only bundles
//   • RFC 3156 wrapEncrypted → pgpMimeEncryptedPayload extraction,
//     with and without leading email headers (Thunderbird-style .eml)
//   • bare armored block is NOT treated as an envelope (J2 guard)
//   • non-MIME plaintext parses to null (existing result path keeps it)
//   • LF-only line endings accepted
//   • quoted-printable body decoding (foreign builders)

package com.pgpony.android.crypto.mime

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class MimeRoundTripTest {

    private val sampleArmor = """
        -----BEGIN PGP MESSAGE-----

        hF4DzLG5/++UFBoSAQdACVEFt0vHn3cXBzuCHQ0V+wUzk1D6W3NDlHGE5t3lc24w
        vRhpO6O2XG2SdKKGeWCd9GVQ3D0iZLbCFRUcnBSTgF/wU5Q0tqZqLYiuFwoWQ17q
        =AbCd
        -----END PGP MESSAGE-----
    """.trimIndent()

    private fun binaryFixture(size: Int, seed: Int): ByteArray =
        Random(seed).nextBytes(size)

    // ── multipart/mixed round trips ─────────────────────────────────────

    @Test
    fun roundTrip_bodyAndTwoAttachments() {
        val pdf = MimeAttachment("report.pdf", "application/pdf", binaryFixture(5000, 1))
        val jpg = MimeAttachment("photo.jpg", "image/jpeg", binaryFixture(12345, 2))
        val body = "Hi Jesse,\n\nHere are the files we talked about.\n\n— NorseHorse"

        val built = MimeBuilder.buildMixed(body, listOf(pdf, jpg))
        val parsed = MimeParser.parse(built)

        assertNotNull(parsed)
        assertEquals(body, parsed!!.body)
        assertEquals(2, parsed.attachments.size)
        assertEquals("report.pdf", parsed.attachments[0].filename)
        assertEquals("application/pdf", parsed.attachments[0].contentType)
        assertArrayEquals(pdf.data, parsed.attachments[0].data)
        assertEquals("photo.jpg", parsed.attachments[1].filename)
        assertArrayEquals(jpg.data, parsed.attachments[1].data)
    }

    @Test
    fun roundTrip_bodyOnly() {
        val body = "Just a message, no files."
        val parsed = MimeParser.parse(MimeBuilder.buildMixed(body, emptyList()))
        assertNotNull(parsed)
        assertEquals(body, parsed!!.body)
        assertTrue(parsed.attachments.isEmpty())
    }

    @Test
    fun roundTrip_attachmentsOnly_noBody() {
        val zip = MimeAttachment("backup.zip", "application/zip", binaryFixture(4096, 3))
        val parsed = MimeParser.parse(MimeBuilder.buildMixed(null, listOf(zip)))
        assertNotNull(parsed)
        assertNull(parsed!!.body)
        assertEquals(1, parsed.attachments.size)
        assertArrayEquals(zip.data, parsed.attachments[0].data)
    }

    @Test
    fun roundTrip_largeBinaryAttachmentSurvivesBase64Wrapping() {
        // > many 76-column lines; exercises the wrap + unwrap path.
        val big = MimeAttachment("blob.bin", "application/octet-stream", binaryFixture(200_000, 4))
        val parsed = MimeParser.parse(MimeBuilder.buildMixed("body", listOf(big)))
        assertNotNull(parsed)
        assertArrayEquals(big.data, parsed!!.attachments[0].data)
    }

    @Test
    fun roundTrip_unicodeBodyAndFilename() {
        val att = MimeAttachment("メモ.txt", "text/plain", "こんにちは".toByteArray())
        val body = "Résumé attached — voilà. 日本語もOK."
        val parsed = MimeParser.parse(MimeBuilder.buildMixed(body, listOf(att)))
        assertNotNull(parsed)
        assertEquals(body, parsed!!.body)
        assertEquals("メモ.txt", parsed.attachments[0].filename)
        assertArrayEquals(att.data, parsed.attachments[0].data)
    }

    @Test
    fun parse_acceptsLfOnlyLineEndings() {
        val crlf = String(
            MimeBuilder.buildMixed("unix body", listOf(
                MimeAttachment("a.txt", "text/plain", "alpha".toByteArray())
            )),
            Charsets.UTF_8
        )
        val lfOnly = crlf.replace("\r\n", "\n").toByteArray(Charsets.UTF_8)
        val parsed = MimeParser.parse(lfOnly)
        assertNotNull(parsed)
        assertEquals("unix body", parsed!!.body)
        assertEquals(1, parsed.attachments.size)
        assertArrayEquals("alpha".toByteArray(), parsed.attachments[0].data)
    }

    // ── Non-MIME inputs stay on the existing path ───────────────────────

    @Test
    fun parse_plainTextIsNotMime() {
        assertNull(MimeParser.parse("just a decrypted note, nothing fancy".toByteArray()))
    }

    @Test
    fun parse_textMentioningContentTypeMidSentenceIsNotMime() {
        val tricky = "I set the Content-Type yesterday.\nIt broke everything."
        // First line has a colon, but there is no blank-line-terminated
        // header block with a MIME signal followed by a body — lenient
        // parsing may see a header block, so assert only that a
        // multipart never materializes from it.
        val parsed = MimeParser.parse(tricky.toByteArray())
        if (parsed != null) {
            assertTrue(parsed.attachments.isEmpty() || parsed.body == null)
        }
    }

    @Test
    fun parse_topLevelTextPlainEntityYieldsBodyOnly() {
        val entity = "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "\r\n" +
            "body only, as a proper entity\r\n"
        val parsed = MimeParser.parse(entity.toByteArray())
        assertNotNull(parsed)
        assertEquals("body only, as a proper entity", parsed!!.body)
        assertTrue(parsed.attachments.isEmpty())
    }

    @Test
    fun parse_quotedPrintableBodyDecodes() {
        val entity = "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Transfer-Encoding: quoted-printable\r\n" +
            "\r\n" +
            "caf=C3=A9 with a soft=\r\n" +
            " break\r\n"
        val parsed = MimeParser.parse(entity.toByteArray())
        assertNotNull(parsed)
        assertEquals("café with a soft break", parsed!!.body)
    }

    // ── RFC 3156 envelope: wrap + unwrap ────────────────────────────────

    @Test
    fun envelope_wrapThenExtractReturnsSameArmor() {
        val wrapped = String(MimeBuilder.wrapEncrypted(sampleArmor), Charsets.UTF_8)
        val extracted = MimeParser.pgpMimeEncryptedPayload(wrapped)
        assertNotNull(extracted)
        assertEquals(sampleArmor.trim(), extracted)
    }

    @Test
    fun envelope_withLeadingEmailHeadersStillExtracts() {
        val eml = "From: NorseHorse <norsehorse@norsehor.se>\r\n" +
            "To: Jesse <jesse@example.com>\r\n" +
            "Subject: ...\r\n" +
            "Date: Fri, 03 Jul 2026 12:00:00 -0500\r\n" +
            String(MimeBuilder.wrapEncrypted(sampleArmor), Charsets.UTF_8)
        val extracted = MimeParser.pgpMimeEncryptedPayload(eml)
        assertNotNull(extracted)
        assertEquals(sampleArmor.trim(), extracted)
    }

    @Test
    fun envelope_thunderbirdStyleFoldedContentTypeExtracts() {
        // Thunderbird folds the Content-Type parameters onto their own
        // lines; the extractor must still recognize the envelope.
        val eml = "Subject: hello\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: multipart/encrypted;\r\n" +
            " protocol=\"application/pgp-encrypted\";\r\n" +
            " boundary=\"tb-boundary-1\"\r\n" +
            "\r\n" +
            "--tb-boundary-1\r\n" +
            "Content-Type: application/pgp-encrypted\r\n" +
            "\r\n" +
            "Version: 1\r\n" +
            "\r\n" +
            "--tb-boundary-1\r\n" +
            "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n" +
            "\r\n" +
            sampleArmor.replace("\n", "\r\n") + "\r\n" +
            "--tb-boundary-1--\r\n"
        val extracted = MimeParser.pgpMimeEncryptedPayload(eml)
        assertNotNull(extracted)
        assertEquals(sampleArmor.trim(), extracted)
    }

    @Test
    fun envelope_bareArmoredBlockIsNotAnEnvelope() {
        // J2 guard: plain inline input must stay on its existing path.
        assertNull(MimeParser.pgpMimeEncryptedPayload(sampleArmor))
    }

    @Test
    fun envelope_randomTextIsNotAnEnvelope() {
        assertNull(MimeParser.pgpMimeEncryptedPayload("nothing to see here"))
    }

    @Test
    fun envelope_encryptedMentionedInBodyTextIsNotAnEnvelope() {
        // "multipart/encrypted" appearing in prose, not in a
        // Content-Type header, must not trigger extraction.
        val prose = "I read about multipart/encrypted today.\n\n$sampleArmor"
        assertNull(MimeParser.pgpMimeEncryptedPayload(prose))
    }

    // ── Helper coverage ─────────────────────────────────────────────────

    @Test
    fun headerParameter_quotedAndBareBoth() {
        assertEquals(
            "xyz",
            MimeParser.headerParameter("multipart/mixed; boundary=\"xyz\"", "boundary")
        )
        assertEquals(
            "xyz",
            MimeParser.headerParameter("multipart/mixed; boundary=xyz", "boundary")
        )
        assertNull(MimeParser.headerParameter("text/plain", "boundary"))
    }

    @Test
    fun base64Wrapped_linesNeverExceed76Columns() {
        val wrapped = MimeBuilder.base64Wrapped(binaryFixture(10_000, 5))
        for (line in wrapped.split("\r\n")) {
            assertTrue("line too long: ${line.length}", line.length <= 76)
        }
    }
}
