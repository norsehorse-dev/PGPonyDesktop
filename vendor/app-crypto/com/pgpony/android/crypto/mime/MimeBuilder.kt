// MimeBuilder.kt
// PGPony Android — 3.1.0 Phase 3 (J-core)
//
// Assembles the two MIME shapes the Bundle feature needs:
//
//   1. buildMixed  — a `multipart/mixed` entity from a body + attachments.
//      This is what gets ENCRYPTED: the plaintext of a PGP/MIME message.
//   2. wrapEncrypted — the RFC 3156 `multipart/encrypted` envelope around
//      an already-armored PGP MESSAGE. This is the .eml-shaped OUTSIDE
//      that Thunderbird and other desktop clients produce and consume.
//
// Port of iOS Services/MIME/MIMEBuilder.swift (7.1.x). Conventions:
//   • CRLF line endings throughout (MIME canonical form; RFC 2045 §2.8).
//   • Text body: text/plain; charset=utf-8 with 8bit transfer encoding —
//     raw and human-inspectable, matching what mail clients emit.
//   • Attachments: base64, wrapped at 76 columns (RFC 2045 §6.8).
//   • Boundaries: random hex, prefixed so a collision with content is
//     practically impossible and PGPony output is recognizable in
//     debugging.

package com.pgpony.android.crypto.mime

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.SecureRandom

object MimeBuilder {

    private const val CRLF = "\r\n"

    /**
     * Attachment bytes encoded per pass in [writeMixed]. A multiple
     * of 57 so every chunk ends on a whole 76 column base64 line and
     * the wrap points match the buffered form exactly.
     */
    private const val B64_CHUNK = 57 * 1024

    /** Random MIME boundary, e.g. "=-PGPony-3f9c2ab47d10e58b". */
    fun randomBoundary(): String {
        val bytes = ByteArray(8)
        SecureRandom().nextBytes(bytes)
        return "=-PGPony-" + bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Build a `multipart/mixed` entity from [body] and [attachments].
     *
     * A null or blank [body] produces no text part (attachments-only
     * bundle); an empty attachment list produces a multipart with just
     * the text part — callers who want a plain text/plain message for
     * that case should simply not use MIME at all, but keeping the
     * shape uniform makes the round-trip predictable.
     *
     * The result starts with `MIME-Version: 1.0` and `Content-Type:`
     * headers so it is a complete MIME entity on its own — exactly the
     * bytes to feed to the encrypt pipeline.
     */
    fun buildMixed(
        body: String?,
        attachments: List<MimeAttachment>,
        boundary: String = randomBoundary()
    ): ByteArray {
        // 4.1.0 Phase 14: one implementation, two entry points. This one
        // still returns the whole entity, which is what the text-mode and
        // share callers want; [writeMixed] is the streaming form that the
        // Bundle encrypt path uses so a multi-megabyte bundle is never
        // resident. Byte-for-byte identical output for a given boundary.
        val out = ByteArrayOutputStream(estimateSize(body, attachments))
        writeMixed(out, body, attachments, boundary)
        return out.toByteArray()
    }

    /**
     * Write the same `multipart/mixed` entity [buildMixed] returns
     * straight to [out], never holding more than one chunk.
     *
     * The buffered form cost roughly six times the attachment payload at
     * peak: base64 expands by a third, a Kotlin StringBuilder holds that
     * as UTF-16 (two bytes per character), growing it copies, toString()
     * copies again and toByteArray() once more. Ten 2 MB attachments came
     * to well over a hundred megabytes of transient allocation before the
     * encrypt even started, which is an OutOfMemoryError on a stock heap.
     * Reported against 4.1.0 by AraafRoyall (issue #12).
     *
     * [onProgress] receives the running total of attachment bytes
     * consumed, so the caller can drive a real byte counted progress bar
     * instead of an indeterminate spinner.
     */
    fun writeMixed(
        out: OutputStream,
        body: String?,
        attachments: List<MimeAttachment>,
        boundary: String = randomBoundary(),
        onProgress: ((Long) -> Unit)? = null
    ) = writeMixedSources(
        out = out,
        body = body,
        sources = attachments.map { att ->
            MimeSource(att.filename, att.contentType) {
                java.io.ByteArrayInputStream(att.data)
            }
        },
        boundary = boundary,
        onProgress = onProgress
    )

    /**
     * 4.2.0 RC6 (#32, AraafRoyall): one attachment the streaming form
     * reads on demand. [open] is invoked exactly once per assembly pass
     * and the stream is closed by the writer. Backing can be a
     * ByteArray (the buffered callers above) or a content:// URI opened
     * at encrypt time, which is what lets a bundle carry attachments
     * that were never resident in memory.
     */
    class MimeSource(
        val filename: String,
        val contentType: String,
        val open: () -> java.io.InputStream
    )

    /**
     * 4.2.0 RC6 (#32): the byte-source generalization of [writeMixed].
     * Identical wire output for identical content: the base64 chunking
     * reads whole [B64_CHUNK] blocks (a multiple of 57, so every full
     * block ends on a whole 76 column line), and the one-block lookahead
     * reproduces the original's end-of-part handling, where the final
     * line takes no trailing CRLF of its own.
     */
    fun writeMixedSources(
        out: OutputStream,
        body: String?,
        sources: List<MimeSource>,
        boundary: String = randomBoundary(),
        onProgress: ((Long) -> Unit)? = null
    ) {
        fun put(s: String) = out.write(s.toByteArray(Charsets.UTF_8))

        put("MIME-Version: 1.0" + CRLF)
        put("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"" + CRLF)
        put(CRLF)

        if (!body.isNullOrBlank()) {
            put("--" + boundary + CRLF)
            put("Content-Type: text/plain; charset=utf-8" + CRLF)
            put("Content-Transfer-Encoding: 8bit" + CRLF)
            put(CRLF)
            // Normalize the body itself to CRLF so the entity is fully
            // canonical regardless of how the compose field delivered it.
            put(body.replace("\r\n", "\n").replace("\n", CRLF) + CRLF)
        }

        val encoder = java.util.Base64.getEncoder()
        var consumed = 0L
        for (src in sources) {
            val safeName = sanitizeFilename(src.filename)
            put("--" + boundary + CRLF)
            put("Content-Type: " + src.contentType + "; name=\"" + safeName + "\"" + CRLF)
            put("Content-Transfer-Encoding: base64" + CRLF)
            put("Content-Disposition: attachment; filename=\"" + safeName + "\"" + CRLF)
            put(CRLF)

            src.open().use { input ->
                // Double-buffered lookahead: `cur` is the block being
                // written, `nxt` tells us whether it is the last one, so
                // the no-CRLF-after-the-final-line rule can be applied
                // without knowing the total size upfront. readBlock fills
                // the whole block or hits EOF; a content:// stream is
                // free to return short reads, so a plain read() would
                // break the 76 column alignment.
                var cur = ByteArray(B64_CHUNK)
                var nxt = ByteArray(B64_CHUNK)
                var curLen = readBlock(input, cur)
                while (curLen > 0) {
                    val nxtLen = if (curLen == B64_CHUNK) readBlock(input, nxt) else 0
                    val isLastChunk = nxtLen == 0
                    val enc = encoder.encode(
                        if (curLen == cur.size) cur else cur.copyOf(curLen)
                    )
                    var i = 0
                    while (i < enc.size) {
                        val lineEnd = minOf(i + 76, enc.size)
                        out.write(enc, i, lineEnd - i)
                        // No terminator after the final line of the final
                        // chunk: the part's own CRLF below closes it, which
                        // is what base64Wrapped + append(CRLF) produced
                        // before.
                        if (lineEnd < enc.size || !isLastChunk) put(CRLF)
                        i = lineEnd
                    }
                    consumed += curLen.toLong()
                    onProgress?.invoke(consumed)
                    val t = cur; cur = nxt; nxt = t
                    curLen = nxtLen
                }
            }
            put(CRLF)
        }

        put("--" + boundary + "--" + CRLF)
    }

    /**
     * 4.2.0 RC6 (#32): fill [buf] completely or read to EOF. Returns the
     * number of bytes placed in [buf]; 0 only at EOF.
     */
    private fun readBlock(input: java.io.InputStream, buf: ByteArray): Int {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) break
            off += n
        }
        return off
    }

    /**
     * Close enough for a ByteArrayOutputStream's initial capacity: the
     * base64 expansion plus line breaks plus a generous header allowance.
     * Wrong only in the direction of one extra grow.
     */
    private fun estimateSize(body: String?, attachments: List<MimeAttachment>): Int {
        var n = 256L + (body?.length ?: 0)
        for (att in attachments) {
            n += 256 + (att.data.size.toLong() / 3 + 1) * 4 * 79 / 76
        }
        return n.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
    }

    /**
     * Wrap an armored PGP MESSAGE in the RFC 3156 §4 `multipart/encrypted`
     * envelope: a control part (`application/pgp-encrypted`, body
     * "Version: 1") followed by the ciphertext part
     * (`application/octet-stream`). The result is a complete MIME entity;
     * prepending email headers (Subject/From/To) on top of it yields a
     * valid .eml — that composition is J4's job, not this module's.
     */
    fun wrapEncrypted(
        armored: String,
        boundary: String = randomBoundary(),
        autocryptHeader: String? = null
    ): ByteArray {
        val sb = StringBuilder()
        sb.append("MIME-Version: 1.0").append(CRLF)
        sb.append("Content-Type: multipart/encrypted;").append(CRLF)
        sb.append(" protocol=\"application/pgp-encrypted\";").append(CRLF)
        sb.append(" boundary=\"").append(boundary).append("\"").append(CRLF)
        // 4.0.0 Phase 4 — optional top-level Autocrypt header (Level 1).
        // Only reaches the recipient when the .eml is sent verbatim; most
        // mail apps rebuild the outer headers on share.
        // 4.1.0 Phase 6: moved BELOW Content-Type. keydata carries the whole
        // certificate as base64, so a photo UID, extra subkeys or accumulated
        // third-party certifications pushed the Content-Type line past the
        // envelope unwrap's detection window, and the .eml then failed to
        // decrypt at all rather than merely misrouting. Header order is not
        // significant in RFC 5322, so the marker is now always within the
        // first ~100 bytes no matter how large keydata grows.
        // Covered by BundleEmlRoundTripTest.
        if (!autocryptHeader.isNullOrBlank()) {
            sb.append(autocryptHeader.replace("\r\n", "\n").replace("\n", CRLF)).append(CRLF)
        }
        sb.append(CRLF)
        sb.append("--").append(boundary).append(CRLF)
        sb.append("Content-Type: application/pgp-encrypted").append(CRLF)
        sb.append("Content-Description: PGP/MIME version identification").append(CRLF)
        sb.append(CRLF)
        sb.append("Version: 1").append(CRLF)
        sb.append(CRLF)
        sb.append("--").append(boundary).append(CRLF)
        sb.append("Content-Type: application/octet-stream; name=\"encrypted.asc\"").append(CRLF)
        sb.append("Content-Description: OpenPGP encrypted message").append(CRLF)
        sb.append("Content-Disposition: inline; filename=\"encrypted.asc\"").append(CRLF)
        sb.append(CRLF)
        sb.append(armored.trimEnd().replace("\r\n", "\n").replace("\n", CRLF)).append(CRLF)
        sb.append(CRLF)
        sb.append("--").append(boundary).append("--").append(CRLF)
        return sb.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * 4.2.0 RC6 (#32): the streaming form of [wrapEncrypted], for
     * armored ciphertext too large to hold as a String (a 750 MB bundle
     * armors to ~1.4 GB). Same envelope bytes for the same boundary:
     * the armored content is normalized to CRLF line by line, and
     * trailing blank lines are withheld until a further non-blank line
     * proves they are interior, which reproduces trimEnd() without
     * buffering the content.
     */
    fun wrapEncryptedTo(
        out: OutputStream,
        armoredSource: () -> java.io.InputStream,
        boundary: String = randomBoundary(),
        autocryptHeader: String? = null
    ) {
        fun put(s: String) = out.write(s.toByteArray(Charsets.UTF_8))
        put("MIME-Version: 1.0" + CRLF)
        put("Content-Type: multipart/encrypted;" + CRLF)
        put(" protocol=\"application/pgp-encrypted\";" + CRLF)
        put(" boundary=\"" + boundary + "\"" + CRLF)
        if (!autocryptHeader.isNullOrBlank()) {
            put(autocryptHeader.replace("\r\n", "\n").replace("\n", CRLF) + CRLF)
        }
        put(CRLF)
        put("--" + boundary + CRLF)
        put("Content-Type: application/pgp-encrypted" + CRLF)
        put("Content-Description: PGP/MIME version identification" + CRLF)
        put(CRLF)
        put("Version: 1" + CRLF)
        put(CRLF)
        put("--" + boundary + CRLF)
        put("Content-Type: application/octet-stream; name=\"encrypted.asc\"" + CRLF)
        put("Content-Description: OpenPGP encrypted message" + CRLF)
        put("Content-Disposition: inline; filename=\"encrypted.asc\"" + CRLF)
        put(CRLF)
        armoredSource().bufferedReader(Charsets.UTF_8).use { reader ->
            var pendingBlanks = 0
            var wroteAny = false
            while (true) {
                val line = reader.readLine() ?: break
                if (line.isEmpty()) {
                    pendingBlanks++
                    continue
                }
                repeat(pendingBlanks) { put(CRLF) }
                pendingBlanks = 0
                put(line + CRLF)
                wroteAny = true
            }
            // Trailing blanks are dropped (trimEnd); an all-blank source
            // degenerates to an empty part, matching wrapEncrypted("").
            if (!wroteAny) put(CRLF)
        }
        put(CRLF)
        put("--" + boundary + "--" + CRLF)
    }

    // ── Internals ───────────────────────────────────────────────────────

    /**
     * Strip CR/LF and quotes from a filename so it can't break the
     * header it's embedded in. (Full RFC 2231 encoding of non-ASCII
     * names is future work; UTF-8 raw in the header is what most
     * clients emit and accept today.)
     */
    private fun sanitizeFilename(name: String): String =
        name.replace("\r", "").replace("\n", "").replace("\"", "'")

    /** RFC 2045 §6.8 base64, wrapped at 76 columns with CRLF. */
    internal fun base64Wrapped(data: ByteArray): String {
        val b64 = java.util.Base64.getEncoder().encodeToString(data)
        if (b64.length <= 76) return b64
        val sb = StringBuilder(b64.length + b64.length / 76 * 2 + 2)
        var i = 0
        while (i < b64.length) {
            val end = minOf(i + 76, b64.length)
            sb.append(b64, i, end)
            if (end < b64.length) sb.append(CRLF)
            i = end
        }
        return sb.toString()
    }
}
