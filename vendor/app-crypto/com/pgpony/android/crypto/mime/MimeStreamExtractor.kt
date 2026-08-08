// MimeStreamExtractor.kt
// PGPony Android, 4.1.0 Phase 14 (issue #10 / #12, AraafRoyall)
//
// The file-backed twin of MimeParser.parse().
//
// MimeParser takes a ByteArray and returns MimeAttachments that carry
// their bytes. That is correct up to INLINE_FILE_LIMIT and impossible
// above it: a decrypt over that limit streams its plaintext to a
// scratch file precisely so the whole thing is never resident (4.0.4,
// issue #6). Before this class the streamed decrypt path simply did
// not attempt MIME routing, so every bundle larger than the limit
// presented as one opaque file with no extension: the raw
// multipart/mixed container written to disk. That is issue #10.
//
// This extractor walks the container on disk, line by line, and writes
// each attachment out as its own file. Peak memory is one 64 KiB
// buffer plus the bounded text body, regardless of how large the
// bundle or any single attachment is.
//
// Deliberately byte-oriented, not String-oriented. Boundary matching,
// base64 and quoted printable are all ASCII concerns, and decoding a
// multi-megabyte base64 blob into a Kotlin String would cost two bytes
// per character for no benefit. Only the text/plain body is decoded as
// UTF-8, and only up to [BODY_LIMIT].
//
// JVM only, no Android APIs, so it unit tests alongside the rest of
// the mime package.

package com.pgpony.android.crypto.mime

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream

/**
 * One attachment recovered from a bundle, backed by a file on disk
 * rather than by a resident ByteArray.
 *
 * The counterpart to [MimeAttachment], which the buffered paths keep
 * using. Both feed the same result sheet.
 */
class MimeFileAttachment(
    val filename: String,
    val contentType: String,
    val file: File
) {
    val size: Long get() = file.length()

    override fun toString(): String =
        "MimeFileAttachment($filename, $contentType, $size bytes, ${file.name})"
}

/** A bundle extracted to disk: an optional text body plus files. */
class MimeFileMessage(
    val body: String?,
    val attachments: List<MimeFileAttachment>
)

object MimeStreamExtractor {

    /** Chunk size for every copy in this file. */
    private const val BUF = 64 * 1024

    /**
     * Cap on the decoded text body. A bundle body is something a person
     * typed; anything past this is not a message and is not worth
     * holding in memory to render in a sheet.
     */
    private const val BODY_LIMIT = 256 * 1024

    /**
     * How much of the head to sniff in [looksLikeBundle]. The container
     * header block is MimeBuilder.buildMixed's first two lines, well
     * under this, and a foreign builder that pushes Content-Type past
     * 8 KiB of headers is not a case worth chasing.
     */
    private const val SNIFF_BYTES = 8 * 1024

    /**
     * Cheap gate before committing to a full walk: does [source] open
     * with a header block declaring a non-encrypted multipart?
     *
     * Deliberately conservative. A false negative costs nothing (the
     * caller keeps the single-file result it would have shown anyway);
     * a false positive costs a wasted pass over a large file.
     */
    fun looksLikeBundle(source: File): Boolean = runCatching {
        val head = ByteArray(minOf(source.length(), SNIFF_BYTES.toLong()).toInt())
        if (head.isEmpty()) return@runCatching false
        source.inputStream().use { it.read(head) }
        val text = String(head, Charsets.ISO_8859_1)
        val sepIndex = text.indexOf("\n\n").let {
            val crlf = text.indexOf("\r\n\r\n")
            when {
                it < 0 -> crlf
                crlf < 0 -> it
                else -> minOf(it, crlf)
            }
        }
        val headerBlock = if (sepIndex >= 0) text.substring(0, sepIndex) else text
        val ct = parseHeaderBlock(headerBlock)["content-type"]?.lowercase() ?: return@runCatching false
        ct.startsWith("multipart/") && !ct.startsWith("multipart/encrypted")
    }.getOrDefault(false)

    /**
     * Walk the multipart container in [source], writing every
     * attachment part into its own file under [outDir].
     *
     * Returns null when [source] is not a multipart entity, when it
     * declares no boundary, or when the walk yields neither a body nor
     * an attachment. In every one of those cases the caller keeps its
     * existing single-file result, so a parse that does not apply is
     * never worse than not having tried.
     *
     * Each attachment lands in its own numbered subdirectory of
     * [outDir] so two parts named the same do not collide, matching
     * what ScratchFiles.allocate does for streamed outputs.
     */
    fun extract(
        source: File,
        outDir: File,
        onProgress: ((Long) -> Unit)? = null
    ): MimeFileMessage? = runCatching {
        source.inputStream().buffered(BUF).use { stream ->
            extractFrom(stream, outDir, onProgress)
        }
    }.getOrNull()

    private fun extractFrom(
        stream: InputStream,
        outDir: File,
        onProgress: ((Long) -> Unit)?
    ): MimeFileMessage? {
        val reader = LineReader(BufferedInputStream(stream, BUF), onProgress)

        // 1) Container headers.
        val headerLines = StringBuilder()
        while (true) {
            val line = reader.readLine() ?: return null
            if (line.isEmpty()) break
            headerLines.append(String(line, Charsets.ISO_8859_1)).append('\n')
        }
        val headers = parseHeaderBlock(headerLines.toString())
        val contentType = headers["content-type"] ?: return null
        val ctLower = contentType.lowercase()
        if (!ctLower.startsWith("multipart/") || ctLower.startsWith("multipart/encrypted")) {
            return null
        }
        val boundary = MimeParser.headerParameter(contentType, "boundary") ?: return null

        val delim = "--$boundary"
        val closing = "--$boundary--"

        // 2) Skip the preamble up to the first boundary.
        var line = reader.readLine() ?: return null
        while (!matchesBoundary(line, delim)) {
            line = reader.readLine() ?: return null
        }
        if (matchesBoundary(line, closing)) return null

        // 3) Parts.
        var body: String? = null
        val attachments = mutableListOf<MimeFileAttachment>()
        var index = 0

        parts@ while (true) {
            // 3a) Part headers.
            val partHeaderLines = StringBuilder()
            while (true) {
                val hl = reader.readLine() ?: break@parts
                if (hl.isEmpty()) break
                partHeaderLines.append(String(hl, Charsets.ISO_8859_1)).append('\n')
            }
            val ph = parseHeaderBlock(partHeaderLines.toString())
            val pct = ph["content-type"] ?: "text/plain"
            val disposition = ph["content-disposition"] ?: ""
            val encoding = ph["content-transfer-encoding"]?.trim()?.lowercase()
            val filename = MimeParser.headerParameter(disposition, "filename")
                ?: MimeParser.headerParameter(pct, "name")
            val isAttachment = filename != null ||
                disposition.lowercase().startsWith("attachment")
            val isTextBody = !isAttachment &&
                pct.lowercase().startsWith("text/plain") &&
                body == null

            // 3b) Part body. Both sinks stop at the next boundary and
            //     report which one they hit, so the loop knows whether
            //     more parts follow.
            if (isTextBody) {
                val sink = ByteArrayOutputStream()
                val closed = pumpPart(reader, delim, closing, encoding, sink, BODY_LIMIT.toLong())
                body = String(sink.toByteArray(), Charsets.UTF_8)
                    .replace("\r\n", "\n")
                    .trimEnd('\n')
                    .ifBlank { null }
                if (closed) break@parts
            } else {
                index++
                val slot = File(outDir, index.toString()).apply { mkdirs() }
                val target = File(slot, safeName(filename, index))
                var closed: Boolean
                target.outputStream().buffered(BUF).use { out ->
                    closed = pumpPart(reader, delim, closing, encoding, out, Long.MAX_VALUE)
                }
                attachments.add(
                    MimeFileAttachment(
                        filename = filename ?: "attachment$index",
                        contentType = pct.substringBefore(';').trim()
                            .ifBlank { "application/octet-stream" },
                        file = target
                    )
                )
                if (closed) break@parts
            }
        }

        if (body == null && attachments.isEmpty()) return null
        return MimeFileMessage(body, attachments)
    }

    /**
     * Copy one part's body into [out], decoding per [encoding], until a
     * boundary line. Returns true when the line that stopped it was the
     * CLOSING boundary.
     *
     * The newline before a boundary belongs to the boundary, not to the
     * part (RFC 2046 section 5.1.1), so a raw part must not end with the
     * separator that precedes its terminator. That is what the deferred
     * newline below is for: each line's terminator is written only once
     * another content line is known to follow. Base64 and quoted
     * printable strip line endings anyway, so it only bites on 7bit,
     * 8bit and binary parts, which is exactly where a spurious trailing
     * newline would corrupt the file.
     */
    private fun pumpPart(
        reader: LineReader,
        delim: String,
        closing: String,
        encoding: String?,
        out: OutputStream,
        limit: Long
    ): Boolean {
        val base64 = encoding == "base64"
        val qp = encoding == "quoted-printable"
        val b64buf = ByteArrayOutputStream(BUF)
        var written = 0L
        var pendingNewline = false

        while (true) {
            val line = reader.readLine() ?: return true
            if (matchesBoundary(line, closing)) {
                flushBase64(b64buf, out, base64, true)
                return true
            }
            if (matchesBoundary(line, delim)) {
                flushBase64(b64buf, out, base64, true)
                return false
            }
            when {
                base64 -> {
                    for (b in line) {
                        val c = b.toInt().toChar()
                        if (c != ' ' && c != '\t' && c != '\r') b64buf.write(b.toInt())
                    }
                    if (b64buf.size() >= BUF) {
                        written += flushBase64(b64buf, out, true, false)
                    }
                }
                qp -> {
                    if (pendingNewline) { out.write('\n'.code); written++ }
                    // A soft line break ("=" at end of line) means the
                    // next line continues this one with no separator, so
                    // the "=" is a continuation marker and not data. It
                    // has to come off before decoding: fed to the decoder
                    // it is a trailing "=" with nothing after it, which
                    // RFC 2045 leaves undefined and the decoder passes
                    // through literally.
                    val soft = line.isNotEmpty() && line[line.size - 1].toInt().toChar() == '='
                    val payload = if (soft) line.copyOfRange(0, line.size - 1) else line
                    val decoded = MimeParser.decodeQuotedPrintable(
                        String(payload, Charsets.ISO_8859_1)
                    )
                    out.write(decoded)
                    written += decoded.size
                    pendingNewline = !soft
                }
                else -> {
                    if (pendingNewline) { out.write('\n'.code); written++ }
                    out.write(line)
                    written += line.size
                    pendingNewline = true
                }
            }
            if (written >= limit) {
                // Bounded sink (the text body). Keep consuming so the
                // reader still lands on the boundary, just stop writing.
                return drainToBoundary(reader, delim, closing)
            }
        }
    }

    /** Consume and discard until a boundary; true if it was the closing one. */
    private fun drainToBoundary(reader: LineReader, delim: String, closing: String): Boolean {
        while (true) {
            val line = reader.readLine() ?: return true
            if (matchesBoundary(line, closing)) return true
            if (matchesBoundary(line, delim)) return false
        }
    }

    /**
     * Decode whatever whole base64 quanta are buffered and write them.
     * Only [final] decodes a trailing partial group, which is where the
     * padding lives.
     */
    private fun flushBase64(
        buf: ByteArrayOutputStream,
        out: OutputStream,
        base64: Boolean,
        final: Boolean
    ): Long {
        if (!base64 || buf.size() == 0) { if (final) buf.reset(); return 0 }
        val all = buf.toByteArray()
        buf.reset()
        val usable = if (final) all.size else (all.size / 4) * 4
        if (usable > 0) {
            val decoded = try {
                java.util.Base64.getMimeDecoder().decode(all.copyOfRange(0, usable))
            } catch (_: Exception) {
                ByteArray(0)
            }
            out.write(decoded)
            if (!final && usable < all.size) buf.write(all, usable, all.size - usable)
            return decoded.size.toLong()
        }
        if (!final) buf.write(all, 0, all.size)
        return 0
    }

    /**
     * True when [line] is this [marker] boundary line. Trailing
     * whitespace after a boundary is legal and common, so the
     * comparison trims the end rather than demanding equality.
     */
    private fun matchesBoundary(line: ByteArray, marker: String): Boolean {
        if (line.size < marker.length) return false
        for (i in marker.indices) {
            if (line[i].toInt().toChar() != marker[i]) return false
        }
        for (i in marker.length until line.size) {
            val c = line[i].toInt().toChar()
            if (c != ' ' && c != '\t' && c != '\r') return false
        }
        // "--b" must not match a line that is really "--b--": the caller
        // tests the closing marker first, so reaching here with a longer
        // line means only trailing whitespace followed.
        return true
    }

    /** Header block to lowercase-keyed map, RFC 5322 folding unfolded. */
    private fun parseHeaderBlock(block: String): Map<String, String> {
        val headers = mutableMapOf<String, String>()
        var current: String? = null
        for (raw in block.replace("\r\n", "\n").split('\n')) {
            val line = raw.trimEnd('\r')
            if (line.isEmpty()) continue
            if ((line[0] == ' ' || line[0] == '\t') && current != null) {
                headers[current] = headers[current] + " " + line.trim()
                continue
            }
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val name = line.substring(0, colon).trim().lowercase()
            headers[name] = line.substring(colon + 1).trim()
            current = name
        }
        return headers
    }

    /**
     * A part's filename is attacker controlled (it arrives inside the
     * ciphertext), so strip every path separator before it becomes a
     * real file. Same rule ScratchFiles.allocate applies to the literal
     * data packet's name.
     */
    private fun safeName(filename: String?, index: Int): String =
        (filename ?: "")
            .substringAfterLast('/')
            .substringAfterLast('\\')
            .replace(" ", "")
            .trim()
            .ifBlank { "attachment$index" }

    /**
     * Reads one line at a time as raw bytes, without a charset in the
     * way. Returns the line without its CR/LF terminator, or null at
     * end of input. Lines here are MIME lines: base64 at 76 columns,
     * headers, boundaries. A pathological input with no line breaks at
     * all grows one buffer, which is why [MAX_LINE] caps it.
     */
    private class LineReader(
        private val input: InputStream,
        private val onProgress: ((Long) -> Unit)? = null
    ) {
        private val acc = ByteArrayOutputStream(256)

        // 4.1.0 Phase 17c: bytes consumed from the container, reported
        // every REPORT_EVERY so a caller can drive a progress bar.
        // Extraction is the slow half of a large card decrypt (base64
        // decode plus one file write per attachment) and it was the half
        // reporting nothing, so the bar sat at 100% through all of it.
        private var consumed = 0L
        private var lastReported = 0L

        // Own buffer rather than one read() per byte through a
        // BufferedInputStream: an 11 MB bundle is 11 million virtual
        // calls that way, which is seconds of pure overhead on a phone.
        private val buf = ByteArray(BUF)
        private var pos = 0
        private var len = 0

        private fun fill(): Boolean {
            if (pos < len) return true
            len = input.read(buf)
            pos = 0
            if (len > 0) {
                consumed += len
                if (consumed - lastReported >= REPORT_EVERY) {
                    lastReported = consumed
                    onProgress?.invoke(consumed)
                }
            }
            return len > 0
        }

        fun readLine(): ByteArray? {
            acc.reset()
            var sawAny = false
            while (true) {
                if (!fill()) return if (sawAny) trimCr(acc.toByteArray()) else null
                var i = pos
                while (i < len && buf[i].toInt() != '\n'.code) i++
                val chunk = i - pos
                if (chunk > 0) {
                    sawAny = true
                    val room = MAX_LINE - acc.size()
                    if (room > 0) acc.write(buf, pos, minOf(chunk, room))
                }
                if (i < len) {
                    pos = i + 1
                    return trimCr(acc.toByteArray())
                }
                pos = len
            }
        }

        private fun trimCr(line: ByteArray): ByteArray =
            if (line.isNotEmpty() && line[line.size - 1].toInt() == '\r'.code) {
                line.copyOfRange(0, line.size - 1)
            } else {
                line
            }

        companion object {
            /** 1 MiB. No legal MIME line approaches this. */
            const val MAX_LINE = 1 shl 20

            /** Progress granularity. Fine enough to animate, coarse
             *  enough not to flood a StateFlow. */
            const val REPORT_EVERY = 256 * 1024
        }
    }
}
