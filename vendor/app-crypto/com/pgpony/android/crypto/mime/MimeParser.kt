// MimeParser.kt
// PGPonyAndroid — 3.1.0 Phase 3 (J-core)
//
// The receive side of the Bundle feature. Two entry points:
//
//   1. parse(bytes)  — decode a DECRYPTED plaintext as MIME. A
//      `multipart/mixed` yields body + attachments (→ the structured
//      result screen, J1); a top-level `text/plain` entity yields a
//      body-only message; anything that doesn't carry MIME headers
//      returns null so the caller keeps the existing file/text result
//      path unchanged.
//
//   2. pgpMimeEncryptedPayload(text) — given INCOMING text that may be
//      an RFC 3156 `multipart/encrypted` envelope (a raw .eml from
//      Thunderbird etc., with or without leading email headers),
//      extract the armored PGP MESSAGE to hand to the normal decrypt
//      pipeline. A bare armored block is deliberately NOT treated as
//      an envelope (returns null) — iOS parity, and it keeps plain
//      inline input on its existing path (J2).
//
// Port of iOS Services/MIME/MIMEParser.swift (7.1.x). Parsing is
// deliberately lenient where mail reality demands it: CRLF and LF
// both accepted, header names case-insensitive, folded headers
// unfolded, boundary and filename parameters quoted or bare,
// base64 / quoted-printable / 7bit / 8bit transfer encodings.

package com.pgpony.android.crypto.mime

object MimeParser {

    private const val ARMOR_BEGIN = "-----BEGIN PGP MESSAGE-----"
    private const val ARMOR_END = "-----END PGP MESSAGE-----"

    // ── 1. Decrypted-plaintext parsing (multipart/mixed → MimeMessage) ──

    /**
     * Parse [data] as a MIME entity. Returns null when the content does
     * not look like MIME at all (no parseable header block with a
     * Content-Type or MIME-Version header before the first blank line),
     * so callers can fall back to the existing plain result handling.
     */
    fun parse(data: ByteArray): MimeMessage? {
        val text = try {
            String(data, Charsets.UTF_8)
        } catch (_: Exception) {
            return null
        }
        val (headers, bodyText) = splitHeadersAndBody(text) ?: return null

        val contentType = headers["content-type"]
        val hasMimeSignal = contentType != null || headers.containsKey("mime-version")
        if (!hasMimeSignal) return null

        val ctLower = contentType?.lowercase() ?: "text/plain"

        // multipart/mixed (and, leniently, other non-encrypted multiparts:
        // multipart/related or /alternative from foreign builders still
        // yield their text + attachment parts usefully).
        if (ctLower.startsWith("multipart/") && !ctLower.startsWith("multipart/encrypted")) {
            val boundary = headerParameter(contentType!!, "boundary") ?: return null
            val parts = splitParts(bodyText, boundary)
            if (parts.isEmpty()) return null

            var body: String? = null
            val attachments = mutableListOf<MimeAttachment>()
            for (part in parts) {
                val (ph, pb) = splitHeadersAndBody(part) ?: Pair(emptyMap(), part)
                val pct = ph["content-type"] ?: "text/plain"
                val pctLower = pct.lowercase()
                val disposition = ph["content-disposition"] ?: ""
                val filename = headerParameter(disposition, "filename")
                    ?: headerParameter(pct, "name")
                val isAttachment = filename != null ||
                    disposition.lowercase().startsWith("attachment")

                val decoded = decodeTransfer(pb, ph["content-transfer-encoding"])
                if (!isAttachment && pctLower.startsWith("text/plain") && body == null) {
                    body = String(decoded, Charsets.UTF_8)
                        .replace("\r\n", "\n")
                        .trimEnd('\n')
                } else {
                    attachments.add(
                        MimeAttachment(
                            filename = filename ?: "attachment",
                            contentType = pct.substringBefore(';').trim()
                                .ifBlank { "application/octet-stream" },
                            data = decoded
                        )
                    )
                }
            }
            if (body == null && attachments.isEmpty()) return null
            return MimeMessage(body, attachments)
        }

        // Non-multipart text entity → body-only message.
        if (ctLower.startsWith("text/plain")) {
            val decoded = decodeTransfer(bodyText, headers["content-transfer-encoding"])
            return MimeMessage(
                String(decoded, Charsets.UTF_8).replace("\r\n", "\n").trimEnd('\n'),
                emptyList()
            )
        }

        // Some other single-part media type: surface it as one attachment
        // rather than dropping it.
        val decoded = decodeTransfer(bodyText, headers["content-transfer-encoding"])
        val filename = headerParameter(headers["content-disposition"] ?: "", "filename")
            ?: headerParameter(contentType ?: "", "name")
            ?: "attachment"
        return MimeMessage(
            null,
            listOf(
                MimeAttachment(
                    filename,
                    (contentType ?: "application/octet-stream").substringBefore(';').trim(),
                    decoded
                )
            )
        )
    }

    // ── 2. RFC 3156 envelope unwrap (incoming .eml → armored payload) ──

    /**
     * If [text] is (or contains, after leading email headers) an RFC
     * 3156 `multipart/encrypted` entity, return the armored PGP MESSAGE
     * from its ciphertext part. Returns null when no such envelope is
     * present — including for a bare armored block, which must stay on
     * the plain inline path (iOS parity).
     */
    fun pgpMimeEncryptedPayload(text: String): String? {
        // Cheap gate: no envelope marker → not our job. This is what
        // keeps a bare "-----BEGIN PGP MESSAGE-----" block out.
        val ctIndex = indexOfHeaderValue(text, "multipart/encrypted") ?: return null

        // Locate the armored block AFTER the envelope declaration; the
        // ciphertext part always follows the Content-Type that declared
        // the envelope.
        val begin = text.indexOf(ARMOR_BEGIN, startIndex = ctIndex)
        if (begin < 0) return null
        val endMarker = text.indexOf(ARMOR_END, startIndex = begin)
        if (endMarker < 0) return null
        val end = endMarker + ARMOR_END.length
        return text.substring(begin, end)
            .replace("\r\n", "\n")
            .trim()
    }

    // ── Internals ───────────────────────────────────────────────────────

    /**
     * Split a MIME entity into (headers, body) at the first blank line.
     * Headers are unfolded (RFC 5322 §2.2.3) and keyed lowercase.
     * Returns null when the text before the first blank line doesn't
     * look like a header block (no "Name: value" lines).
     */
    private fun splitHeadersAndBody(text: String): Pair<Map<String, String>, String>? {
        val normalized = text.replace("\r\n", "\n")
        val sepIndex = normalized.indexOf("\n\n")
        val headerBlock: String
        val body: String
        if (sepIndex >= 0) {
            headerBlock = normalized.substring(0, sepIndex)
            body = normalized.substring(sepIndex + 2)
        } else {
            headerBlock = normalized
            body = ""
        }

        val headers = mutableMapOf<String, String>()
        var currentName: String? = null
        var sawHeader = false
        for (line in headerBlock.split('\n')) {
            if (line.isEmpty()) continue
            if ((line[0] == ' ' || line[0] == '\t') && currentName != null) {
                // Folded continuation of the previous header.
                headers[currentName] = headers[currentName] + " " + line.trim()
                continue
            }
            val colon = line.indexOf(':')
            if (colon <= 0) {
                // Not a header line: if we haven't seen any header yet,
                // this isn't a header block at all.
                if (!sawHeader) return null
                // After valid headers, a stray line ends the block
                // leniently; treat the rest as body.
                break
            }
            val name = line.substring(0, colon).trim().lowercase()
            val value = line.substring(colon + 1).trim()
            headers[name] = value
            currentName = name
            sawHeader = true
        }
        if (!sawHeader) return null
        return Pair(headers, body)
    }

    /**
     * Extract a parameter (boundary, filename, name, …) from a header
     * value like `multipart/mixed; boundary="xyz"`. Quoted or bare.
     */
    internal fun headerParameter(headerValue: String, param: String): String? {
        val regex = Regex(
            "(?:^|;)\\s*${Regex.escape(param)}\\s*=\\s*(\"([^\"]*)\"|[^;\\s]+)",
            RegexOption.IGNORE_CASE
        )
        val m = regex.find(headerValue) ?: return null
        return m.groupValues[2].ifEmpty { m.groupValues[1] }.trim().takeIf { it.isNotEmpty() }
    }

    /** Split a multipart body into its parts by [boundary]. */
    private fun splitParts(body: String, boundary: String): List<String> {
        val delim = "--$boundary"
        val closing = "--$boundary--"
        val lines = body.split('\n')
        val parts = mutableListOf<String>()
        var current: StringBuilder? = null
        for (line in lines) {
            val trimmed = line.trimEnd('\r')
            when {
                trimmed == closing || trimmed.startsWith(closing) -> {
                    current?.let { parts.add(it.toString()) }
                    current = null
                }
                trimmed == delim -> {
                    current?.let { parts.add(it.toString()) }
                    current = StringBuilder()
                }
                else -> current?.append(line)?.append('\n')
            }
        }
        // Unterminated final part (missing closing boundary): keep it,
        // mail reality includes truncated entities.
        current?.let { if (it.isNotBlank()) parts.add(it.toString()) }
        return parts.map { it.trimEnd('\n') }.filter { it.isNotBlank() }
    }

    /** Decode a part body per its Content-Transfer-Encoding. */
    private fun decodeTransfer(body: String, encoding: String?): ByteArray {
        return when (encoding?.trim()?.lowercase()) {
            "base64" -> {
                val compact = body.filterNot { it == '\r' || it == '\n' || it == ' ' || it == '\t' }
                try {
                    java.util.Base64.getDecoder().decode(compact)
                } catch (_: Exception) {
                    body.toByteArray(Charsets.UTF_8)
                }
            }
            "quoted-printable" -> decodeQuotedPrintable(body)
            // 7bit, 8bit, binary, or absent → raw bytes.
            else -> body.toByteArray(Charsets.UTF_8)
        }
    }

    /** RFC 2045 §6.7 quoted-printable, including soft line breaks. */
    internal fun decodeQuotedPrintable(text: String): ByteArray {
        val src = text.replace("\r\n", "\n")
        val out = java.io.ByteArrayOutputStream(src.length)
        var i = 0
        while (i < src.length) {
            val c = src[i]
            if (c == '=') {
                when {
                    // Soft line break: "=\n" disappears.
                    i + 1 < src.length && src[i + 1] == '\n' -> i += 2
                    i + 2 < src.length -> {
                        val hex = src.substring(i + 1, i + 3)
                        val value = hex.toIntOrNull(16)
                        if (value != null) {
                            out.write(value)
                            i += 3
                        } else {
                            out.write(c.code)
                            i += 1
                        }
                    }
                    else -> {
                        out.write(c.code)
                        i += 1
                    }
                }
            } else {
                // Non-ASCII chars in QP source are technically illegal but
                // occur in the wild; write their UTF-8 bytes.
                val bytes = c.toString().toByteArray(Charsets.UTF_8)
                out.write(bytes, 0, bytes.size)
                i += 1
            }
        }
        return out.toByteArray()
    }

    /**
     * Case-insensitive search for [needle] appearing as part of a
     * Content-Type header value (i.e. on a line whose name is
     * Content-Type, allowing folding). Returns the index just past the
     * match, or null. Lenient by design: leading email headers, CRLF or
     * LF, and folded parameters all pass through.
     */
    private fun indexOfHeaderValue(text: String, needle: String): Int? {
        val lower = text.lowercase()
        var from = 0
        while (true) {
            val i = lower.indexOf(needle.lowercase(), startIndex = from)
            if (i < 0) return null
            // Walk back to the start of the (possibly folded) header this
            // occurrence sits in and check its name.
            var lineStart = lower.lastIndexOf('\n', i).let { if (it < 0) 0 else it + 1 }
            // Unfold: while the line starts with whitespace, the header
            // began on an earlier line.
            while (lineStart > 0 && (lower[lineStart] == ' ' || lower[lineStart] == '\t')) {
                lineStart = lower.lastIndexOf('\n', lineStart - 2).let { if (it < 0) 0 else it + 1 }
            }
            if (lower.startsWith("content-type", startIndex = lineStart)) {
                return i + needle.length
            }
            from = i + needle.length
        }
    }
}
