// MimeEnvelope.kt
// PGPony Android — 4.1.0 Phase 7
//
// The RFC 3156 envelope unwrap, extracted out of the ViewModels.
//
// It existed as two byte-for-byte identical private functions,
// EncryptDecryptViewModel.effectiveDecryptFileBytes and
// ShareTargetViewModel.unwrapEnvelopeBytes, plus a third reproduction inside
// BundleEmlRoundTripTest because neither was reachable from a JVM test. Phase
// 6 had to apply the same one-line fix to both copies by hand, which is the
// concrete cost that justified this move: the share path is where issue #6 is
// reported, and a divergence between the two would be invisible.
//
// WHAT CHANGED BEYOND THE MOVE. The old code decided whether to attempt an
// unwrap by scanning a FIXED PREFIX of the input for the "multipart/encrypted"
// marker. That prefix was 8192 bytes, raised to 65536 in Phase 6 after a
// sender's Autocrypt header, which carries a whole certificate as base64, was
// found to push the Content-Type line out of it and cause a hard
// DecryptionFailed rather than a misroute.
//
// A bigger number was never the right answer, because the bound is arbitrary
// and the failure it produces is silent. The prefix scan only ever existed to
// avoid decoding a large BINARY blob into a String, and
// MimeParser.pgpMimeEncryptedPayload already carries its own marker gate and
// returns null for anything that is not an envelope. So the question this
// needs to answer is not "does the marker appear early" but "is this text at
// all", which is cheap, bounded, and has no size limit hiding in it.
//
// The answer here is a 1 KB probe: no NUL bytes, and the first non-blank line
// looks like an RFC 5322 header. Binary OpenPGP ciphertext fails on the first
// test almost immediately; a bare armored block fails on the second, since
// "-----BEGIN PGP MESSAGE-----" has no colon, which preserves the deliberate
// J2 behaviour that a bare block is NOT an envelope and stays on the plain
// inline path. An .eml passes regardless of how large its headers are, which
// is what removes the class of bug Phase 6 found rather than moving its
// threshold.

package com.pgpony.android.crypto.mime

object MimeEnvelope {

    /**
     * Bytes past which this refuses to decode at all. A PGP/MIME email is not
     * 32 MB; a file the user picked might well be. The old fixed-prefix code
     * had no such ceiling and would decode a file of any size once its marker
     * check passed, so this is strictly safer than what it replaces.
     */
    private const val MAX_ENVELOPE_BYTES = 32 * 1024 * 1024

    /** How much is examined to decide "is this text at all". */
    private const val PROBE_BYTES = 1024

    /**
     * Text entry point. If [raw] is (or contains, after leading email headers)
     * an RFC 3156 `multipart/encrypted` entity, return the armored PGP MESSAGE
     * inside it; otherwise return [raw] unchanged. A bare armored block is NOT
     * an envelope and passes through as-is (iOS parity, J2).
     */
    fun unwrapText(raw: String): String =
        MimeParser.pgpMimeEncryptedPayload(raw) ?: raw

    /**
     * Byte entry point, for an .eml opened or shared as a FILE. Unwraps to the
     * armored bytes when an envelope is present; otherwise returns [bytes]
     * unchanged, which covers binary ciphertext and plain armored files.
     */
    fun unwrapBytes(bytes: ByteArray): ByteArray {
        if (bytes.size > MAX_ENVELOPE_BYTES) return bytes
        if (!looksLikeMailHeaders(bytes)) return bytes
        val text = try {
            String(bytes, Charsets.UTF_8)
        } catch (_: Exception) {
            return bytes
        }
        val armored = MimeParser.pgpMimeEncryptedPayload(text) ?: return bytes
        return armored.toByteArray(Charsets.UTF_8)
    }

    /**
     * 4.2.0 RC6 (#32, tail-4): streaming envelope support. Returns the
     * byte offset at which the armored PGP MESSAGE begins inside the
     * input, or -1 when no armor marker appears in the first
     * [OFFSET_SCAN_BYTES]. The streamed decrypt paths were feeding a
     * raw .eml straight to the crypto layer — only the buffered path
     * (≤ INLINE_FILE_LIMIT) unwrapped the RFC 3156 envelope, so any
     * .eml past 4 MB failed with "invalid header encountered". Callers
     * probe with one open of the source, then reopen and skip to the
     * offset for the real pass:
     *   • plain armored file → marker on line one → offset 0, harmless
     *   • binary ciphertext → no marker in the scan window → -1,
     *     stream passes through untouched
     *   • .eml → offset of the BEGIN line inside the ciphertext part
     * The trailing envelope close after END is never consumed: the
     * armor parser stops at the END line on its own.
     */
    fun armoredPayloadOffset(input: java.io.InputStream): Long {
        val marker = "-----BEGIN PGP MESSAGE-----"
        val bin = java.io.BufferedInputStream(input)
        val lineBuf = StringBuilder()
        var lineStart = 0L
        var pos = 0L
        while (pos < OFFSET_SCAN_BYTES) {
            val b = bin.read()
            if (b < 0) break
            pos++
            when (b) {
                '\n'.code -> {
                    if (lineBuf.toString() == marker) return lineStart
                    lineBuf.setLength(0)
                    lineStart = pos
                }
                '\r'.code -> { /* dropped; CRLF handled at the \n */ }
                else -> if (lineBuf.length <= marker.length) lineBuf.append(b.toChar())
            }
        }
        // A final unterminated line can still be the marker (armored
        // content follows in the same stream past the scan cap).
        if (lineBuf.toString() == marker) return lineStart
        return -1L
    }

    /** Scan window for [armoredPayloadOffset]. An RFC 3156 prefix is a
     *  few hundred bytes; 64 KiB leaves room for oversized mail headers
     *  (Autocrypt keydata etc.) while keeping the probe cheap. */
    private const val OFFSET_SCAN_BYTES = 64L * 1024

    /**
     * Cheap, bounded "is this an RFC 5322 header block" test, replacing the
     * old fixed-prefix marker scan. Deliberately conservative: a false
     * negative means an envelope is not unwrapped, a false positive only costs
     * one wasted decode because [MimeParser.pgpMimeEncryptedPayload] then
     * returns null and the bytes pass through untouched.
     */
    private fun looksLikeMailHeaders(bytes: ByteArray): Boolean {
        val probeLen = minOf(bytes.size, PROBE_BYTES)
        if (probeLen == 0) return false

        // Binary ciphertext reaches a NUL almost immediately; mail headers
        // never contain one.
        for (i in 0 until probeLen) {
            if (bytes[i] == 0.toByte()) return false
        }

        val probe = try {
            String(bytes, 0, probeLen, Charsets.UTF_8)
        } catch (_: Exception) {
            return false
        }
        val firstLine = probe.lineSequence().firstOrNull { it.isNotBlank() } ?: return false

        // "Name: value". The name is what distinguishes a header from armor,
        // from base64, and from prose.
        val colon = firstLine.indexOf(':')
        if (colon <= 0) return false
        return firstLine.substring(0, colon).all { it.isLetterOrDigit() || it == '-' }
    }
}
