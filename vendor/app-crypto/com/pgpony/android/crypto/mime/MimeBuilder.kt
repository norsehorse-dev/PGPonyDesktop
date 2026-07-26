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

import java.security.SecureRandom

object MimeBuilder {

    private const val CRLF = "\r\n"

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
        val sb = StringBuilder()
        sb.append("MIME-Version: 1.0").append(CRLF)
        sb.append("Content-Type: multipart/mixed; boundary=\"").append(boundary).append("\"")
            .append(CRLF)
        sb.append(CRLF)

        if (!body.isNullOrBlank()) {
            sb.append("--").append(boundary).append(CRLF)
            sb.append("Content-Type: text/plain; charset=utf-8").append(CRLF)
            sb.append("Content-Transfer-Encoding: 8bit").append(CRLF)
            sb.append(CRLF)
            // Normalize the body itself to CRLF so the entity is fully
            // canonical regardless of how the compose field delivered it.
            sb.append(body.replace("\r\n", "\n").replace("\n", CRLF)).append(CRLF)
        }

        for (att in attachments) {
            val safeName = sanitizeFilename(att.filename)
            sb.append("--").append(boundary).append(CRLF)
            sb.append("Content-Type: ").append(att.contentType)
                .append("; name=\"").append(safeName).append("\"").append(CRLF)
            sb.append("Content-Transfer-Encoding: base64").append(CRLF)
            sb.append("Content-Disposition: attachment; filename=\"").append(safeName)
                .append("\"").append(CRLF)
            sb.append(CRLF)
            sb.append(base64Wrapped(att.data)).append(CRLF)
        }

        sb.append("--").append(boundary).append("--").append(CRLF)
        return sb.toString().toByteArray(Charsets.UTF_8)
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
        // 4.0.0 Phase 4 — optional top-level Autocrypt header (Level 1).
        // Only reaches the recipient when the .eml is sent verbatim; most
        // mail apps rebuild the outer headers on share.
        if (!autocryptHeader.isNullOrBlank()) {
            sb.append(autocryptHeader.replace("\r\n", "\n").replace("\n", CRLF)).append(CRLF)
        }
        sb.append("Content-Type: multipart/encrypted;").append(CRLF)
        sb.append(" protocol=\"application/pgp-encrypted\";").append(CRLF)
        sb.append(" boundary=\"").append(boundary).append("\"").append(CRLF)
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
