// MimeMessage.kt
// PGPony Android — 3.1.0 Phase 3 (J-core)
//
// Models for the PGP/MIME "Bundle" feature: a message body plus zero
// or more attachments, carried as RFC 2045/2046 `multipart/mixed`
// inside the encrypted payload, and (on the outside) the RFC 3156
// `multipart/encrypted` envelope.
//
// Port of iOS Services/MIME/MIMEMessage.swift (7.1.x). Transport-
// agnostic by design: nothing in this package touches Android APIs,
// crypto, or I/O — it builds and parses bytes. That keeps it fully
// unit-testable on the JVM (see test/kotlin/.../mime/) and reusable
// from the encrypt flow, the decrypt flow, and the share path alike.

package com.pgpony.android.crypto.mime

/**
 * One attachment inside a MIME bundle.
 *
 * [contentType] is the declared media type (e.g. "application/pdf",
 * "image/jpeg"); "application/octet-stream" when unknown. [data] is
 * the raw decoded bytes — transfer encoding (base64 etc.) is a
 * builder/parser concern and never leaks into the model.
 */
class MimeAttachment(
    val filename: String,
    val contentType: String,
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MimeAttachment) return false
        return filename == other.filename &&
            contentType == other.contentType &&
            data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = filename.hashCode()
        result = 31 * result + contentType.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }

    override fun toString(): String =
        "MimeAttachment($filename, $contentType, ${data.size} bytes)"
}

/**
 * A parsed (or to-be-built) bundle: an optional text body plus
 * attachments. Body null means the bundle carried no text part;
 * attachments empty means a body-only message.
 */
class MimeMessage(
    val body: String?,
    val attachments: List<MimeAttachment>
) {
    val hasAttachments: Boolean get() = attachments.isNotEmpty()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MimeMessage) return false
        return body == other.body && attachments == other.attachments
    }

    override fun hashCode(): Int = 31 * (body?.hashCode() ?: 0) + attachments.hashCode()

    override fun toString(): String =
        "MimeMessage(body=${body?.length ?: "null"} chars, ${attachments.size} attachments)"
}
