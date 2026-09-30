// SopCleartext.kt
// PGPony Desktop 3.0.0, checkpoint 5d-4: the Cleartext Signature Framework (RFC 9580 section 7)
// for pgpony-sop, read and written with the line endings kept.
//
// The shared ClearSignedParser turns CRLF into LF and drops the line ending in front of the
// signature, and the canonicalizer then dropped one more line ending; a message whose text
// ends in a blank line, or any v6 message from another implementation, did not verify. This
// reader takes the text between the header and the signature (dash escapes removed) and builds
// the signed octets from it: every line with its trailing spaces and tabs removed, joined with
// CRLF. The line ending in front of the BEGIN PGP SIGNATURE line belongs to the framework, not
// the text (RFC 9580 7.1), so neither the signed octets nor the output include it.
//
// The output is the signed text: each line with its trailing spaces and tabs removed (they are
// not signed, so handing them back would pass off unauthenticated bytes as signed) and with the
// line ending it had, so CRLF text comes back as CRLF.
//
// It is strict where the interop suite says to be: text before the BEGIN line or after the
// END line, and a header other than Hash (SaltedHash and Charset are tolerated), make the
// message malformed, since either could pass for signed text.
//
// The writer covers several signing keys: one signature packet per key in the signature block,
// and a Hash header only when every signature is v4 (RFC 9580 leaves it out for v6).

package com.pgpony.desktop

internal object SopCleartext {

    private const val BEGIN_MESSAGE = "-----BEGIN PGP SIGNED MESSAGE-----"
    private const val BEGIN_SIGNATURE = "-----BEGIN PGP SIGNATURE-----"
    private const val END_SIGNATURE = "-----END PGP SIGNATURE-----"
    private val ALLOWED_HEADERS = setOf("hash", "saltedhash", "charset")

    class Parsed(
        /** The text as it was signed: dash escapes removed, line endings as sent. */
        val text: ByteArray,
        /** The octets the signatures cover (RFC 9580 7.2). */
        val signed: ByteArray,
        /** The armored signature block. */
        val signatureBlock: ByteArray
    )

    /** One line: its content (no line ending) and the ending it had ("", "\n" or "\r\n"). */
    private class Line(val content: String, val ending: String)

    private fun lines(text: String): List<Line> {
        val out = ArrayList<Line>()
        var i = 0
        while (i < text.length) {
            val nl = text.indexOf('\n', i)
            if (nl < 0) {
                out.add(Line(text.substring(i), ""))
                break
            }
            val raw = text.substring(i, nl)
            if (raw.endsWith("\r")) out.add(Line(raw.dropLast(1), "\r\n")) else out.add(Line(raw, "\n"))
            i = nl + 1
        }
        return out
    }

    private fun bad(msg: String): Nothing = throw SopException(SopExit.BAD_DATA, "malformed cleartext signed message: $msg")

    /** Read a cleartext signed message. Throws BAD_DATA when it is malformed. */
    fun parse(input: ByteArray): Parsed {
        val all = lines(String(input, Charsets.UTF_8))
        var i = 0
        while (i < all.size && all[i].content.isBlank()) i++
        if (i >= all.size || all[i].content.trimEnd() != BEGIN_MESSAGE) bad("text before the message")
        i++
        while (true) {
            val line = all.getOrNull(i) ?: bad("no text")
            i++
            if (line.content.isBlank()) break
            val key = line.content.substringBefore(':', "").trim().lowercase()
            if (key !in ALLOWED_HEADERS) bad("unexpected header")
        }
        val body = ArrayList<Line>()
        while (true) {
            val line = all.getOrNull(i) ?: bad("no signature")
            i++
            if (line.content.trimEnd() == BEGIN_SIGNATURE) break
            val content = if (line.content.startsWith("- ")) line.content.substring(2) else line.content
            body.add(Line(content.trimEnd(' ', '\t'), line.ending))
        }
        // The last line ending before the signature is the framework's, not the text's.
        val text = StringBuilder()
        body.forEachIndexed { k, l -> text.append(l.content); if (k < body.lastIndex) text.append(l.ending) }
        val sig = StringBuilder(BEGIN_SIGNATURE).append('\n')
        while (true) {
            val line = all.getOrNull(i) ?: bad("no end of signature")
            i++
            sig.append(line.content).append('\n')
            if (line.content.trimEnd() == END_SIGNATURE) break
        }
        while (i < all.size) {
            if (all[i].content.isNotBlank()) bad("text after the signature")
            i++
        }
        return Parsed(
            text = text.toString().toByteArray(Charsets.UTF_8),
            signed = signedOctets(body.map { it.content }),
            signatureBlock = sig.toString().toByteArray(Charsets.UTF_8)
        )
    }

    private fun signedOctets(lines: List<String>): ByteArray =
        lines.joinToString("\r\n") { it.trimEnd(' ', '\t') }.toByteArray(Charsets.UTF_8)

    /**
     * The octets a signature over [text] must cover when [text] is sent as cleartext. A text that
     * ends in a line ending has an empty last line, which [write] keeps with a separator.
     */
    fun signedOctetsOf(text: ByteArray): ByteArray {
        val content = String(text, Charsets.UTF_8).split('\n').map { it.removeSuffix("\r") }
        return signedOctets(content)
    }

    /**
     * A cleartext signed message carrying [text] and the signature [packets] (binary), which
     * must be text signatures over [signedOctetsOf] of the same text.
     */
    fun write(text: ByteArray, packets: List<ByteArray>): ByteArray {
        val infos = packets.map { SopSigInfo.parse(it) }
        val out = StringBuilder(BEGIN_MESSAGE).append('\n')
        if (infos.isNotEmpty() && infos.all { it != null && it.version == 4 }) {
            val names = infos.mapNotNull { HASH_NAMES[it!!.hashAlgo] }.distinct()
            if (names.isNotEmpty()) out.append("Hash: ").append(names.joinToString(",")).append('\n')
        }
        out.append('\n')
        val body = lines(String(text, Charsets.UTF_8))
        // The text keeps its own line endings, then one more line ending separates it from the
        // signature block (RFC 9580 7.1), so a text that ends in a line ending keeps it.
        for (line in body) {
            if (line.content.startsWith("-")) out.append("- ")
            out.append(line.content).append(line.ending)
        }
        out.append('\n')
        val block = SopArmor.output(packets.fold(ByteArray(0)) { acc, b -> acc + b }, SopArmor.SIGNATURE, false)
        return out.toString().toByteArray(Charsets.UTF_8) + block
    }

    private val HASH_NAMES = mapOf(
        2 to "SHA1", 8 to "SHA256", 9 to "SHA384", 10 to "SHA512", 11 to "SHA224", 12 to "SHA3-256", 14 to "SHA3-512"
    )
}

/**
 * 3.0.0 (5d-4): an inline signed message for one or more signers, built from their detached
 * signature packets: one-pass signature packets in signer order (all but the last flagged as
 * followed by another), the literal data, then the signatures in reverse order, as RFC 9580
 * 5.4 pairs them. A composite (ML-DSA) signature takes a v6 one-pass packet like any v6 one.
 */
internal object SopInline {

    fun build(packets: List<ByteArray>, data: ByteArray, text: Boolean): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        packets.forEachIndexed { i, p -> out.write(onePass(p, last = i == packets.lastIndex)) }
        out.write(literal(data, text))
        packets.asReversed().forEach { out.write(it) }
        return out.toByteArray()
    }

    /** A literal data packet: binary ('b') or UTF-8 text ('u'), no file name, no date. */
    fun literal(data: ByteArray, text: Boolean): ByteArray =
        com.pgpony.android.crypto.pqc.CompositeSigPacket.packet(
            11, byteArrayOf(if (text) 'u'.code.toByte() else 'b'.code.toByte(), 0, 0, 0, 0, 0) + data
        )

    /** The one-pass signature packet announcing signature [packet]. */
    private fun onePass(packet: ByteArray, last: Boolean): ByteArray {
        val (_, body) = com.pgpony.android.crypto.pqc.CompositeSigPacket.firstPacket(packet)
        val sig = com.pgpony.android.crypto.CertificateBindings.SigBody(body)
        val flag = if (last) 1.toByte() else 0.toByte()
        val out = java.io.ByteArrayOutputStream()
        if (sig.version == 6) {
            val fp = sig.issuerFingerprint() ?: throw SopException(SopExit.BAD_DATA, "a v6 signature without its issuer")
            out.write(byteArrayOf(6, sig.type.toByte(), sig.hashAlg.toByte(), sig.pkAlg.toByte(), sig.salt.size.toByte()))
            out.write(sig.salt)
            out.write(fp)
        } else {
            val id = sig.issuerKeyId() ?: sig.issuerFingerprint()?.let { fp ->
                var v = 0L
                for (b in fp.copyOfRange(fp.size - 8, fp.size)) v = (v shl 8) or (b.toLong() and 0xFF)
                v
            } ?: throw SopException(SopExit.BAD_DATA, "a signature without its issuer")
            out.write(byteArrayOf(3, sig.type.toByte(), sig.hashAlg.toByte(), sig.pkAlg.toByte()))
            for (k in 7 downTo 0) out.write(((id ushr (8 * k)) and 0xFF).toInt())
        }
        out.write(flag.toInt())
        return com.pgpony.android.crypto.pqc.CompositeSigPacket.packet(4, out.toByteArray())
    }
}
