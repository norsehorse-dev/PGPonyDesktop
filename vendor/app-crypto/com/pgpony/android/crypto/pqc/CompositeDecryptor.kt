// CompositeDecryptor.kt
// PGPony Android — 4.0.0 Phase 2b (slice 4b, decrypt side)
//
// Decrypt an OpenPGP message whose session key is wrapped for an IETF
// composite (algo 35, ML-KEM-768 + X25519) recipient. BouncyCastle's PKESK
// parser throws on algo 35 (PGPEncryptedDataList only skips *version*
// mismatches, not unknown algorithms), so we can't hand BC the raw message.
// Instead:
//
//   1. Split the top-level packets ourselves. Find the composite PKESK
//      (tag 1, v6, algo 35) and keep everything from the SEIPD onward.
//   2. Recover the session key with our own KEM: ML-KEM-decapsulate +
//      X25519-ECDH → combiner KEK → RFC-3394 unwrap.
//   3. Feed the SEIPD (with no ESK packet in front) to BC via
//      PGPEncryptedDataList.extractSessionKeyEncryptedData(), applying the
//      recovered session key. BC does the SEIPDv2 (AEAD) / SEIPDv1 body.
//
// Verified against sequoia-sq 1.4.0-pqc.1 composite messages.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import java.io.ByteArrayInputStream
import java.io.InputStream

object CompositeDecryptor {

    /** Composite decrypt succeeded: [stream] is the plaintext, [integrity]
     *  is BC's encrypted-data object for the SEIPD integrity gate. */
    class Result(val stream: InputStream, val integrity: PGPEncryptedData)

    class NoMatchingKey(message: String) : Exception(message)

    /**
     * Attempt composite decryption. Returns null when the message carries
     * no composite PKESK (caller should fall back to the normal path).
     * Throws [NoMatchingKey] / [CompositeSecretKeyMaterial.ProtectedKeyException]
     * when a composite PKESK IS present but can't be decrypted.
     */
    fun tryDecrypt(
        encryptedData: ByteArray,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String? = null
    ): Result? {
        val binary = toBinary(encryptedData)
        val split = split(binary) ?: return null // no composite PKESK

        val secKey = findSecretKey(split.parsed.recipientFingerprint, secretKeyRings)
            ?: throw NoMatchingKey(
                "no held composite secret key for recipient " +
                    split.parsed.recipientFingerprint.toHex()
            )

        val material = CompositeSecretKeyMaterial.extract(secKey, passphrase?.toCharArray())
            ?: throw NoMatchingKey("matched key is not a composite secret key")

        // Rebuild the recipient's composite secret and derive the KEK.
        // 4.2.0 §1.1: the PKESK told us which suite (35 or 36); use it for the
        // ML-KEM parameter set and to route the combiner to X25519 or X448.
        val suite = split.parsed.suite
        val mlkemSec = MLKEMPrivateKeyParameters(suite.mlkem.params, material.mlkemSeed)
        val (recipientXPub, _) = CompositeKeyMaterial.publicMaterial(secKey.publicKey)
            ?: throw NoMatchingKey("composite public material malformed")

        val kek = CompositeKem.decapsulate(
            ephemeralX25519 = split.parsed.ephemeralX25519,
            mlkemCiphertext = split.parsed.mlkemCiphertext,
            recipientX25519Sec = material.x25519Secret,
            recipientMlkemSec = mlkemSec,
            recipientX25519Pub = recipientXPub,
            suite = suite
        )
        val sessionKey = CompositeKem.unwrapSessionKey(kek, split.parsed.wrappedSessionKey)

        // Hand the recovered session key to BC's SEIPD decryptor. The SEIPD
        // sits alone (no ESK packet), so use the session-key entry point.
        val bcpgIn = BCPGInputStream(ByteArrayInputStream(split.remainder))
        val encList = PGPEncryptedDataList(bcpgIn)
        val sessionEnc = encList.extractSessionKeyEncryptedData()
        val factory = BcSessionKeyDataDecryptorFactory(
            PGPSessionKey(SymmetricKeyAlgorithmTags.AES_256, sessionKey)
        )
        val stream = sessionEnc.getDataStream(factory)
        return Result(stream, sessionEnc)
    }

    /** 4.1.2 (issue #33): head-sniff for the streaming decrypt path.
     *  True when the leading ESK packets include an algo-35 composite
     *  PKESK. [head] is typically truncated somewhere past the ESKs; a
     *  truncated or unparseable head reads as false, and the caller then
     *  falls through to BouncyCastle, which fails the same way it did
     *  before the sniff existed, so a miss cannot regress anything. */
    fun sniffHead(head: ByteArray): Boolean {
        var i = 0
        while (i < head.size) {
            val h = try { header(head, i) } catch (e: Exception) { null } ?: return false
            if (h.tag != TAG_PKESK && h.tag != TAG_SKESK) return false
            val end = h.bodyStart + h.bodyLen
            if (h.tag == TAG_PKESK) {
                if (h.bodyLen < 0 || end > head.size) return false
                val ok = try {
                    CompositePkesk.parseBody(head.copyOfRange(h.bodyStart, end)) != null
                } catch (e: Exception) { false }
                if (ok) return true
            }
            if (end <= i) return false
            i = end
        }
        return false
    }

    // ── packet splitting ─────────────────────────────────────────────

    private class Split(val parsed: CompositePkesk.Parsed, val remainder: ByteArray)

    /**
     * Walk the top-level packets, dropping every leading ESK packet
     * (PKESK tag 1 / SKESK tag 3) and returning the composite PKESK's
     * parsed fields plus the byte stream from the first non-ESK packet
     * (the SEIPD) onward. Returns null if no composite PKESK is present.
     */
    private fun split(data: ByteArray): Split? {
        var i = 0
        var parsed: CompositePkesk.Parsed? = null
        val n = data.size
        while (i < n) {
            // 4.1.2 (issue #33): decide ESK-vs-body from the tag octet
            // alone, BEFORE parsing any length. The SEIPD that follows the
            // ESKs may use partial-length framing (BC's generator emits it
            // for anything over its buffer), which header() rejects, and
            // the old order made that reject read as "no composite PKESK",
            // so any composite message over roughly one buffer fell
            // through to BC and failed. ESK packets themselves always
            // carry definite lengths, so header() stays correct for them.
            val first = data[i].toInt() and 0xFF
            if (first and 0x80 == 0) break
            val tag = if (first and 0x40 != 0) first and 0x3F else (first shr 2) and 0x0F
            if (tag != TAG_PKESK && tag != TAG_SKESK) {
                // First non-ESK packet: the encrypted-data (SEIPD) packet,
                // handed onward with its framing intact; BC reads partial
                // lengths natively.
                val p = parsed ?: return null
                return Split(p, data.copyOfRange(i, n))
            }
            val h = header(data, i) ?: break
            if (h.tag == TAG_PKESK && parsed == null) {
                val body = data.copyOfRange(h.bodyStart, h.bodyStart + h.bodyLen)
                CompositePkesk.parseBody(body)?.let { parsed = it }
            }
            i = h.bodyStart + h.bodyLen
        }
        return null
    }

    private class Header(val tag: Int, val bodyStart: Int, val bodyLen: Int)

    private fun header(data: ByteArray, start: Int): Header? {
        var i = start
        val c = data[i++].toInt() and 0xFF
        if (c and 0x80 == 0) return null
        val tag: Int
        val length: Int
        if (c and 0x40 != 0) { // new format
            tag = c and 0x3F
            val l0 = data[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (data[i++].toInt() and 0xFF) + 192
                l0 == 255 -> uint32(data, i).also { i += 4 }
                else -> return null // partial length: not expected before/at SEIPD start
            }
        } else { // old format
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> data[i++].toInt() and 0xFF
                1 -> (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> uint32(data, i).also { i += 4 }
                else -> data.size - i
            }
        }
        return Header(tag, i, length)
    }

    private fun uint32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or
            ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or
            (b[off + 3].toInt() and 0xFF)

    private const val TAG_PKESK = 1
    private const val TAG_SKESK = 3

    // ── helpers ──────────────────────────────────────────────────────

    private fun findSecretKey(fp: ByteArray, rings: List<PGPSecretKeyRing>) =
        rings.asSequence()
            .flatMap { it.secretKeys.asSequence() }
            .firstOrNull {
                CompositeSuite.ietfFor(it.publicKey.algorithm) != null &&
                    it.publicKey.fingerprint.contentEquals(fp)
            }

    private fun toBinary(data: ByteArray): ByteArray {
        val looksArmored = data.isNotEmpty() && data[0].toInt() == '-'.code
        if (!looksArmored) return data
        ArmoredInputStream(ByteArrayInputStream(data)).use { armored ->
            return armored.readBytes()
        }
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02X".format(it) }
}
