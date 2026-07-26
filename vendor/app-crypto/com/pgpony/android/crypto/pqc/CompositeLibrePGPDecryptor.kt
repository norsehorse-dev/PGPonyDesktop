// CompositeLibrePGPDecryptor.kt
// PGPony Android — 4.0.0 Phase 2b (LibrePGP composite, algorithm 8)
//
// Decrypt a GnuPG/LibrePGP message whose session key is wrapped for a
// Kyber/ML-KEM-768 + X25519 composite (algorithm 8) recipient. As with the
// IETF algo-35 path, BouncyCastle's PKESK parser throws on the unknown
// algorithm, so we:
//   1. Split the top-level packets; find the v3 algo-8 PKESK, keep the
//      encrypted-data packet (SEIPDv1 tag 18, or LibrePGP AEAD tag 20) after it.
//   2. Recover the session key with the LibrePGP KMAC256 combiner:
//      X25519-ECDH + Kyber-decapsulate -> KEK -> RFC-3394 unwrap.
//   3. Hand the encrypted-data packet + session key to BC's session-key
//      decryptor (it handles both tag-18 v1 CFB/MDC and tag-20 AEAD).
//
// v3 algo-8 PKESK algorithm-specific fields (verified vs GnuPG 2.5.21):
//   ecc ephemeral MPI (X25519 point, 32) | kyberLen(4) | kyber ct (1088) |
//   symAlgo(1) | wrapLen(1) | AES-256-keywrapped session key
//
// Validated offline against GnuPG 2.5.21 composite messages.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import java.io.ByteArrayInputStream
import java.io.InputStream

object CompositeLibrePGPDecryptor {

    class Result(val stream: InputStream, val integrity: PGPEncryptedData)

    class NoMatchingKey(message: String) : Exception(message)

    private const val TAG_PKESK = 1
    private const val TAG_SKESK = 3
    private const val VERSION_3 = 3

    fun tryDecrypt(
        encryptedData: ByteArray,
        secretKeyRings: List<PGPSecretKeyRing>,
        passphrase: String? = null
    ): Result? {
        val binary = toBinary(encryptedData)
        val split = split(binary) ?: return null // no LibrePGP algo-8 PKESK
        val pkesk = split.pkesk

        val secKey = findSecretKey(pkesk.keyId, secretKeyRings)
            ?: throw NoMatchingKey("no held LibrePGP composite secret key for ${pkesk.keyId.toHex()}")
        val packet = secKey.encoded

        val material = CompositeLibrePGPKeyMaterial.extractFromPacket(packet, passphrase?.toCharArray())
        val v5fp = CompositeLibrePGPKeyMaterial.v5Fingerprint(packet)
        val (recipientXPub, _) = CompositeLibrePGPKeyMaterial.publicMaterial(packet)

        val mlkemSec = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, material.kyberSeed)
        val fixedInfo = CompositeKemLibrePGP.fixedInfo(pkesk.symAlgo, v5fp)
        val kek = CompositeKemLibrePGP.decapsulate(
            pkesk.eccEphemeral, pkesk.kyberCiphertext, material.x25519Secret, recipientXPub, mlkemSec, fixedInfo
        )
        val sessionKey = CompositeKemLibrePGP.unwrapSessionKey(kek, pkesk.wrappedSessionKey)

        val bcpgIn = BCPGInputStream(ByteArrayInputStream(split.remainder))
        val encList = PGPEncryptedDataList(bcpgIn)
        val sessionEnc = encList.extractSessionKeyEncryptedData()
        val factory = BcSessionKeyDataDecryptorFactory(PGPSessionKey(pkesk.symAlgo, sessionKey))
        return Result(sessionEnc.getDataStream(factory), sessionEnc)
    }

    // ── PKESK parsing ────────────────────────────────────────────────

    private class Pkesk(
        val keyId: ByteArray,
        val symAlgo: Int,
        val eccEphemeral: ByteArray,
        val kyberCiphertext: ByteArray,
        val wrappedSessionKey: ByteArray
    )

    /** Parse a v3 algo-8 PKESK body, or null if it isn't one. */
    private fun parsePkesk(body: ByteArray): Pkesk? {
        try {
            var i = 0
            if ((body[i++].toInt() and 0xFF) != VERSION_3) return null
            val keyId = body.copyOfRange(i, i + 8); i += 8
            if ((body[i++].toInt() and 0xFF) != CompositeKemLibrePGP.ALGORITHM_ID) return null

            // ecc ephemeral: MPI (X25519 point)
            val bits = ((body[i].toInt() and 0xFF) shl 8) or (body[i + 1].toInt() and 0xFF); i += 2
            val eccLen = (bits + 7) / 8
            val ecc = body.copyOfRange(i, i + eccLen); i += eccLen
            // kyber ciphertext: 4-octet length prefix
            val kyberLen = readUInt32(body, i); i += 4
            val kyber = body.copyOfRange(i, i + kyberLen); i += kyberLen
            // wrapped session key: symAlgo(1), wrapLen(1), wrapped
            val symAlgo = body[i++].toInt() and 0xFF
            val wrapLen = body[i++].toInt() and 0xFF
            val wrapped = body.copyOfRange(i, i + wrapLen)
            return Pkesk(keyId, symAlgo, ecc, kyber, wrapped)
        } catch (e: Exception) {
            return null
        }
    }

    // ── packet splitting ─────────────────────────────────────────────

    private class Split(val pkesk: Pkesk, val remainder: ByteArray)

    private fun split(data: ByteArray): Split? {
        var i = 0
        var pkesk: Pkesk? = null
        val n = data.size
        while (i < n) {
            val h = header(data, i) ?: break
            val isEsk = h.tag == TAG_PKESK || h.tag == TAG_SKESK
            if (!isEsk) {
                val p = pkesk ?: return null
                return Split(p, data.copyOfRange(i, n))
            }
            if (h.tag == TAG_PKESK && pkesk == null) {
                parsePkesk(data.copyOfRange(h.bodyStart, h.bodyStart + h.bodyLen))?.let { pkesk = it }
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
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = data[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (data[i++].toInt() and 0xFF) + 192
                l0 == 255 -> readUInt32(data, i).also { i += 4 }
                else -> return null
            }
        } else {
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> data[i++].toInt() and 0xFF
                1 -> (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> readUInt32(data, i).also { i += 4 }
                else -> data.size - i
            }
        }
        return Header(tag, i, length)
    }

    // ── helpers ──────────────────────────────────────────────────────

    private fun findSecretKey(keyId: ByteArray, rings: List<PGPSecretKeyRing>): PGPSecretKey? =
        rings.asSequence()
            .flatMap { it.secretKeys.asSequence() }
            .firstOrNull { sk ->
                sk.publicKey.algorithm == CompositeLibrePGPKeyMaterial.ALGORITHM_ID &&
                    sk.publicKey.version == 5 &&
                    CompositeLibrePGPKeyMaterial.v5KeyId(sk.encoded).contentEquals(keyId)
            }

    private fun readUInt32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun toBinary(data: ByteArray): ByteArray {
        val looksArmored = data.isNotEmpty() && data[0].toInt() == '-'.code
        if (!looksArmored) return data
        ArmoredInputStream(ByteArrayInputStream(data)).use { return it.readBytes() }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02X".format(it) }
}
