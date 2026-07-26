// CompositeLibrePGPKeyMaterial.kt
// PGPony Android — 4.0.0 Phase 2b (LibrePGP composite, algorithm 8)
//
// Parse a v5 LibrePGP composite (algo 8, Kyber/ML-KEM-768 + X25519) secret
// subkey packet: recover the raw secret material and compute the v5
// fingerprint. BouncyCastle can't interpret algo-8 key material, so we
// hand-parse the packet; the S2K + CFB decryption of a protected key reuses
// BC's tested PBESecretKeyDecryptor.
//
// v5 secret subkey packet (verified against GnuPG 2.5.21 output):
//   ver(1)=5 | ctime(4) | algo(1)=8 | pkMatLen(4)=1227 | pubMat(1227) |
//   s2kUsage(1) | [protection] | secMatLen(4) | secretMaterial
// where for usage 254 (SHA-1 CFB) the protection is
//   paramCount(1) | sym(1) | S2K | IV        (paramCount = sym+S2K+IV length)
// and the decrypted secret material is
//   X25519 secret (32) || Kyber-768 seed (64) [ || SHA-1 checksum (20) ].
//
// v5 fingerprint = SHA-256( 0x9A || 4-octet packet-length || packet body ).

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.security.MessageDigest

object CompositeLibrePGPKeyMaterial {

    const val ALGORITHM_ID = CompositeKemLibrePGP.ALGORITHM_ID // 8
    const val KYBER768_SEED_LEN = 64
    const val X25519_LEN = 32

    private const val USAGE_NONE = 0
    private const val USAGE_SHA1 = 254
    private const val USAGE_CHECKSUM = 255

    data class Material(val x25519Secret: ByteArray, val kyberSeed: ByteArray)

    class ProtectedKeyException(message: String) : Exception(message)

    /** v5 fingerprint over the public-key portion of [packet]. */
    fun v5Fingerprint(packet: ByteArray): ByteArray {
        val body = tagAndBody(packet).second
        val pkMatLen = readUInt32(body, 6)
        val pub = body.copyOfRange(0, 10 + pkMatLen)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(0x9A.toByte())
        md.update(uint32be(pub.size))
        md.update(pub)
        return md.digest()
    }

    /** v5 key ID = the leading 8 octets of the v5 fingerprint. */
    fun v5KeyId(packet: ByteArray): ByteArray = v5Fingerprint(packet).copyOfRange(0, 8)

    /**
     * (X25519 public 32, Kyber-768 public 1184) from a v5 algo-8 key packet.
     * Public material = OID | X25519 point MPI (0x40 || 32) | kyberLen(4) | kyber.
     */
    fun publicMaterial(packet: ByteArray): Pair<ByteArray, ByteArray> {
        val body = tagAndBody(packet).second
        val pkMatLen = readUInt32(body, 6)
        val pub = body.copyOfRange(10, 10 + pkMatLen)
        var p = 0
        val oidLen = pub[p++].toInt() and 0xFF
        p += oidLen
        val bits = ((pub[p].toInt() and 0xFF) shl 8) or (pub[p + 1].toInt() and 0xFF); p += 2
        val pointLen = (bits + 7) / 8            // includes the 0x40 native prefix
        val x25519 = pub.copyOfRange(p + pointLen - X25519_LEN, p + pointLen)
        p += pointLen
        val kyberLen = readUInt32(pub, p); p += 4
        val kyber = pub.copyOfRange(p, p + kyberLen)
        return x25519 to kyber
    }

    /**
     * Recover (X25519 secret, Kyber-768 seed) from a v5 algo-8 secret subkey
     * [packet], decrypting with [passphrase] if protected.
     */
    fun extractFromPacket(packet: ByteArray, passphrase: CharArray?): Material {
        val body = tagAndBody(packet).second
        var i = 0
        require((body[i++].toInt() and 0xFF) == 5) { "LibrePGP composite subkey must be v5" }
        i += 4 // creation time
        require((body[i++].toInt() and 0xFF) == ALGORITHM_ID) { "expected algo $ALGORITHM_ID" }
        val pkMatLen = readUInt32(body, i); i += 4
        i += pkMatLen // skip public material

        val usage = body[i++].toInt() and 0xFF
        val material: ByteArray = when (usage) {
            USAGE_NONE -> {
                i++ // v5 conditional-parameter length octet (0 when unprotected)
                val secMatLen = readUInt32(body, i); i += 4
                require(secMatLen >= X25519_LEN + KYBER768_SEED_LEN) { "secret material too short" }
                body.copyOfRange(i, i + X25519_LEN + KYBER768_SEED_LEN)
            }

            USAGE_SHA1, USAGE_CHECKSUM -> {
                if (passphrase == null) {
                    throw ProtectedKeyException("LibrePGP composite secret key is passphrase-protected")
                }
                val paramCount = body[i++].toInt() and 0xFF
                val paramStart = i
                val sym = body[i++].toInt() and 0xFF
                val s2kLen = s2kSpecifierLength(body[i].toInt() and 0xFF)
                val s2kBytes = body.copyOfRange(i, i + s2kLen); i += s2kLen
                val ivLen = paramCount - (i - paramStart)
                val iv = body.copyOfRange(i, i + ivLen); i += ivLen
                val secMatLen = readUInt32(body, i); i += 4
                val enc = body.copyOfRange(i, i + secMatLen)

                val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase)
                val s2k = buildS2K(s2kBytes)
                val key = decryptor.makeKeyFromPassPhrase(sym, s2k)
                val plain = decryptor.recoverKeyData(sym, key, iv, enc, 0, enc.size)
                require(plain.size >= X25519_LEN + KYBER768_SEED_LEN) { "recovered material too short" }
                plain.copyOfRange(0, X25519_LEN + KYBER768_SEED_LEN)
            }

            else -> throw ProtectedKeyException("unsupported v5 S2K usage $usage")
        }

        return Material(
            material.copyOfRange(0, X25519_LEN),
            material.copyOfRange(X25519_LEN, X25519_LEN + KYBER768_SEED_LEN)
        )
    }

    // ── helpers ──────────────────────────────────────────────────────

    private fun s2kSpecifierLength(type: Int): Int = when (type) {
        S2K.SIMPLE -> 2                 // type + hash
        S2K.SALTED -> 10                // type + hash + salt(8)
        S2K.SALTED_AND_ITERATED -> 11   // type + hash + salt(8) + count
        S2K.ARGON_2 -> 20               // type + salt(16) + t + p + m
        else -> throw ProtectedKeyException("unsupported S2K type $type")
    }

    private fun buildS2K(b: ByteArray): S2K = when (val type = b[0].toInt() and 0xFF) {
        S2K.SIMPLE -> S2K.simpleS2K(b[1].toInt() and 0xFF)
        S2K.SALTED -> S2K.saltedS2K(b[1].toInt() and 0xFF, b.copyOfRange(2, 10))
        S2K.SALTED_AND_ITERATED -> S2K.saltedAndIteratedS2K(
            b[1].toInt() and 0xFF, b.copyOfRange(2, 10), b[10].toInt() and 0xFF
        )
        S2K.ARGON_2 -> S2K.argon2S2K(
            S2K.Argon2Params(b.copyOfRange(1, 17), b[17].toInt() and 0xFF, b[18].toInt() and 0xFF, b[19].toInt() and 0xFF)
        )
        else -> throw ProtectedKeyException("unsupported S2K type $type")
    }

    private fun uint32be(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun readUInt32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun tagAndBody(packet: ByteArray): Pair<Int, ByteArray> {
        var i = 0
        val c = packet[i++].toInt() and 0xFF
        require(c and 0x80 != 0) { "not a packet header" }
        val tag: Int
        val length: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = packet[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (packet[i++].toInt() and 0xFF) + 192
                l0 == 255 -> readUInt32(packet, i).also { i += 4 }
                else -> throw IllegalArgumentException("partial length in key packet")
            }
        } else {
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> packet[i++].toInt() and 0xFF
                1 -> (((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> readUInt32(packet, i).also { i += 4 }
                else -> packet.size - i
            }
        }
        return tag to packet.copyOfRange(i, i + length)
    }
}
