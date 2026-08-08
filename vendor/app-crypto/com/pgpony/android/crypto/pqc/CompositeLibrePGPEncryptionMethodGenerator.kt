// CompositeLibrePGPEncryptionMethodGenerator.kt
// PGPony Android — 4.0.0 Phase 2b (LibrePGP composite, algorithm 8 — encrypt)
//
// A BouncyCastle PGPKeyEncryptionMethodGenerator that wraps the message
// session key for a LibrePGP Kyber/ML-KEM-768 + X25519 composite (algo 8)
// recipient and emits the v3 PKESK. BC generates one session key for the
// whole message; here we encapsulate to the recipient, derive the KEK with
// the KMAC256 combiner, RFC-3394 wrap the session key, and hand back a v3
// PKESK packet. BC then builds the encrypted-data body with the same key.
//
// v3 algo-8 PKESK algorithm-specific fields (GnuPG 2.5.21 wire format):
//   ecc ephemeral MPI (X25519 point) | kyberLen(4) | kyber ct (1088) |
//   symAlgo(1) | wrapLen(1) | AES-256-keywrapped session key
//
// Validated by GnuPG decrypting PGPony's output.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.bcpg.ContainedPacket
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

class CompositeLibrePGPEncryptionMethodGenerator(
    private val recipientSubkey: PGPPublicKey,
    private val random: SecureRandom = SecureRandom()
) : PGPKeyEncryptionMethodGenerator {

    override fun generate(
        dataEncryptorBuilder: PGPDataEncryptorBuilder,
        sessionKey: ByteArray
    ): ContainedPacket {
        if (recipientSubkey.algorithm != CompositeLibrePGPKeyMaterial.ALGORITHM_ID) {
            throw PGPException("recipient subkey is not a LibrePGP composite (algo 8)")
        }
        val packet = recipientSubkey.encoded
        val suite = CompositeLibrePGPKeyMaterial.suiteOf(packet)
        val (xPub, kyberPub) = CompositeLibrePGPKeyMaterial.publicMaterial(packet)
        val v5fp = CompositeLibrePGPKeyMaterial.v5Fingerprint(packet)

        // The session-key symmetric algorithm (feeds fixedInfo and the PKESK).
        val symAlgo = dataEncryptorBuilder.algorithm

        val fixedInfo = CompositeKemLibrePGP.fixedInfo(symAlgo, v5fp)
        val enc = CompositeKemLibrePGP.encapsulate(xPub, kyberPub, fixedInfo, random, suite)
        val wrapped = CompositeKemLibrePGP.wrapSessionKey(enc.kek, sessionKey)

        val algoFields = ByteArrayOutputStream().apply {
            write(eccSos(enc.eccEphemeral))
            write(uint32(enc.kyberCiphertext.size))
            write(enc.kyberCiphertext)
            write(symAlgo)
            write(wrapped.size)
            write(wrapped)
        }.toByteArray()

        return PublicKeyEncSessionPacket.createV3PKESKPacket(
            keyIdToLong(CompositeLibrePGPKeyMaterial.v5KeyId(packet)),
            CompositeLibrePGPKeyMaterial.ALGORITHM_ID,
            arrayOf(algoFields)
        )
    }

    private fun eccSos(value: ByteArray): ByteArray {
        // Fixed-width SOS, byte-identical to iOS / GnuPG 2.5.x: the X25519 or
        // X448 KEM ciphertext is a plain keyLen-octet value (no 0x40 native-
        // point prefix, no leading-zero stripping), so the bit length is
        // exactly value.size * 8 (256 for X25519, 448 for X448). gpg reads
        // (bits + 7) / 8 octets and uses them raw, so any high byte value,
        // 0x00 included, round-trips, with no ephemeral-regeneration guard.
        val bits = value.size * 8
        return byteArrayOf((bits ushr 8).toByte(), bits.toByte()) + value
    }

    private fun uint32(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun keyIdToLong(keyId: ByteArray): Long {
        var k = 0L
        for (b in keyId) k = (k shl 8) or (b.toLong() and 0xFF)
        return k
    }
}
