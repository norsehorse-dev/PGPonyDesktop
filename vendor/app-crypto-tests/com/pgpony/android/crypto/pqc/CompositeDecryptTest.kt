// CompositeDecryptTest.kt
// PGPony Android — 4.0.0 Phase 2b (slice 4b)
//
// End-to-end decrypt of real composite (ML-KEM-768 + X25519, algo 35)
// messages, driven through PGPony's public PGPCryptoService.decrypt so the
// whole composite routing is exercised: hand-split the PKESK, extract the
// composite secret material, decapsulate + unwrap the session key, and hand
// it to BouncyCastle's SEIPDv2 (AEAD) decryptor.
//
// Fixtures are genuine output from post-quantum tools, in
// src/test/resources/pqc/:
//   sq-sec.pgp / sq-msg.pgp                  sequoia-sq 1.4.0-pqc.1
//   rfc9580-pqc-sample-key.asc / -message    draft-ietf-openpgp-pqc Appendix A
//
// These are STRONG correctness proofs, not "didn't throw": SEIPDv2 is AEAD,
// so a wrong session key (i.e. a wrong KEM combiner, unwrap, or secret-key
// split) fails the OCB tag and throws inside the stream read. Recovering a
// non-empty literal means the recovered session key was exactly right.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeNoException
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeDecryptTest {

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    private fun secretRing(bytes: ByteArray): PGPSecretKeyRing =
        PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)),
            JcaKeyFingerprintCalculator()
        )

    // De-armor to raw packet bytes (fixtures are ASCII-armored despite .pgp).
    private fun deArmor(bytes: ByteArray): ByteArray =
        if (bytes.isNotEmpty() && bytes[0].toInt() == '-'.code)
            ArmoredInputStream(ByteArrayInputStream(bytes)).use { it.readBytes() }
        else bytes

    // Find and return the algo-35 secret subkey packet (header + body) from a
    // binary key stream, without asking BC to parse the (ML-DSA-signed) ring.
    private fun algo35SecretSubkeyPacket(data: ByteArray): ByteArray {
        var i = 0
        while (i < data.size) {
            val c = data[i].toInt() and 0xFF
            var j = i + 1
            val tag: Int
            val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                val l0 = data[j++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (data[j++].toInt() and 0xFF) + 192
                    l0 == 255 -> uint32(data, j).also { j += 4 }
                    else -> error("partial length unexpected in key")
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> data[j++].toInt() and 0xFF
                    1 -> (((data[j].toInt() and 0xFF) shl 8) or (data[j + 1].toInt() and 0xFF)).also { j += 2 }
                    2 -> uint32(data, j).also { j += 4 }
                    else -> data.size - j
                }
            }
            val body = data.copyOfRange(j, j + len)
            if (tag == 7 && body.size > 6 && body[0].toInt() == 6 && (body[5].toInt() and 0xFF) == 35) {
                return data.copyOfRange(i, j + len)
            }
            i = j + len
        }
        error("no algo-35 secret subkey packet found")
    }

    // (X25519 pub 32, ML-KEM pub 1184) from the packet's public material.
    private fun compositePublicMaterial(packet: ByteArray): Pair<ByteArray, ByteArray> {
        // strip header
        var i = 1
        val c = packet[0].toInt() and 0xFF
        if (c and 0x40 != 0) {
            val l0 = packet[i++].toInt() and 0xFF
            when {
                l0 < 192 -> {}
                l0 < 224 -> i += 1
                l0 == 255 -> i += 4
            }
        } else {
            when (c and 0x03) { 0 -> i += 1; 1 -> i += 2; 2 -> i += 4 }
        }
        // body: ver(1) ctime(4) algo(1) pkMatLen(4) pubMat
        val pubStart = i + 1 + 4 + 1 + 4
        val xPub = packet.copyOfRange(pubStart, pubStart + 32)
        val mPub = packet.copyOfRange(pubStart + 32, pubStart + 32 + 1184)
        return xPub to mPub
    }

    private fun uint32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or
            ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or
            (b[off + 3].toInt() and 0xFF)

    @Test
    fun `sq composite message decrypts with the sq secret key`() {
        val sk = res("sq-sec.pgp")
        val msg = res("sq-msg.pgp")
        assumeTrue("pqc/sq-sec.pgp or sq-msg.pgp absent", sk != null && msg != null)

        // sq's mldsa65-ed25519 key carries ML-DSA (algo 30) self-signatures.
        // BouncyCastle 1.85 has no ML-DSA, so PGPSecretKeyRing construction
        // throws ("unknown signature key algorithm: 30") before our composite
        // code is reached. That's a PQC *signature* gap in BC, orthogonal to
        // ML-KEM *decryption* (proven by the RFC 9580 vector below). Skip
        // cleanly so this second, independent-tool fixture activates for free
        // once BC gains ML-DSA.
        val ring = try {
            secretRing(sk!!)
        } catch (e: java.io.IOException) {
            assumeNoException("BC 1.85 can't parse sq's ML-DSA (algo 30) signatures", e)
            return
        }

        val result = PGPCryptoService.shared.decrypt(msg!!, listOf(ring), passphrase = null)

        assertTrue("decrypted plaintext should be non-empty", result.data.isNotEmpty())
        println("[composite] sq-msg -> ${result.data.size} bytes: '${String(result.data).take(120)}'")
    }

    @Test
    fun `RFC9580 PQC sample message decrypts with the sample key`() {
        val sk = res("rfc9580-pqc-sample-key.asc")
        val msg = res("rfc9580-pqc-sample-message.asc")
        assumeTrue("pqc/rfc9580 sample fixtures absent", sk != null && msg != null)

        val result = PGPCryptoService.shared.decrypt(msg!!, listOf(secretRing(sk!!)), passphrase = null)

        // The draft's canonical composite message decrypts to exactly this.
        assertArrayEquals(
            "RFC 9580 PQC vector must decrypt to the draft's plaintext",
            "Testing\n".toByteArray(), result.data
        )
    }

    @Test
    fun `PGPony encrypt to a composite key round-trips through PGPony decrypt`() {
        // Uses the composite subkey as recipient (slice 4a), then reads it
        // back with the composite decrypt path (slice 4b). Exact byte
        // round-trip proves both directions agree on the KEM, the wrap, the
        // PKESK layout, and the secret-key split — offline, no external tool.
        val sk = res("rfc9580-pqc-sample-key.asc")
        assumeTrue("pqc/rfc9580 sample key absent", sk != null)
        val secRing = secretRing(sk!!)
        val pubRing = PGPPublicKeyRing(secRing.publicKeys.asSequence().toList())

        val plaintext = "PGPony composite round-trip check 123".toByteArray()
        val armored = PGPCryptoService.shared.encrypt(plaintext, listOf(pubRing))

        val result = PGPCryptoService.shared.decrypt(armored, listOf(secRing), passphrase = null)
        assertArrayEquals("composite round-trip must preserve plaintext", plaintext, result.data)
    }

    @Test
    fun `sq AEAD-protected composite subkey decrypts and matches its public key`() {
        val sk = res("sq-sec-protected.pgp")
        assumeTrue("pqc/sq-sec-protected.pgp absent", sk != null)

        // Throwaway test-fixture passphrase for the protected sq key.
        val passphrase = "pgpony-test".toCharArray()

        val packet = algo35SecretSubkeyPacket(deArmor(sk!!))
        val material = CompositeSecretKeyMaterial.extractFromPacket(packet, passphrase)

        // Recovering the secret at all already proves the AEAD unwrap: OCB is
        // authenticated, so a wrong S2K key, nonce, or AAD fails the tag and
        // throws. Prove it's the RIGHT key by re-deriving the public halves.
        val (xPub, mPub) = compositePublicMaterial(packet)

        val derivedX = X25519PrivateKeyParameters(material.x25519Secret, 0)
            .generatePublicKey().encoded
        assertArrayEquals("recovered X25519 secret must match the public key", xPub, derivedX)

        val derivedM = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, material.mlkemSeed).publicKey
        assertArrayEquals("recovered ML-KEM seed must expand to the public key", mPub, derivedM)
    }

    @Test
    fun `tryDecrypt returns null for a classic (non-composite) v6 message`() {
        // The canonical RFC 9580 X25519-AEAD message (A.8.5) is v6 but NOT
        // composite; the composite path must decline it so BC's normal
        // decrypt runs. Absence of the vector just skips the check.
        val ct = javaClass.getResourceAsStream("/rfc9580/a8_encrypted.asc")?.use { it.readBytes() }
        assumeTrue("rfc9580/a8_encrypted.asc absent", ct != null)
        assertNull(
            "classic X25519 message must not be claimed by the composite path",
            CompositeDecryptor.tryDecrypt(ct!!, emptyList())
        )
    }
}
