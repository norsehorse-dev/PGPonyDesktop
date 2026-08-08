// CompositeStreamDecryptTest.kt
// PGPony Android, 4.1.2 (issue #33)
//
// Regression net for the bug where the composite (PQC) trial existed only
// in the buffered decrypt: a file encrypted to an ML-KEM key failed in
// decryptStream because BouncyCastle's PKESK parser throws on the unknown
// algorithm before any PGPony code runs. These tests drive the public
// decryptStream entry point end to end for both composite families and
// both armor states, plus the interchange a user actually crosses
// (encrypt buffered, decrypt streamed, and both streamed).
//
// Same strong-proof property as CompositeDecryptTest: the containers are
// AEAD or MDC checked, so a wrong session key fails the read rather than
// yielding wrong bytes quietly.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class CompositeStreamDecryptTest {

    private val svc = PGPCryptoService.shared

    private fun pub(data: ByteArray) =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun sec(data: ByteArray) =
        PGPSecretKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun newKey(algo: KeyAlgorithm, passphrase: String? = null) =
        svc.generateKeyPair("Streamer PQC", "pqc@pgpony.app", algo, passphrase, null)

    private fun decryptStreamed(
        ciphertext: ByteArray,
        rings: List<PGPSecretKeyRing>,
        passphrase: String? = null,
    ): Pair<ByteArray, com.pgpony.android.crypto.DecryptStreamResult> {
        val out = ByteArrayOutputStream()
        val result = svc.decryptStream(
            input = ByteArrayInputStream(ciphertext),
            output = out,
            secretKeyRings = rings,
            passphrase = passphrase,
        )
        return out.toByteArray() to result
    }

    private fun roundTrip(algo: KeyAlgorithm, armor: Boolean) {
        val k = newKey(algo)
        // Non-repeating and larger than one 64 KiB chunk, so truncation
        // or chunk duplication cannot hide behind compression.
        val plaintext = ByteArray(200_000) { (it * 31 + (it shr 8)).toByte() }
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = armor
        )
        val (recovered, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun `v6 composite file decrypts through the stream, binary`() =
        roundTrip(KeyAlgorithm.MLKEM768_X25519_V6, armor = false)

    @Test
    fun `v6 composite file decrypts through the stream, armored`() =
        roundTrip(KeyAlgorithm.MLKEM768_X25519_V6, armor = true)

    @Test
    fun `v5 LibrePGP composite file decrypts through the stream, binary`() =
        roundTrip(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, armor = false)

    @Test
    fun `v5 LibrePGP composite file decrypts through the stream, armored`() =
        roundTrip(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, armor = true)

    @Test
    fun `streamed composite encrypt decrypts through the stream`() {
        val k = newKey(KeyAlgorithm.MLKEM768_X25519_V6)
        val plaintext = "file both ways".toByteArray()
        val out = ByteArrayOutputStream()
        svc.encryptStream(
            input = ByteArrayInputStream(plaintext),
            output = out,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            filename = "notes.txt",
            armor = false,
            messagePassword = null,
        )
        val (recovered, result) = decryptStreamed(out.toByteArray(), listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, recovered)
        assertEquals("notes.txt", result.filename)
    }

    @Test
    fun `v6 composite large message decrypts through the buffer too`() {
        // The first run of this file exposed a second bug: split() parsed
        // the SEIPD's length before deciding it was the body, so the
        // partial-length framing BC emits past its 4 KiB buffer read as
        // "no composite PKESK" and the buffered text path failed on any
        // large composite message. This holds the line on that.
        val k = newKey(KeyAlgorithm.MLKEM768_X25519_V6)
        val plaintext = ByteArray(200_000) { (it * 31 + (it shr 8)).toByte() }
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val result = svc.decrypt(ct, secretKeyRings = listOf(sec(k.privateKeyData)), passphrase = null)
        assertArrayEquals(plaintext, result.data)
    }

    @Test
    fun `v5 LibrePGP large message decrypts through the buffer too`() {
        val k = newKey(KeyAlgorithm.MLKEM768_X25519_LIBREPGP)
        val plaintext = ByteArray(200_000) { (it * 31 + (it shr 8)).toByte() }
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val result = svc.decrypt(ct, secretKeyRings = listOf(sec(k.privateKeyData)), passphrase = null)
        assertArrayEquals(plaintext, result.data)
    }

    @Test
    fun `classical key still streams untouched by the sniff`() {
        val k = newKey(KeyAlgorithm.ED25519_CV25519)
        val plaintext = ByteArray(150_000) { (it * 17).toByte() }
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val (recovered, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, recovered)
    }
}
