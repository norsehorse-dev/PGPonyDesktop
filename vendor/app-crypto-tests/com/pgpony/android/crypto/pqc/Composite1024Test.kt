// Composite1024Test.kt
// PGPony Android, 4.2.0 §1.1 (ML-KEM-1024 + X448 composite)
//
// End-to-end coverage for the 1024 parameter set added in 4.2.0. These run
// against real BouncyCastle on the JVM test classpath, so they prove the
// whole PGPony pipeline is self-consistent at 1024: keygen emits a subkey
// the parsers read back, encrypt wraps a session key the decrypt path
// recovers, and detectAlgorithm labels the key by its code point and curve.
//
// Same strong-proof property as the 768 tests: the SEIPD is AEAD or MDC
// checked, so a wrong session key fails the read rather than yielding wrong
// bytes quietly. Wire-format correctness against GnuPG 2.5.x's ky1024_cv448
// and the published draft vectors is the device/interop step (§1.1) that a
// JVM round-trip cannot prove.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

class Composite1024Test {

    private val svc = PGPCryptoService.shared
    private val rnd = SecureRandom()

    private fun pub(data: ByteArray) =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun sec(data: ByteArray) =
        PGPSecretKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun genX448(): Pair<ByteArray, ByteArray> {
        val kp = X448KeyPairGenerator()
            .apply { init(X448KeyGenerationParameters(rnd)) }.generateKeyPair()
        return (kp.public as X448PublicKeyParameters).encoded to
            (kp.private as X448PrivateKeyParameters).encoded
    }

    private fun genMlkem1024(): Pair<ByteArray, MLKEMPrivateKeyParameters> {
        val kp = MLKEMKeyPairGenerator()
            .apply { init(MLKEMKeyGenerationParameters(rnd, MLKEMParameters.ml_kem_1024)) }
            .generateKeyPair()
        return (kp.public as MLKEMPublicKeyParameters).encoded to (kp.private as MLKEMPrivateKeyParameters)
    }

    // ── KEM cores at 1024 ────────────────────────────────────────────

    @Test fun `IETF 1024 encapsulate and decapsulate derive the same KEK`() {
        val (xPub, xSec) = genX448()
        val (mPub, mSec) = genMlkem1024()

        val enc = CompositeKem.encapsulate(xPub, mPub, rnd, CompositeSuite.IETF_1024)
        val kek2 = CompositeKem.decapsulate(
            enc.ephemeralX25519, enc.mlkemCiphertext, xSec, mSec, xPub, CompositeSuite.IETF_1024
        )

        assertArrayEquals("KEK must match across encapsulate/decapsulate", enc.kek, kek2)
        assertEquals(32, enc.kek.size)
        assertEquals("X448 ephemeral is 56 octets", 56, enc.ephemeralX25519.size)
        assertEquals("ML-KEM-1024 ciphertext is 1568 octets", 1568, enc.mlkemCiphertext.size)
        assertEquals("ML-KEM-1024 public is 1568 octets", 1568, mPub.size)
    }

    @Test fun `LibrePGP 1024 encapsulate and decapsulate derive the same KEK`() {
        val (xPub, xSec) = genX448()
        val (mPub, mSec) = genMlkem1024()
        // fixedInfo = symAlgo(1) || a stand-in 32-octet v5 fingerprint; the
        // KEM only requires both sides feed the same bytes.
        val fixedInfo = CompositeKemLibrePGP.fixedInfo(9, ByteArray(32) { it.toByte() })

        val enc = CompositeKemLibrePGP.encapsulate(xPub, mPub, fixedInfo, rnd, CompositeSuite.LIBREPGP_1024)
        val kek2 = CompositeKemLibrePGP.decapsulate(
            enc.eccEphemeral, enc.kyberCiphertext, xSec, xPub, mSec, fixedInfo, CompositeSuite.LIBREPGP_1024
        )

        assertArrayEquals("KEK must match across encapsulate/decapsulate", enc.kek, kek2)
        assertEquals(32, enc.kek.size)
        assertEquals("X448 ephemeral is 56 octets", 56, enc.eccEphemeral.size)
        assertEquals("Kyber-1024 ciphertext is 1568 octets", 1568, enc.kyberCiphertext.size)
    }

    // ── full pipeline: generate, encrypt, decrypt at 1024 ────────────

    private fun roundTrip(algo: KeyAlgorithm, armor: Boolean) {
        val k = svc.generateKeyPair("PQC 1024", "pqc1024@pgpony.app", algo, null, null)
        // Non-repeating and larger than one 64 KiB chunk.
        val plaintext = ByteArray(200_000) { (it * 31 + (it shr 8)).toByte() }

        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = armor
        )
        // Buffered decrypt.
        val buffered = svc.decrypt(ct, secretKeyRings = listOf(sec(k.privateKeyData)), passphrase = null)
        assertArrayEquals("buffered decrypt round-trips", plaintext, buffered.data)

        // Streamed decrypt (the path #33 fixed; exercise it at 1024 too).
        val out = ByteArrayOutputStream()
        svc.decryptStream(
            input = ByteArrayInputStream(ct),
            output = out,
            secretKeyRings = listOf(sec(k.privateKeyData)),
            passphrase = null
        )
        assertArrayEquals("streamed decrypt round-trips", plaintext, out.toByteArray())
    }

    @Test fun `v6 IETF 1024 file round-trips, binary`() =
        roundTrip(KeyAlgorithm.MLKEM1024_X448_V6, armor = false)

    @Test fun `v6 IETF 1024 file round-trips, armored`() =
        roundTrip(KeyAlgorithm.MLKEM1024_X448_V6, armor = true)

    @Test fun `v5 LibrePGP 1024 file round-trips, binary`() =
        roundTrip(KeyAlgorithm.MLKEM1024_X448_LIBREPGP, armor = false)

    @Test fun `v5 LibrePGP 1024 file round-trips, armored`() =
        roundTrip(KeyAlgorithm.MLKEM1024_X448_LIBREPGP, armor = true)

    // ── keygen labeling and material ─────────────────────────────────

    @Test fun `generated v6 1024 key is labeled and carries an algo-36 subkey`() {
        val k = svc.generateKeyPair("PQC v6", "v6@pgpony.app", KeyAlgorithm.MLKEM1024_X448_V6, null, null)
        val ring = pub(k.publicKeyData)
        assertEquals(
            KeyAlgorithm.MLKEM1024_X448_V6,
            svc.detectAlgorithm(ring.publicKey, ring)
        )
        val sub = ring.publicKeys.asSequence().firstOrNull { it.algorithm == 36 }
        assertNotNull("v6 1024 key must carry an algo-36 encryption subkey", sub)
        // The composite public material must be X448(56) + ML-KEM-1024(1568).
        val (x, m) = CompositeKeyMaterial.publicMaterial(sub!!)!!
        assertEquals(56, x.size)
        assertEquals(1568, m.size)
    }

    @Test fun `generated v5 1024 key is labeled and reads as the X448 suite`() {
        val k = svc.generateKeyPair("PQC v5", "v5@pgpony.app", KeyAlgorithm.MLKEM1024_X448_LIBREPGP, null, null)
        val ring = pub(k.publicKeyData)
        assertEquals(
            KeyAlgorithm.MLKEM1024_X448_LIBREPGP,
            svc.detectAlgorithm(ring.publicKey, ring)
        )
        val sub = ring.publicKeys.asSequence().first { it.algorithm == 8 && it.version == 5 }
        assertEquals(CompositeSuite.LIBREPGP_1024, CompositeLibrePGPKeyMaterial.suiteOf(sub.encoded))
    }

    // ── regression: the 768 label is unchanged by the 1024 additions ──

    @Test fun `generated 768 keys still label as 768`() {
        val v6 = svc.generateKeyPair("PQC 768 v6", "a@pgpony.app", KeyAlgorithm.MLKEM768_X25519_V6, null, null)
        val v6ring = pub(v6.publicKeyData)
        assertEquals(KeyAlgorithm.MLKEM768_X25519_V6, svc.detectAlgorithm(v6ring.publicKey, v6ring))

        val v5 = svc.generateKeyPair("PQC 768 v5", "b@pgpony.app", KeyAlgorithm.MLKEM768_X25519_LIBREPGP, null, null)
        val v5ring = pub(v5.publicKeyData)
        assertEquals(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, svc.detectAlgorithm(v5ring.publicKey, v5ring))
    }

    @Test fun `the two IETF code points map to distinct suites`() {
        assertTrue(CompositeSuite.ietfFor(35) == CompositeSuite.IETF_768)
        assertTrue(CompositeSuite.ietfFor(36) == CompositeSuite.IETF_1024)
        assertTrue(CompositeSuite.ietfFor(8) == null)
    }
}
