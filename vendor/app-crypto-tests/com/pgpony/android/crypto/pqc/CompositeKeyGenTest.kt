// CompositeKeyGenTest.kt
// PGPony Android — 4.0.0 Phase 2b (composite keygen)
//
// Generates composite encryption subkeys onto real PGPony-generated primary
// keys and proves each works end to end via a PGPony encrypt -> decrypt
// round-trip. Because the composite AEAD/SEIPD fails on a wrong session key,
// an exact-plaintext round-trip proves the emitted key packets are
// byte-correct: BC parsed them, computed fingerprints, bound the subkey, and
// our own encrypt/decrypt agreed on the recovered session key.
//
// The LibrePGP case additionally closes the gpg->PGPony decrypt direction
// that was previously blocked: a PGPony-generated algo-8 key IS a
// standard-form secret (unlike gpg's s-expr export), so PGPony can decrypt a
// message encrypted to it.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeKeyGenTest {

    private val svc = PGPCryptoService.shared

    private fun roundTrip(
        scheme: CompositeKeyGen.Scheme,
        primaryAlgo: KeyAlgorithm,
        expectLabel: KeyAlgorithm,
        passphrase: String? = null
    ) {
        val base = svc.generateKeyPair("PQC Test", "pqc@test.local", primaryAlgo, passphrase)
        val secRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(base.privateKeyData)),
            JcaKeyFingerprintCalculator()
        )

        val withSub = CompositeKeyGen.addCompositeSubkey(secRing, scheme, passphrase)
        val pubRing = CompositeKeyGen.publicRingOf(withSub)

        // Labeling picks up the generated composite subkey.
        assertEquals(expectLabel, svc.detectAlgorithm(pubRing.publicKey, pubRing))

        val plaintext = "composite keygen round-trip ${scheme.name}".toByteArray()
        val armored = svc.encrypt(plaintext, listOf(pubRing))
        val result = svc.decrypt(armored, listOf(withSub), passphrase = passphrase)
        assertArrayEquals("round-trip must preserve plaintext", plaintext, result.data)
    }

    @Test
    fun `IETF v6 composite subkey generates and round-trips`() {
        roundTrip(
            CompositeKeyGen.Scheme.IETF_V6,
            KeyAlgorithm.V6_ED25519,
            KeyAlgorithm.MLKEM768_X25519_V6
        )
    }

    @Test
    fun `LibrePGP v5 composite subkey generates and round-trips`() {
        // v4 EdDSA primary, matching gpg's ky768_cv25519 structure.
        roundTrip(
            CompositeKeyGen.Scheme.LIBREPGP_V5,
            KeyAlgorithm.ED25519_CV25519,
            KeyAlgorithm.MLKEM768_X25519_LIBREPGP
        )
    }

    // Full public path: generateKeyPair -> export -> re-import -> round-trip.
    private fun generateAndRoundTrip(algorithm: KeyAlgorithm, passphrase: String? = null) {
        val gen = svc.generateKeyPair("PQC UI", "pqc-ui@test.local", algorithm, passphrase = passphrase)
        val secRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(gen.privateKeyData)), JcaKeyFingerprintCalculator()
        )
        val pubRing = org.bouncycastle.openpgp.PGPPublicKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(gen.publicKeyData)), JcaKeyFingerprintCalculator()
        )
        assertEquals(algorithm, svc.detectAlgorithm(pubRing.publicKey, pubRing))
        val pt = "generateKeyPair ${algorithm.shortName}".toByteArray()
        val enc = svc.encrypt(pt, listOf(pubRing))
        assertArrayEquals(pt, svc.decrypt(enc, listOf(secRing), passphrase = passphrase).data)
    }

    @Test
    fun `generateKeyPair MLKEM768_X25519_V6 works end to end`() =
        generateAndRoundTrip(KeyAlgorithm.MLKEM768_X25519_V6)

    @Test
    fun `generateKeyPair MLKEM768_X25519_LIBREPGP works end to end`() =
        generateAndRoundTrip(KeyAlgorithm.MLKEM768_X25519_LIBREPGP)

    @Test
    fun `generateKeyPair protected MLKEM768_X25519_V6 works end to end`() =
        generateAndRoundTrip(KeyAlgorithm.MLKEM768_X25519_V6, passphrase = "pgpony-test")

    @Test
    fun `generateKeyPair protected MLKEM768_X25519_LIBREPGP works end to end`() =
        generateAndRoundTrip(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, passphrase = "pgpony-test")

    @Test
    fun `passphrase-protected IETF v6 composite key round-trips`() =
        roundTrip(
            CompositeKeyGen.Scheme.IETF_V6, KeyAlgorithm.V6_ED25519,
            KeyAlgorithm.MLKEM768_X25519_V6, passphrase = "pgpony-test"
        )

    @Test
    fun `passphrase-protected LibrePGP v5 composite key round-trips`() =
        roundTrip(
            CompositeKeyGen.Scheme.LIBREPGP_V5, KeyAlgorithm.ED25519_CV25519,
            KeyAlgorithm.MLKEM768_X25519_LIBREPGP, passphrase = "pgpony-test"
        )
}
