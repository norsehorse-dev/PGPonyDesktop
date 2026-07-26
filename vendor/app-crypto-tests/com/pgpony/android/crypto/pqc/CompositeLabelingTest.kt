// CompositeLabelingTest.kt
// PGPony Android — 4.0.0 Phase 2b (leftovers)
//
// Locks the key-list labeling for both post-quantum composites against the
// real fixtures: an IETF (algo 35, v6) key labels as ML-KEM v6, a LibrePGP
// (algo 8, v5, GnuPG 2.5.x) key labels as ML-KEM LibrePGP — and neither
// mislabels the other or a classic key.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeLabelingTest {

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    private fun pubRing(bytes: ByteArray): PGPPublicKeyRing =
        PGPPublicKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)), JcaKeyFingerprintCalculator())

    private fun secToPub(bytes: ByteArray): PGPPublicKeyRing {
        val sec = PGPSecretKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)), JcaKeyFingerprintCalculator())
        return PGPPublicKeyRing(sec.publicKeys.asSequence().toList())
    }

    @Test
    fun `LibrePGP algo-8 key labels as ML-KEM LibrePGP`() {
        val pub = res("librepgp-clean-pub.asc")
        assumeTrue("pqc/librepgp-clean-pub.asc absent", pub != null)
        val ring = pubRing(pub!!)
        assertEquals(
            KeyAlgorithm.MLKEM768_X25519_LIBREPGP,
            PGPCryptoService.shared.detectAlgorithm(ring.publicKey, ring)
        )
    }

    @Test
    fun `IETF algo-35 key labels as ML-KEM v6`() {
        val sk = res("rfc9580-pqc-sample-key.asc")
        assumeTrue("pqc/rfc9580-pqc-sample-key.asc absent", sk != null)
        val ring = secToPub(sk!!)
        assertEquals(
            KeyAlgorithm.MLKEM768_X25519_V6,
            PGPCryptoService.shared.detectAlgorithm(ring.publicKey, ring)
        )
    }

    @Test
    fun `enum mapping for v5 algo 8 resolves`() {
        assertEquals(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, KeyAlgorithm.from(8, 5))
        assertEquals(KeyAlgorithm.MLKEM768_X25519_V6, KeyAlgorithm.from(35, 6))
        // algo 8 is only the composite in v5 framing — not v4/v6
        assertEquals(null, KeyAlgorithm.from(8, 4))
    }
}
