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

    @Test
    fun `ECDSA primary (algo 19) labels as ECDSA, not RSA`() {
        // issue #2: gpg 2.5.x LibrePGP PQC keys carry an ECDSA primary. Before
        // this fix it fell through detectAlgorithm's catch-all and mislabeled as
        // RSA 4096. Lock both the v4 and v6 mappings.
        assertEquals(KeyAlgorithm.ECDSA, KeyAlgorithm.from(19, 4))
        assertEquals(KeyAlgorithm.ECDSA, KeyAlgorithm.from(19, 6))
    }

    @Test
    fun `brainpoolP384r1 composite (algo 8) imports and labels as ML-KEM-1024 bp384`() {
        // issue #2, symptom A: homehsu's gpg 2.5.21 key (ECDSA/brainpoolP384r1
        // primary + ML-KEM-1024/brainpoolP384r1 algo-8 subkey). Before the fix,
        // the unknown curve OID made suiteOf throw inside detectAlgorithm and the
        // whole import failed. It must now import and label by the curve OID.
        val pub = res("gpg-bp384-ecdsa-pub.asc")
        assumeTrue("pqc/gpg-bp384-ecdsa-pub.asc absent", pub != null)
        val ring = pubRing(pub!!)
        assertEquals(
            KeyAlgorithm.MLKEM1024_BP384_LIBREPGP,
            PGPCryptoService.shared.detectAlgorithm(ring.publicKey, ring)
        )
    }

    @Test
    fun `brainpool composite public material parses as uncompressed point plus ML-KEM-1024`() {
        val pub = res("gpg-bp384-ecdsa-pub.asc")
        assumeTrue("pqc/gpg-bp384-ecdsa-pub.asc absent", pub != null)
        val sub = pubRing(pub!!).publicKeys.asSequence().first { it.algorithm == 8 && it.version == 5 }
        val (ecc, kyber) = CompositeLibrePGPKeyMaterial.publicMaterial(sub.encoded)
        assertEquals("uncompressed bp384 point is 0x04 || X(48) || Y(48)", 97, ecc.size)
        assertEquals(0x04, ecc[0].toInt() and 0xFF)
        assertEquals("ML-KEM-1024 public key is 1568 octets", 1568, kyber.size)
    }
}
