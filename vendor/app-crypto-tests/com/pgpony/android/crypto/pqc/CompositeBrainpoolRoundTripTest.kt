// CompositeBrainpoolRoundTripTest.kt
// PGPony Android - issue #2 (brainpoolP384r1 composite, full message round-trip)
//
// Inline end-to-end check: generate an Ed25519 key with a brainpoolP384r1
// ML-KEM-1024 composite subkey, encrypt a message to it through the real
// encrypt path, and decrypt it back through the real decrypt path. This
// exercises keygen, publicMaterial, encapsulate, the v3 PKESK encode/decode,
// extractFromPacket, and decapsulate as one chain. It is self-consistent
// verification only; a wrong-but-symmetric construction would still pass, so
// the gpg 2.5 round-trip stays the interop acceptance gate.

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

class CompositeBrainpoolRoundTripTest {

    private val svc = PGPCryptoService.shared

    @Test
    fun `brainpoolP384r1 composite full message round-trips through encrypt and decrypt`() {
        val base = svc.generateKeyPair(
            "BP Round", "bp-round@test.local", KeyAlgorithm.ED25519_CV25519, passphrase = null
        )
        val baseRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(base.privateKeyData)),
            JcaKeyFingerprintCalculator()
        )
        val ring = CompositeKeyGen.addCompositeSubkey(
            baseRing, CompositeSuite.LIBREPGP_1024_BP384, passphrase = null
        )

        val sub = ring.publicKeys.asSequence().first { it.algorithm == 8 && it.version == 5 }
        assertEquals(
            EccCurve.BRAINPOOL_P384R1,
            CompositeLibrePGPKeyMaterial.suiteOf(sub.encoded).curve
        )

        val pubRing = CompositeKeyGen.publicRingOf(ring)
        val pt = "brainpool composite round-trip".toByteArray()
        val enc = svc.encrypt(pt, listOf(pubRing))
        val dec = svc.decrypt(enc, listOf(ring), passphrase = null)
        assertArrayEquals(pt, dec.data)
    }
}
