// CompositeBrainpoolKemTest.kt
// PGPony Android - issue #2 (brainpoolP384r1 composite KEM)
//
// Self-consistency lock for the Weierstrass composite KEM: it proves the
// brainpoolP384r1 ECDH + uncompressed-point + SHA3-512 KDF path is internally
// symmetric, i.e. encapsulate and decapsulate derive the same KEK. It does NOT
// prove interop with gpg; a wrong-but-symmetric construction would still pass
// here. The gpg 2.5 round-trip (decrypt a real gpg message to this curve)
// remains the acceptance gate before the KEM is trusted for release.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom

class CompositeBrainpoolKemTest {

    private fun fixed(v: BigInteger, len: Int): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == len -> b
            b.size == len + 1 && b[0].toInt() == 0 -> b.copyOfRange(1, b.size)
            b.size < len -> ByteArray(len - b.size) + b
            else -> b.copyOfRange(b.size - len, b.size)
        }
    }

    @Test
    fun `brainpoolP384r1 composite KEM encapsulate and decapsulate agree`() {
        val rnd = SecureRandom()
        val suite = CompositeSuite.LIBREPGP_1024_BP384
        assertEquals(EccCurve.BRAINPOOL_P384R1, suite.curve)
        assertEquals(512, suite.curve.kdfHashBits)

        val x9 = TeleTrusTNamedCurves.getByName("brainpoolP384r1")
        val dom = ECDomainParameters(x9.curve, x9.g, x9.n, x9.h)
        val ecKp = ECKeyPairGenerator().apply {
            init(ECKeyGenerationParameters(dom, rnd))
        }.generateKeyPair()
        val eccSec = fixed((ecKp.private as ECPrivateKeyParameters).d, suite.curve.keyLen)
        val eccPub = (ecKp.public as ECPublicKeyParameters).q.getEncoded(false)
        assertEquals("uncompressed bp384 point is 97 octets", suite.curve.pointLen, eccPub.size)

        val mKp = MLKEMKeyPairGenerator().apply {
            init(MLKEMKeyGenerationParameters(rnd, suite.mlkem.params))
        }.generateKeyPair()
        val kyberPub = (mKp.public as MLKEMPublicKeyParameters).encoded
        val kyberSec = mKp.private as MLKEMPrivateKeyParameters

        val fixedInfo = CompositeKemLibrePGP.fixedInfo(9, ByteArray(32))
        val enc = CompositeKemLibrePGP.encapsulate(eccPub, kyberPub, fixedInfo, rnd, suite)
        val kek = CompositeKemLibrePGP.decapsulate(
            enc.eccEphemeral, enc.kyberCiphertext, eccSec, eccPub, kyberSec, fixedInfo, suite
        )
        assertArrayEquals("encapsulate and decapsulate must derive the same KEK", enc.kek, kek)
    }
}
