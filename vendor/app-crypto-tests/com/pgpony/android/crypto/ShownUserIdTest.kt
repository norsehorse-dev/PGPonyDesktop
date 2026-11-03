// ShownUserIdTest.kt
// PGPony Android 4.7.0 (item 52): the identity a key shows is the live User ID
// with the newest primary flag, not the first User ID in ring order. A tester's
// key listed a revoked first User ID, and publishing refused with a repair hint
// that could not be followed.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class ShownUserIdTest {

    private val t0 = 1_760_000_000_000L
    private val first = "Old Name <old@pgpony.test>"
    private val second = "New Name <new@pgpony.test>"
    private val third = "Other Name <other@pgpony.test>"

    private fun keyPair(): BcPGPKeyPair {
        val g = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }
        return BcPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, g.generateKeyPair(), Date(t0))
    }

    private fun sign(pub: PGPPublicKey, priv: PGPPrivateKey, uid: String, type: Int, at: Long, primary: Boolean): PGPPublicKey {
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(pub.algorithm, HashAlgorithmTags.SHA256), pub)
        gen.init(type, priv)
        gen.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(false, Date(at))
            setIssuerFingerprint(false, pub)
            if (primary) setPrimaryUserID(false, true)
        }.generate())
        return PGPPublicKey.addCertification(pub, uid, gen.generateCertification(uid, pub))
    }

    private fun cert(pub: PGPPublicKey, priv: PGPPrivateKey, uid: String, at: Long, primary: Boolean = false) =
        sign(pub, priv, uid, PGPSignature.POSITIVE_CERTIFICATION, at, primary)

    private fun revoke(pub: PGPPublicKey, priv: PGPPrivateKey, uid: String, at: Long) =
        sign(pub, priv, uid, PGPSignature.CERTIFICATION_REVOCATION, at, false)

    @Test
    fun `a revoked first User ID is not shown when a later one is flagged primary`() {
        val kp = keyPair()
        var pub = cert(kp.publicKey, kp.privateKey, first, t0)
        pub = cert(pub, kp.privateKey, second, t0 + 1000, primary = true)
        pub = cert(pub, kp.privateKey, third, t0 + 2000)
        pub = revoke(pub, kp.privateKey, first, t0 + 3000)
        assertEquals(first, pub.userIDs.next())
        assertEquals(second, UserIdService.shared.shownUserId(pub))
        assertEquals(listOf(second), UserIdService.shared.primaryFlaggedLiveUserIds(pub))
    }

    @Test
    fun `with no primary flag the first live User ID is shown`() {
        val kp = keyPair()
        var pub = cert(kp.publicKey, kp.privateKey, first, t0)
        pub = cert(pub, kp.privateKey, second, t0 + 1000)
        pub = revoke(pub, kp.privateKey, first, t0 + 2000)
        assertEquals(second, UserIdService.shared.shownUserId(pub))
    }

    @Test
    fun `a revoked User ID still flagged primary is passed over`() {
        val kp = keyPair()
        var pub = cert(kp.publicKey, kp.privateKey, first, t0, primary = true)
        pub = cert(pub, kp.privateKey, second, t0 + 1000)
        pub = revoke(pub, kp.privateKey, first, t0 + 2000)
        assertEquals(second, UserIdService.shared.shownUserId(pub))
    }

    @Test
    fun `when two are flagged the newest flag wins`() {
        val kp = keyPair()
        var pub = cert(kp.publicKey, kp.privateKey, first, t0, primary = true)
        pub = cert(pub, kp.privateKey, second, t0 + 5000, primary = true)
        pub = cert(pub, kp.privateKey, third, t0 + 1000, primary = true)
        assertEquals(second, UserIdService.shared.shownUserId(pub))
    }

    @Test
    fun `a single User ID with no flag is shown`() {
        val kp = keyPair()
        val pub = cert(kp.publicKey, kp.privateKey, first, t0)
        assertEquals(first, UserIdService.shared.shownUserId(pub))
    }
}
