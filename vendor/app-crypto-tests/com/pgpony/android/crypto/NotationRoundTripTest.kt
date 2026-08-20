// NotationRoundTripTest.kt
// PGPony Android — 4.3.0 §5.6.7 (editable key notations)
//
// Proves UserIdService.setNotations writes a human-readable notation into the
// primary UID self-cert and readNotations reads it back, and that removing it
// (empty set) clears it — across v4, v6, and both composite forms. The self-
// cert is signed by the (classical) primary, so the composite cases exercise
// the same reassemble path the #29 identities feature ships on.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream

class NotationRoundTripTest {

    private val svc = PGPCryptoService.shared
    private val uid = UserIdService.shared

    private fun rings(algo: KeyAlgorithm, passphrase: String?): Pair<PGPPublicKeyRing, PGPSecretKeyRing> {
        val gen = svc.generateKeyPair("Notation Test", "notation@test.local", algo, passphrase)
        val sec = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(gen.privateKeyData)), JcaKeyFingerprintCalculator()
        )
        val pub = PGPPublicKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(gen.publicKeyData)), JcaKeyFingerprintCalculator()
        )
        return pub to sec
    }

    private fun roundTrip(algo: KeyAlgorithm, passphrase: String?) {
        val (pub, sec) = rings(algo, passphrase)
        val n = UserIdService.Notation("proof@ariadne.id", "https://github.com/example")

        val added = uid.setNotations(sec, pub, listOf(n), passphrase)
        val read = uid.readNotations(added.publicRing.publicKey)
        assertEquals("one notation after add (${algo.shortName})", 1, read.size)
        assertEquals(n.name, read[0].name)
        assertEquals(n.value, read[0].value)

        val removed = uid.setNotations(added.secretRing, added.publicRing, emptyList(), passphrase)
        assertEquals("no notations after remove (${algo.shortName})", 0, uid.readNotations(removed.publicRing.publicKey).size)
    }

    @Test fun `v4 notations round-trip`() = roundTrip(KeyAlgorithm.ED25519_CV25519, "pw")
    @Test fun `v6 notations round-trip`() = roundTrip(KeyAlgorithm.V6_ED25519, "pw")
    @Test fun `composite 768 v6 notations round-trip`() = roundTrip(KeyAlgorithm.MLKEM768_X25519_V6, "pw")
    @Test fun `composite 768 LibrePGP notations round-trip`() = roundTrip(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, "pw")
    @Test fun `composite 1024 v6 notations round-trip`() = roundTrip(KeyAlgorithm.MLKEM1024_X448_V6, "pw")
    @Test fun `unprotected v4 notations round-trip`() = roundTrip(KeyAlgorithm.ED25519_CV25519, null)
}
