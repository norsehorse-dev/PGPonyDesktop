// EngineRoundTripTest.kt
// D1 validation: the vendored Android engine generates, exports, and re-imports keys on a plain
// JVM — v4 and v6. These are the same code paths the Android unit suites exercise; a failure here
// means the vendor set or the desktop toolchain broke, not the crypto.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EngineRoundTripTest {

    private val service = PGPCryptoService.shared

    @Test
    fun v4Ed25519RoundTrip() = roundTrip(KeyAlgorithm.ED25519_CV25519)

    @Test
    fun v6Ed25519RoundTrip() = roundTrip(KeyAlgorithm.V6_ED25519)

    private fun roundTrip(algorithm: KeyAlgorithm) {
        val gen = service.generateKeyPair(
            name = "Desktop Test",
            email = "test@pgpony.app",
            algorithm = algorithm,
            passphrase = "test-passphrase"
        )

        val pub = service.importArmoredKey(gen.armoredPublicKey)
        assertEquals(gen.fingerprint.lowercase(), pub.fingerprint.lowercase(), "public fingerprint")
        assertFalse(pub.hasPrivateKey, "public block must not carry a secret")

        val sec = service.importArmoredKey(gen.armoredPrivateKey)
        assertEquals(gen.fingerprint.lowercase(), sec.fingerprint.lowercase(), "secret fingerprint")
        assertTrue(sec.hasPrivateKey, "secret block must carry the secret")
    }
}
