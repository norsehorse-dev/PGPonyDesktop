// CompositeKemTest.kt
// PGPony Android — 4.0.0 Phase 2b
//
// Round-trip / symmetry tests for the ML-KEM-768+X25519 KEM core. These
// run against real BouncyCastle on the JVM test classpath and prove the
// encapsulate and decapsulate sides derive the SAME KEK, and that the
// RFC-3394 session-key wrap round-trips. Wire-format correctness (the
// exact combiner byte layout matching the draft) is validated separately
// against Sequoia `sq`.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.security.SecureRandom

class CompositeKemTest {

    private val rnd = SecureRandom()

    private fun genX25519(): Pair<ByteArray, X25519PrivateKeyParameters> {
        val g = X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(rnd)) }
        val kp = g.generateKeyPair()
        return (kp.public as X25519PublicKeyParameters).encoded to (kp.private as X25519PrivateKeyParameters)
    }

    private fun genMlkem(): Pair<ByteArray, MLKEMPrivateKeyParameters> {
        val g = MLKEMKeyPairGenerator().apply {
            init(MLKEMKeyGenerationParameters(rnd, MLKEMParameters.ml_kem_768))
        }
        val kp = g.generateKeyPair()
        return (kp.public as MLKEMPublicKeyParameters).encoded to (kp.private as MLKEMPrivateKeyParameters)
    }

    @Test fun encapsulate_and_decapsulate_derive_the_same_kek() {
        val (xPub, xSec) = genX25519()
        val (mPub, mSec) = genMlkem()

        val enc = CompositeKem.encapsulate(xPub, mPub, rnd)
        val kek2 = CompositeKem.decapsulate(
            enc.ephemeralX25519, enc.mlkemCiphertext, xSec.encoded, mSec, xPub
        )

        assertArrayEquals("KEK must match across encapsulate/decapsulate", enc.kek, kek2)
        assertEquals(32, enc.kek.size)
        assertEquals(CompositeKem.X25519_KEY_LEN, enc.ephemeralX25519.size)
        assertEquals(CompositeKem.MLKEM768_CT_LEN, enc.mlkemCiphertext.size)
        assertEquals(CompositeKem.MLKEM768_PUB_LEN, mPub.size)
    }

    @Test fun session_key_wrap_round_trips() {
        val kek = ByteArray(32).also { rnd.nextBytes(it) }
        val sessionKey = ByteArray(32).also { rnd.nextBytes(it) } // AES-256
        val wrapped = CompositeKem.wrapSessionKey(kek, sessionKey)
        assertArrayEquals(sessionKey, CompositeKem.unwrapSessionKey(kek, wrapped))
    }

    @Test fun split_public_recovers_components() {
        val (xPub, _) = genX25519()
        val (mPub, _) = genMlkem()
        val (x, m) = CompositeKem.splitPublic(xPub + mPub)
        assertArrayEquals(xPub, x)
        assertArrayEquals(mPub, m)
    }

    @Test fun wrong_key_derives_different_kek() {
        val (xPub, _) = genX25519()
        val (mPub, _) = genMlkem()
        val (_, xSecWrong) = genX25519()
        val (_, mSecWrong) = genMlkem()

        val enc = CompositeKem.encapsulate(xPub, mPub, rnd)
        val kekWrong = CompositeKem.decapsulate(
            enc.ephemeralX25519, enc.mlkemCiphertext, xSecWrong.encoded, mSecWrong, xPub
        )
        // Astronomically unlikely to collide; a match would mean the KEM
        // isn't actually binding to the key material.
        org.junit.Assert.assertFalse(enc.kek.contentEquals(kekWrong))
    }
}
