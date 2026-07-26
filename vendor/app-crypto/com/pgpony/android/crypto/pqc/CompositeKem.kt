// CompositeKem.kt
// PGPony Android — 4.0.0 Phase 2b (post-quantum: ML-KEM-768 + X25519)
//
// The KEM core for the IETF composite (draft-ietf-openpgp-pqc, algorithm
// 35). BouncyCastle ships the primitives (ML-KEM, X25519, SHA3, RFC-3394
// key wrap) but NOT the OpenPGP composite framing, so we build it here on
// top of those primitives.
//
// Composite (algorithm 35 = ML-KEM-768 + X25519):
//   • public key  = X25519 pub (32) || ML-KEM-768 pub (1184)
//   • encapsulation produces: ephemeral X25519 pub (32) + ML-KEM ct (1088)
//   • KEK = SHA3-256( mlkemShare || ecdhShare || ephPub || recipientPub ||
//                     algId || "OpenPGPCompositeKDFv1" || 21 )
//     ecdhShare = X25519(ephemeral_sk, recipient_pk)
//   • session key is RFC-3394 AES-256 key-wrapped under the KEK.
//
// SECURITY-CRITICAL and interop-validated with Sequoia `sq` (this module
// alone can't prove wire-correctness — only round-trip symmetry, which the
// unit test covers; the combiner byte layout is proven by `sq` interop).

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.RFC3394WrapEngine
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom

object CompositeKem {

    /** draft-ietf-openpgp-pqc algorithm id for ML-KEM-768 + X25519. */
    const val ALGORITHM_ID = 35

    const val X25519_KEY_LEN = 32
    const val MLKEM768_PUB_LEN = 1184
    const val MLKEM768_CT_LEN = 1088
    const val COMPOSITE_PUB_LEN = X25519_KEY_LEN + MLKEM768_PUB_LEN // 1216

    // KDF domain separation (draft-ietf-openpgp-pqc): 21 octets.
    private val DOM_SEP = "OpenPGPCompositeKDFv1".toByteArray(Charsets.US_ASCII)

    /** Result of encapsulating to a recipient composite public key. */
    data class Encapsulation(
        /** Ephemeral X25519 public key (32). */
        val ephemeralX25519: ByteArray,
        /** ML-KEM-768 ciphertext (1088). */
        val mlkemCiphertext: ByteArray,
        /** Derived key-encryption key (32) — wrap the session key with it. */
        val kek: ByteArray
    )

    /** Split a composite public key blob into (x25519, mlkem). */
    fun splitPublic(compositePub: ByteArray): Pair<ByteArray, ByteArray> {
        require(compositePub.size == COMPOSITE_PUB_LEN) {
            "composite pubkey must be $COMPOSITE_PUB_LEN bytes, got ${compositePub.size}"
        }
        return compositePub.copyOfRange(0, X25519_KEY_LEN) to
            compositePub.copyOfRange(X25519_KEY_LEN, COMPOSITE_PUB_LEN)
    }

    /**
     * Encapsulate to a recipient's composite public key: generate an X25519
     * ephemeral + ML-KEM ciphertext and derive the KEK.
     */
    fun encapsulate(
        recipientX25519Pub: ByteArray,
        recipientMlkemPub: ByteArray,
        random: SecureRandom = SecureRandom()
    ): Encapsulation {
        // X25519 ephemeral + ECDH share against the recipient.
        val gen = X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(random)) }
        val kp = gen.generateKeyPair()
        val ephSk = kp.private as X25519PrivateKeyParameters
        val ephPub = (kp.public as X25519PublicKeyParameters).encoded
        val ecdhShare = x25519(ephSk, recipientX25519Pub)

        // ML-KEM encapsulation.
        val mlkemPub = MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, recipientMlkemPub)
        val enc = MLKEMGenerator(random).generateEncapsulated(mlkemPub)

        val kek = combine(enc.secret, ecdhShare, ephPub, recipientX25519Pub)
        return Encapsulation(ephPub, enc.encapsulation, kek)
    }

    /**
     * Decapsulate: recover the KEK from the ephemeral X25519 pub + ML-KEM
     * ciphertext, using the recipient's composite secret material.
     */
    fun decapsulate(
        ephemeralX25519: ByteArray,
        mlkemCiphertext: ByteArray,
        recipientX25519Sec: ByteArray,
        recipientMlkemSec: MLKEMPrivateKeyParameters,
        recipientX25519Pub: ByteArray
    ): ByteArray {
        val ecdhShare = x25519(X25519PrivateKeyParameters(recipientX25519Sec, 0), ephemeralX25519)
        val mlkemShare = MLKEMExtractor(recipientMlkemSec).extractSecret(mlkemCiphertext)
        return combine(mlkemShare, ecdhShare, ephemeralX25519, recipientX25519Pub)
    }

    /** RFC-3394 AES-256 key wrap the session key under [kek]. */
    fun wrapSessionKey(kek: ByteArray, sessionKey: ByteArray): ByteArray =
        RFC3394WrapEngine(AESEngine.newInstance()).run {
            init(true, KeyParameter(kek))
            wrap(sessionKey, 0, sessionKey.size)
        }

    /** RFC-3394 AES-256 key unwrap the session key under [kek]. */
    fun unwrapSessionKey(kek: ByteArray, wrapped: ByteArray): ByteArray =
        RFC3394WrapEngine(AESEngine.newInstance()).run {
            init(false, KeyParameter(kek))
            unwrap(wrapped, 0, wrapped.size)
        }

    // ── internals ────────────────────────────────────────────────────

    private fun x25519(sk: X25519PrivateKeyParameters, peerPub: ByteArray): ByteArray {
        val agr = X25519Agreement().apply { init(sk) }
        val out = ByteArray(agr.agreementSize)
        agr.calculateAgreement(X25519PublicKeyParameters(peerPub, 0), out, 0)
        return out
    }

    /**
     * KEK = SHA3-256( mlkemShare || ecdhShare || ephPub || recipientPub ||
     *                 algId || DOM_SEP || len(DOM_SEP) ).
     * Both parties feed identical inputs, so encapsulate and decapsulate
     * agree (round-trip symmetry — covered by the unit test); the exact
     * byte layout is validated for wire-correctness against Sequoia `sq`.
     */
    private fun combine(
        mlkemShare: ByteArray,
        ecdhShare: ByteArray,
        ephPub: ByteArray,
        recipientPub: ByteArray
    ): ByteArray {
        val d = SHA3Digest(256)
        d.update(mlkemShare, 0, mlkemShare.size)
        d.update(ecdhShare, 0, ecdhShare.size)
        d.update(ephPub, 0, ephPub.size)            // ecdhCipherText
        d.update(recipientPub, 0, recipientPub.size) // ecdhPublicKey
        d.update(ALGORITHM_ID.toByte())
        d.update(DOM_SEP, 0, DOM_SEP.size)
        d.update(DOM_SEP.size.toByte())
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out
    }
}
