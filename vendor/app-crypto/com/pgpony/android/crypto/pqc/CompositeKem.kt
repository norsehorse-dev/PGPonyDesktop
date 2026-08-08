// CompositeKem.kt
// PGPony Android — 4.0.0 Phase 2b (post-quantum: ML-KEM-768 + X25519)
//                  4.2.0 §1.1 (generalized to ML-KEM-1024 + X448, algo 36)
//
// The KEM core for the IETF composite (draft-ietf-openpgp-pqc). BouncyCastle
// ships the primitives (ML-KEM, X25519/X448, SHA3, RFC-3394 key wrap) but
// NOT the OpenPGP composite framing, so we build it here on top of those
// primitives.
//
// Two registered code points, one combiner:
//   • algo 35 = ML-KEM-768  + X25519  (shipped 4.0.0, sq-validated)
//   • algo 36 = ML-KEM-1024 + X448    (4.2.0 §1.1)
// The construction is identical for both: only the ECDH curve, the ML-KEM
// parameter set, the byte lengths and the algorithm-id octet fed into the
// KDF differ, and all of those come from a [CompositeSuite]. This is the
// single audited combiner the 4.2.0 middle-path design keeps in one place.
//
// Composite public key = ECC pub || ML-KEM pub. Encapsulation produces an
// ECC ephemeral public + ML-KEM ciphertext, and:
//   KEK = SHA3-256( mlkemShare || ecdhShare || ephPub || recipientPub ||
//                   algId || "OpenPGPCompositeKDFv1" || 21 )
//     ecdhShare = ECDH(ephemeral_sk, recipient_pk)
// The session key is RFC-3394 AES-256 key-wrapped under the KEK (a 32-octet
// KEK for both parameter sets, since both wrap an AES-256 session key).
//
// SECURITY-CRITICAL. The 768 path is byte-locked by CompositeKemTest and
// wire-validated against Sequoia `sq`; the suite defaults to IETF_768 so
// every existing 768 caller and test exercises the exact prior behavior.
// The 1024 wire layout is validated against the published draft vectors and
// GnuPG 2.5.x interop (§1.1), which the JVM round-trip test cannot prove.

package com.pgpony.android.crypto.pqc

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.agreement.X448Agreement
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.RFC3394WrapEngine
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.crypto.params.X448PrivateKeyParameters
import org.bouncycastle.crypto.params.X448PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import java.security.SecureRandom

object CompositeKem {

    /** draft-ietf-openpgp-pqc algorithm id for ML-KEM-768 + X25519. */
    const val ALGORITHM_ID = 35

    // 768 (X25519) constants, kept as the named defaults that the algo-35
    // packet code (CompositePkesk, CompositeKeyMaterial) and CompositeKemTest
    // reference. The 1024 equivalents live on CompositeSuite / MlkemLevel.
    const val X25519_KEY_LEN = 32
    const val MLKEM768_PUB_LEN = 1184
    const val MLKEM768_CT_LEN = 1088
    const val COMPOSITE_PUB_LEN = X25519_KEY_LEN + MLKEM768_PUB_LEN // 1216

    // KDF domain separation (draft-ietf-openpgp-pqc): 21 octets.
    private val DOM_SEP = "OpenPGPCompositeKDFv1".toByteArray(Charsets.US_ASCII)

    /** Result of encapsulating to a recipient composite public key. */
    data class Encapsulation(
        /** ECC ephemeral public (32 for X25519, 56 for X448). */
        val ephemeralX25519: ByteArray,
        /** ML-KEM ciphertext (1088 for ML-KEM-768, 1568 for ML-KEM-1024). */
        val mlkemCiphertext: ByteArray,
        /** Derived key-encryption key (32) — wrap the session key with it. */
        val kek: ByteArray
    )

    /** Split a composite public key blob into (ecc, mlkem) for [suite]. */
    fun splitPublic(
        compositePub: ByteArray,
        suite: CompositeSuite = CompositeSuite.IETF_768
    ): Pair<ByteArray, ByteArray> {
        require(compositePub.size == suite.compositePubLen) {
            "composite pubkey must be ${suite.compositePubLen} bytes, got ${compositePub.size}"
        }
        val eccLen = suite.curve.keyLen
        return compositePub.copyOfRange(0, eccLen) to
            compositePub.copyOfRange(eccLen, suite.compositePubLen)
    }

    /**
     * Encapsulate to a recipient's composite public key: generate an ECC
     * ephemeral + ML-KEM ciphertext and derive the KEK. [suite] selects the
     * curve, ML-KEM parameter set and algorithm id (defaults to IETF_768).
     */
    fun encapsulate(
        recipientX25519Pub: ByteArray,
        recipientMlkemPub: ByteArray,
        random: SecureRandom = SecureRandom(),
        suite: CompositeSuite = CompositeSuite.IETF_768
    ): Encapsulation {
        // ECC ephemeral + ECDH share against the recipient.
        val (ephSec, ephPub) = genEphemeral(suite, random)
        val ecdhShare = ecdh(suite, ephSec, recipientX25519Pub)

        // ML-KEM encapsulation for the suite's parameter set.
        val mlkemPub = MLKEMPublicKeyParameters(suite.mlkem.params, recipientMlkemPub)
        val enc = MLKEMGenerator(random).generateEncapsulated(mlkemPub)

        val kek = combine(enc.secret, ecdhShare, ephPub, recipientX25519Pub, suite)
        return Encapsulation(ephPub, enc.encapsulation, kek)
    }

    /**
     * Decapsulate: recover the KEK from the ECC ephemeral + ML-KEM
     * ciphertext, using the recipient's composite secret material. The
     * ML-KEM parameter set is carried by [recipientMlkemSec]; [suite]
     * supplies the curve and algorithm id.
     */
    fun decapsulate(
        ephemeralX25519: ByteArray,
        mlkemCiphertext: ByteArray,
        recipientX25519Sec: ByteArray,
        recipientMlkemSec: MLKEMPrivateKeyParameters,
        recipientX25519Pub: ByteArray,
        suite: CompositeSuite = CompositeSuite.IETF_768
    ): ByteArray {
        val ecdhShare = ecdh(suite, recipientX25519Sec, ephemeralX25519)
        val mlkemShare = MLKEMExtractor(recipientMlkemSec).extractSecret(mlkemCiphertext)
        return combine(mlkemShare, ecdhShare, ephemeralX25519, recipientX25519Pub, suite)
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

    /** Generate an ECC ephemeral for [suite]'s curve: (secret, public). */
    private fun genEphemeral(suite: CompositeSuite, random: SecureRandom): Pair<ByteArray, ByteArray> =
        if (suite.curve == EccCurve.X448) {
            val kp = X448KeyPairGenerator()
                .apply { init(X448KeyGenerationParameters(random)) }
                .generateKeyPair()
            (kp.private as X448PrivateKeyParameters).encoded to
                (kp.public as X448PublicKeyParameters).encoded
        } else {
            val kp = X25519KeyPairGenerator()
                .apply { init(X25519KeyGenerationParameters(random)) }
                .generateKeyPair()
            (kp.private as X25519PrivateKeyParameters).encoded to
                (kp.public as X25519PublicKeyParameters).encoded
        }

    /** ECDH agreement on [suite]'s curve between a raw secret and peer public. */
    private fun ecdh(suite: CompositeSuite, secret: ByteArray, peerPub: ByteArray): ByteArray =
        if (suite.curve == EccCurve.X448) {
            val agr = X448Agreement().apply { init(X448PrivateKeyParameters(secret, 0)) }
            val out = ByteArray(agr.agreementSize)
            agr.calculateAgreement(X448PublicKeyParameters(peerPub, 0), out, 0)
            out
        } else {
            val agr = X25519Agreement().apply { init(X25519PrivateKeyParameters(secret, 0)) }
            val out = ByteArray(agr.agreementSize)
            agr.calculateAgreement(X25519PublicKeyParameters(peerPub, 0), out, 0)
            out
        }

    /**
     * KEK = SHA3-256( mlkemShare || ecdhShare || ephPub || recipientPub ||
     *                 algId || DOM_SEP || len(DOM_SEP) ).
     * Both parties feed identical inputs, so encapsulate and decapsulate
     * agree (round-trip symmetry — covered by the unit test); the exact
     * byte layout is validated for wire-correctness against Sequoia `sq`
     * (algo 35) and the published draft vectors (algo 36). [suite]'s
     * algorithm id (35 or 36) is the only octet that differs between them.
     */
    private fun combine(
        mlkemShare: ByteArray,
        ecdhShare: ByteArray,
        ephPub: ByteArray,
        recipientPub: ByteArray,
        suite: CompositeSuite
    ): ByteArray {
        val d = SHA3Digest(256)
        d.update(mlkemShare, 0, mlkemShare.size)
        d.update(ecdhShare, 0, ecdhShare.size)
        d.update(ephPub, 0, ephPub.size)            // ecdhCipherText
        d.update(recipientPub, 0, recipientPub.size) // ecdhPublicKey
        d.update(suite.ietfAlgId.toByte())
        d.update(DOM_SEP, 0, DOM_SEP.size)
        d.update(DOM_SEP.size.toByte())
        val out = ByteArray(32)
        d.doFinal(out, 0)
        return out
    }
}
