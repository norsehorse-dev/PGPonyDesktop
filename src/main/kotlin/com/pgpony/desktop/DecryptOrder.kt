// DecryptOrder.kt
// PGPony Desktop 3.0.0, stage 2 checkpoint 2c (plan 3.7 and 3.8): the two consumers of the Key
// Detail settings 2b stores.
//
// DecryptOrder is Android's fallbackOrderedKeys and decryptWithFallbackCascade (#34): the key the
// user decrypts with first, then its enabled fallbacks in their order, then every other key
// pair, unless the key is in strict mode, which stops after the fallbacks. Byte-sized decrypts
// try each ring alone in that order and finish with the whole list, so the last attempt's error
// is exactly the pre-#34 error; a stream cannot be re-read, so the streaming paths take the
// order only.
//
// SigningDefaults is Android's resolveEffectiveSigner: the signing_defaults row of the key that
// would otherwise sign can hand the signature to another software key pair, one choice for
// all-post-quantum recipients, one when any recipient is classical, one for signing without
// encrypting. A missing, revoked or card-backed pick falls back to the key itself, and a
// card-backed key keeps its own signature (the card routing is decided before this runs).

package com.pgpony.desktop

import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.SigningDefaultsEntity
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import kotlin.coroutines.cancellation.CancellationException

/** The keys one decrypt tries, already in order (DesktopKeyRepository.decryptKeys). */
class DecryptKeys(
    val keys: List<PGPKeyEntity>,
    val secretRings: List<PGPSecretKeyRing>,
    /** Raw composite and v4 algo-35 secret rings, in the same order. */
    val compositeRings: List<ByteArray>,
    /** Every public ring, for verifying a signature inside the message. */
    val verificationRings: List<PGPPublicKeyRing>
)

object DecryptOrder {

    /**
     * [selected] first, then its enabled [fallbacks] in order, then the rest of [available]
     * (skipped when [strict] and anything was found). With nothing selected the order is
     * [available] as given, the pre-3.0.0 behavior.
     */
    fun ordered(
        selected: String?,
        available: List<PGPKeyEntity>,
        fallbacks: List<String>,
        strict: Boolean
    ): List<PGPKeyEntity> {
        val byFp = available.associateBy { it.fingerprint }
        val out = mutableListOf<PGPKeyEntity>()
        fun add(k: PGPKeyEntity) {
            if (out.none { it.fingerprint == k.fingerprint }) out.add(k)
        }
        if (selected != null) {
            byFp[selected]?.let(::add)
            fallbacks.forEach { fp -> byFp[fp]?.let(::add) }
            if (strict && out.isNotEmpty()) return out
        }
        available.forEach(::add)
        return out
    }

    /**
     * Android's cascade rule (decided 8 August, #34): with more than one ring, try each alone in
     * order and move on after ANY failure; the final attempt is the whole list, and only its
     * failure propagates, so the error the user sees is the one they saw before fallbacks.
     */
    inline fun <R, T> cascade(rings: List<R>, attempt: (List<R>) -> T): T {
        if (rings.size > 1) {
            for (ring in rings) {
                try {
                    return attempt(listOf(ring))
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    // Any failure moves to the next key.
                }
            }
        }
        return attempt(rings)
    }
}

object SigningDefaults {

    /**
     * The key that actually signs when [base] would. [row] is [base]'s signing_defaults row (a row
     * for another key is ignored, so a stale async load cannot leak across a picker change).
     * [recipients] are the encryption recipients; empty with [signOnly] for a plain signature.
     */
    fun pick(
        base: PGPKeyEntity,
        row: SigningDefaultsEntity?,
        recipients: List<PGPKeyEntity>,
        signOnly: Boolean,
        keys: List<PGPKeyEntity>
    ): PGPKeyEntity {
        if (row == null || row.fingerprint != base.fingerprint || base.isCardBacked) return base
        val pickedFp = when {
            signOnly -> row.signOnlySignerFingerprint
            // isPostQuantum, not Android's isComposite: a composite ML-DSA recipient receives on
            // its ML-KEM subkey and is a post-quantum recipient too (upstream finding, D23 notes).
            recipients.isNotEmpty() && recipients.all { it.algorithm.isPostQuantum } -> row.pqcSignerFingerprint
            else -> row.classicalSignerFingerprint
        } ?: return base
        if (pickedFp == base.fingerprint) return base
        val picked = keys.firstOrNull { it.fingerprint == pickedFp } ?: return base
        return if (picked.isKeyPair && !picked.isCardBacked && !picked.isRevoked) picked else base
    }
}
