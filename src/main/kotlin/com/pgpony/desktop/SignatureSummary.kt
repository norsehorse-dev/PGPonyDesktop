// SignatureSummary.kt
// PGPony Desktop 3.0.0: one reading of "what does this signature tell me" for every decrypt and
// verify surface (text, bundle, file, folder, CLI).
//
// Two Android changes meet here:
//   * 4.5.3 (#57): a valid signature from a key the user has not confirmed (trust UNKNOWN or
//     UNVERIFIED) reads "Signed, key not verified" in amber, not a flat green "Verified". Anyone
//     can publish a key for any address, so an unconfirmed signer is a weaker statement. A
//     VERIFIED or ULTIMATE signer, or one that could not be resolved to a keyring row, stays green.
//   * 4.5.3: a composite ML-DSA signature inside an encrypted message comes back from the engine
//     as DecryptResult.compositeInline (BouncyCastle cannot parse it). It used to read as
//     unsigned on desktop; it is now verified against the stored composite key.

package com.pgpony.desktop

import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.TrustLevel

object SignatureSummary {

    enum class State {
        NONE,
        /** Valid, and the signer key is confirmed (or could not be resolved to a row). */
        VERIFIED,
        /** Valid, but the signer key's trust is UNKNOWN or UNVERIFIED. */
        UNCONFIRMED,
        /** A signature from a key that is not in the keyring. */
        UNHELD,
        /** A composite signature that did not verify. */
        INVALID
    }

    data class Summary(
        val state: State,
        val signer: PGPKeyEntity? = null,
        /** 16 hex, for display when the signer is not held. */
        val keyIdHex: String? = null,
        /** 3.0.0 (5d-3): the signer key's label ("RSA 1024", "DSA") when it is weak. */
        val weakKey: String? = null
    ) {
        val signerLabel: String? get() = signer?.userID?.ifBlank { null } ?: keyIdHex
    }

    fun isConfirmed(trust: TrustLevel?): Boolean =
        trust == null || trust == TrustLevel.VERIFIED || trust == TrustLevel.ULTIMATE

    /**
     * Summarize a decrypt result's signature fields. [compositeBytes] and [compositeClaimedFp]
     * are DecryptResult.compositeInlineBytes / compositeClaimedSignerFp, set when the engine
     * handed back a composite inline signature for the caller to verify.
     */
    suspend fun of(
        repo: DesktopKeyRepository,
        verified: Boolean,
        hasSignature: Boolean,
        signerKeyID: String?,
        signatureKeyIDRaw: Long?,
        compositeInline: Boolean = false,
        compositeBytes: ByteArray? = null,
        compositeClaimedFp: String? = null,
        weakKey: String? = null
    ): Summary {
        if (compositeInline && compositeBytes != null) {
            return fromVerification(repo, DesktopCompositeVerify.verifyInlineBytes(repo, compositeBytes, compositeClaimedFp))
        }
        val rawHex = signatureKeyIDRaw?.let { String.format("%016X", it) }
        return when {
            verified -> {
                val signer = signerKeyID?.let { repo.findByKeyId(it) }
                Summary(if (isConfirmed(signer?.trustLevel)) State.VERIFIED else State.UNCONFIRMED, signer, signerKeyID, weakKey)
            }
            hasSignature -> Summary(State.UNHELD, null, rawHex ?: signerKeyID)
            else -> Summary(State.NONE)
        }
    }

    /** Map a VerificationResult (detached, clear-signed, composite) onto the same states. */
    suspend fun fromVerification(repo: DesktopKeyRepository, r: VerificationResult): Summary = when (r) {
        is VerificationResult.Verified -> {
            val signer = repo.byFingerprint(r.signerFingerprint) ?: repo.findByKeyId(r.signerKeyID)
            val trust = r.signerTrust ?: signer?.trustLevel
            Summary(if (isConfirmed(trust)) State.VERIFIED else State.UNCONFIRMED, signer, r.signerKeyID, r.signerWeakKey)
        }
        is VerificationResult.Invalid -> Summary(State.INVALID, null, r.signerKeyID)
        is VerificationResult.UnknownSigner -> Summary(State.UNHELD, null, r.signerKeyID)
        is VerificationResult.Unsigned -> Summary(State.NONE)
    }

    /** The short suffix the Files tab and file outcomes append (" · signature VERIFIED" etc). */
    fun fileNote(s: Summary): String = when (s.state) {
        State.VERIFIED -> tr("d_file_sig_verified") + (s.keyIdHex?.let { tr("d_file_sig_id_suffix", it) } ?: "")
        State.UNCONFIRMED -> tr("d_file_sig_unconfirmed") + (s.keyIdHex?.let { tr("d_file_sig_id_suffix", it) } ?: "")
        State.UNHELD -> tr("d_file_sig_unheld") + (s.keyIdHex?.let { tr("d_file_sig_id_suffix", it) } ?: "")
        State.INVALID -> tr("d_file_sig_invalid")
        State.NONE -> ""
    } + (s.weakKey?.let { tr("d_sig_weak_suffix", it) } ?: "")

    /**
     * 3.0.0 (5d-3): the note a result adds when a weak key (RSA under 2048 bits, DSA, ElGamal)
     * made the signature or opened the message. Both still work; the note says so.
     */
    fun weakNote(signerWeak: String?, decryptWeak: String?): String =
        (signerWeak?.let { tr("d_sig_weak_suffix", it) } ?: "") +
            (decryptWeak?.let { tr("d_decrypt_weak_suffix", it) } ?: "")
}
