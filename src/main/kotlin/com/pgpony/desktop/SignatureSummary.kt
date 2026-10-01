// SignatureSummary.kt
// PGPony Desktop 3.0.0: one reading of "what does this signature tell me" for every decrypt and
// verify surface (text, bundle, file, folder, CLI).
//
// Two Android changes meet here:
//   * 4.5.3 (#57): a valid signature from a key the user has not confirmed (trust UNKNOWN or
//     UNVERIFIED) reads "Signed, key not verified" in amber, not a flat green "Verified". Anyone
//     can publish a key for any address, so an unconfirmed signer is a weaker statement. Only a
//     VERIFIED or ULTIMATE signer reads green.
//   * 4.5.3: a composite ML-DSA signature inside an encrypted message comes back from the engine
//     as DecryptResult.compositeInline (BouncyCastle cannot parse it). It used to read as
//     unsigned on desktop; it is now verified against the stored composite keys.
//
// The signer is the certificate that holds the key the signature verified under, found by its
// primary fingerprint as the engine reports it, never by the issuer key ID the signature claims.
// A signature from a held key that the engine did not grade VERIFIED (revoked, expired, not a
// signing key, an expired signature ...) is INVALID here, with the engine's status kept so the
// screens can say why. The entry points that take a whole engine result (ofDecrypt, ofStream,
// ofCard) read all of this from it; prefer them over [of].

package com.pgpony.desktop

import com.pgpony.android.crypto.DecryptResult
import com.pgpony.android.crypto.DecryptStreamResult
import com.pgpony.android.crypto.SignerStatus
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.card.CardDecryptResult
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.TrustLevel
import org.bouncycastle.openpgp.PGPPublicKeyRing

object SignatureSummary {

    enum class State {
        NONE,
        /** Valid, and the signer key is confirmed. */
        VERIFIED,
        /** Valid, but the signer key's trust is UNKNOWN or UNVERIFIED, or its row was not found. */
        UNCONFIRMED,
        /** A signature from a key that is not in the keyring. */
        UNHELD,
        /** A signature that did not verify, or verified from a key or at a time that does not pass. */
        INVALID
    }

    data class Summary(
        val state: State,
        val signer: PGPKeyEntity? = null,
        /** 16 hex, for display: the key that verified, or the claimed one when none did. */
        val keyIdHex: String? = null,
        /** 3.0.0 (5d-3): the signer key's label ("RSA 1024", "DSA") when it is weak. */
        val weakKey: String? = null,
        /** The engine's grade behind an INVALID state, when it had one. */
        val status: SignerStatus? = null
    ) {
        val signerLabel: String? get() = signer?.userID?.ifBlank { null } ?: keyIdHex
    }

    fun isConfirmed(trust: TrustLevel?): Boolean =
        trust == TrustLevel.VERIFIED || trust == TrustLevel.ULTIMATE

    /**
     * Summarize a decrypt result's signature fields. [compositeBytes] and [compositeClaimedFp]
     * are DecryptResult.compositeInlineBytes / compositeClaimedSignerFp, set when the engine
     * handed back a composite inline signature for the caller to verify. [signerFingerprint]
     * (the primary fingerprint of the certificate that holds the verifying key) and
     * [signerStatus] (the engine's grade) identify the signer; without them the older callers
     * keep the key ID lookup.
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
        weakKey: String? = null,
        signerFingerprint: String? = null,
        signerStatus: SignerStatus? = null
    ): Summary {
        if (compositeInline && compositeBytes != null) {
            return fromVerification(repo, DesktopCompositeVerify.verifyInlineBytes(repo, compositeBytes, compositeClaimedFp))
        }
        val rawHex = signatureKeyIDRaw?.let { String.format("%016X", it) }
        if (signerStatus != null) {
            return when (signerStatus) {
                SignerStatus.VERIFIED -> verifiedSummary(repo, signerFingerprint, signerKeyID, weakKey)
                SignerStatus.NONE -> if (hasSignature) Summary(State.UNHELD, null, rawHex ?: signerKeyID) else Summary(State.NONE)
                SignerStatus.UNKNOWN_SIGNER -> Summary(State.UNHELD, null, rawHex ?: signerKeyID)
                else -> Summary(
                    State.INVALID,
                    signerFingerprint?.let { repo.byFingerprint(it) },
                    signerKeyID ?: rawHex,
                    weakKey,
                    signerStatus
                )
            }
        }
        return when {
            verified -> verifiedSummary(repo, signerFingerprint, signerKeyID, weakKey)
            hasSignature -> Summary(State.UNHELD, null, rawHex ?: signerKeyID)
            else -> Summary(State.NONE)
        }
    }

    /**
     * A verified signature's row: by [fingerprint] when the engine gave one (a row that cannot
     * be found reads unconfirmed), else the older key ID lookup.
     */
    private suspend fun verifiedSummary(
        repo: DesktopKeyRepository,
        fingerprint: String?,
        keyId: String?,
        weakKey: String?
    ): Summary {
        val signer = if (fingerprint != null) repo.byFingerprint(fingerprint) else keyId?.let { repo.findByKeyId(it) }
        val state = if (signer != null && isConfirmed(signer.trustLevel)) State.VERIFIED else State.UNCONFIRMED
        return Summary(state, signer, keyId, weakKey)
    }

    /** A software decrypt (text, bundle, armored file). */
    suspend fun ofDecrypt(repo: DesktopKeyRepository, r: DecryptResult): Summary =
        of(
            repo, r.signatureVerified, r.hasSignature, r.signerKeyID, r.signatureKeyIDRaw,
            r.compositeInline, r.compositeInlineBytes, r.compositeClaimedSignerFp,
            weakKey = r.signerWeakKey,
            signerFingerprint = r.signerPrimaryFingerprint,
            signerStatus = r.signerStatus.takeUnless { r.compositeInline && r.compositeInlineBytes != null }
        )

    /** A streaming decrypt (binary files, CLI). */
    suspend fun ofStream(repo: DesktopKeyRepository, r: DecryptStreamResult): Summary =
        of(
            repo, r.signatureVerified, r.hasSignature, r.signerKeyID, r.signatureKeyIDRaw,
            r.compositeInline, r.compositeInlineBytes, r.compositeClaimedSignerFp,
            weakKey = r.signerWeakKey,
            signerFingerprint = r.signerPrimaryFingerprint,
            signerStatus = r.signerStatus.takeUnless { r.compositeInline && r.compositeInlineBytes != null }
        )

    /**
     * A smart-card decrypt, graded by the engine like the software path. The signer is the
     * certificate the engine names as validly holding the verifying key. [rings] is kept for
     * callers; the engine already graded against the verification keys it was given.
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun ofCard(repo: DesktopKeyRepository, r: CardDecryptResult, rings: List<PGPPublicKeyRing> = emptyList()): Summary {
        if (r.signerStatus == SignerStatus.VERIFIED && r.signerPrimaryFingerprint == null) {
            // Verified, yet no certificate validly carries the key: say less, not more.
            return Summary(State.UNCONFIRMED, null, r.signerKeyID, r.signerWeakKey)
        }
        return of(
            repo, r.signatureVerified, r.hadSignature, r.signerKeyID, r.signatureKeyIDRaw,
            weakKey = r.signerWeakKey,
            signerFingerprint = r.signerPrimaryFingerprint,
            signerStatus = r.signerStatus
        )
    }

    /** Map a VerificationResult (detached, clear-signed, composite) onto the same states. */
    suspend fun fromVerification(repo: DesktopKeyRepository, r: VerificationResult): Summary = when (r) {
        is VerificationResult.Verified -> {
            val signer = repo.byFingerprint(r.signerFingerprint)
            val trust = if (signer == null) null else (r.signerTrust ?: signer.trustLevel)
            Summary(if (isConfirmed(trust)) State.VERIFIED else State.UNCONFIRMED, signer, r.signerKeyID, r.signerWeakKey)
        }
        is VerificationResult.Invalid -> Summary(
            State.INVALID,
            r.signerFingerprint?.takeIf { r.signerStatus != null }?.let { repo.byFingerprint(it) },
            r.signerKeyID,
            null,
            r.signerStatus
        )
        is VerificationResult.UnknownSigner -> Summary(State.UNHELD, null, r.signerKeyID)
        is VerificationResult.Unsigned -> Summary(State.NONE)
    }

    /** Why a signature was not accepted, in a few words, for an INVALID state's [status]. */
    fun reason(status: SignerStatus?): String = when (status) {
        SignerStatus.REVOKED_KEY -> tr("d_sig_reason_revoked")
        SignerStatus.EXPIRED_KEY -> tr("d_sig_reason_expired_key")
        SignerStatus.EXPIRED_SIGNATURE -> tr("d_sig_reason_expired_sig")
        SignerStatus.NOT_SIGNING_KEY -> tr("d_sig_reason_not_signing")
        SignerStatus.UNBOUND_SIGNER, SignerStatus.NOT_VALID_AT_TIME, SignerStatus.PREDATES_KEY ->
            tr("d_sig_reason_not_valid")
        SignerStatus.WEAK_SIGNATURE, SignerStatus.WEAK_KEY -> tr("d_sig_reason_weak")
        else -> tr("d_sig_reason_mismatch")
    }

    /** The short suffix the Files tab and file outcomes append (" · signature VERIFIED" etc). */
    fun fileNote(s: Summary): String = when (s.state) {
        State.VERIFIED -> tr("d_file_sig_verified") + (s.keyIdHex?.let { tr("d_file_sig_id_suffix", it) } ?: "")
        State.UNCONFIRMED -> tr("d_file_sig_unconfirmed") + (s.keyIdHex?.let { tr("d_file_sig_id_suffix", it) } ?: "")
        State.UNHELD -> tr("d_file_sig_unheld") + (s.keyIdHex?.let { tr("d_file_sig_id_suffix", it) } ?: "")
        State.INVALID ->
            if (s.status == null || s.status == SignerStatus.INVALID) tr("d_file_sig_invalid")
            else tr("d_file_sig_rejected", reason(s.status))
        State.NONE -> ""
    } + (s.weakKey?.let { tr("d_sig_weak_suffix", it) } ?: "")

    /**
     * 3.0.0 (5d-3): the note a result adds when a weak key (RSA under 2048 bits, DSA, ElGamal)
     * made the signature or opened the message. Both still work; the note says so.
     */
    fun weakNote(signerWeak: String?, decryptWeak: String?): String =
        (signerWeak?.let { tr("d_sig_weak_suffix", it) } ?: "") +
            (decryptWeak?.let { tr("d_decrypt_weak_suffix", it) } ?: "")

    /** How a banner reads: its colour and its text. */
    enum class Tone { GOOD, WARN, BAD, INFO }

    data class Line(val tone: Tone, val text: String)

    /**
     * The Decrypt tab's banner for [s], the same rules for a software and a card decrypt
     * ([onCard] picks the wording). [suffix] is appended (attachments, the decrypt weak-key
     * note); the signer's weak-key note comes from [s].
     */
    fun decryptLine(s: Summary, onCard: Boolean, suffix: String = ""): Line {
        val signer = s.signerLabel?.let { tr("d_crypto_banner_signer_suffix", it) } ?: ""
        val weak = s.weakKey?.let { tr("d_sig_weak_suffix", it) } ?: ""
        return when (s.state) {
            State.VERIFIED -> Line(
                Tone.GOOD,
                tr(if (onCard) "d_crypto_banner_decrypted_card_verified" else "d_crypto_banner_decrypted_verified") +
                    signer + weak + suffix
            )
            State.UNCONFIRMED -> Line(
                Tone.WARN,
                tr(if (onCard) "d_crypto_banner_decrypted_card_unconfirmed" else "d_crypto_banner_decrypted_unconfirmed") +
                    signer + weak + suffix
            )
            State.INVALID -> Line(
                Tone.BAD,
                tr(if (onCard) "d_crypto_banner_decrypted_card_rejected" else "d_crypto_banner_decrypted_rejected", reason(s.status)) +
                    suffix
            )
            State.UNHELD -> Line(
                Tone.WARN,
                tr(if (onCard) "d_crypto_banner_decrypted_card_unknown" else "d_crypto_banner_decrypted_unknown") +
                    (s.keyIdHex?.let { tr("d_crypto_banner_keyid_suffix", it) } ?: "") + suffix
            )
            State.NONE -> Line(
                Tone.INFO,
                tr(if (onCard) "d_crypto_banner_decrypted_card_unsigned" else "d_crypto_banner_decrypted_unsigned") + suffix
            )
        }
    }

    /**
     * The Verify tab's banner for [r]. The key shown is the one the signature verified under
     * (its fingerprint), never the issuer key ID the signature names.
     */
    suspend fun verifyLine(repo: DesktopKeyRepository, r: VerificationResult): Line = when (r) {
        is VerificationResult.Verified -> {
            val s = fromVerification(repo, r)
            val confirmed = s.state == State.VERIFIED
            val shown = (r.signingKeyFingerprint ?: r.signerFingerprint).uppercase().chunked(4).joinToString(" ")
            val text = tr(
                if (confirmed) "d_crypto_banner_verified" else "d_file_verify_ok_unconfirmed",
                r.signerName ?: "",
                r.signerEmail ?: "?",
                shown
            ) + weakNote(r.signerWeakKey, null)
            // 3.0.0 (5d-3): a weak signing key reads amber too.
            Line(if (confirmed && r.signerWeakKey == null) Tone.GOOD else Tone.WARN, text)
        }
        is VerificationResult.Invalid ->
            if (r.signerStatus == null || r.signerStatus == SignerStatus.INVALID) Line(Tone.BAD, tr("d_crypto_banner_invalid"))
            else Line(Tone.BAD, tr("d_crypto_banner_rejected", reason(r.signerStatus)))
        is VerificationResult.UnknownSigner -> Line(Tone.WARN, tr("d_crypto_banner_unknown_signer"))
        is VerificationResult.Unsigned -> Line(Tone.INFO, tr("d_crypto_banner_no_signature"))
    }
}
