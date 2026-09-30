// EncryptOps.kt
// PGPony Desktop 3.0.0: the one place every desktop encrypt path decides what it encrypts to
// and how it signs. Before 3.0.0 each site (text, bundle, file, folder, CLI) loaded recipients
// and the signer on its own; that is how a composite ML-DSA signer ended up refused on some
// paths and a v4 algo-35 recipient silently lost its post-quantum subkey on others.
//
// A Plan is built once per operation:
//   * recipients through DesktopKeyRepository.requireRecipients: BouncyCastle rings, the v4
//     algo-35 channel, and a hard stop naming any selected key that cannot be encrypted to
//     (Android 4.6.1, #67);
//   * the expired-key rule (KeyUsePolicy, Android 4.5.3);
//   * the signer: a classical secret ring, or a composite ML-DSA key's unlocked secret, which
//     the engine signs through CompositeDocumentSigner (Android 4.5.2 / 4.5.3);
//   * the Android 4.6.0 item 14 question: a composite signature inside a SEIPDv1 container
//     (any v4-only recipient) reads in PGPony but not in GnuPG or Thunderbird, so the caller
//     must decide. The GUI asks (Sign anyway / Send unsigned / Cancel); the CLI signs and
//     warns on stderr.

package com.pgpony.desktop

import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.data.PGPKeyEntity
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.io.InputStream
import java.io.OutputStream

/** A composite ML-DSA signature would go into a SEIPDv1 container; the caller must choose. */
class CompositeV4SignDecisionNeeded : Exception("composite signature to a v4-only recipient needs a decision")

class EncryptOps(private val repo: DesktopKeyRepository) {

    private val crypto = PGPCryptoService.shared

    class Plan(
        val recipients: DesktopKeyRepository.LoadedRecipients,
        val classicalSigner: PGPSecretKeyRing?,
        val compositeSigner: CompositeKeyFacade.Info?,
        /** True when a composite signature goes into a SEIPDv1 container (a v4-only recipient). */
        val compositeInSeipdV1: Boolean,
        /** False when the user chose "Send unsigned" for that case. */
        val keepCompositeInSeipdV1: Boolean,
        /** 3.0.0 (Android 4.5.0 item 13): chosen encryption subkey per recipient, keyed by the
         *  uppercase fingerprint; a recipient left out gets the engine's automatic pick. */
        val subkeyChoices: Map<String, Long> = emptyMap()
    ) {
        val signs: Boolean get() = classicalSigner != null || (compositeSigner != null && (!compositeInSeipdV1 || keepCompositeInSeipdV1))
        val needsBuffering: Boolean get() = compositeSigner != null
    }

    /**
     * Build the plan. [compositeInV1Decision] is the answer to the item 14 question: null means
     * "not asked yet", and throws [CompositeV4SignDecisionNeeded] when the question applies.
     * A signer that cannot be loaded or unlocked stops the whole operation (the Phase A3 rule:
     * a requested signature never silently drops).
     */
    suspend fun plan(
        recipientFingerprints: Collection<String>,
        signer: PGPKeyEntity?,
        signerPassphrase: String?,
        compositeInV1Decision: Boolean? = null,
        subkeyChoices: Map<String, Long> = emptyMap()
    ): Plan {
        val entities = recipientFingerprints.mapNotNull { repo.byFingerprint(it) }
        KeyUsePolicy.requireUsable(entities, signer)
        val recipients = repo.requireRecipients(recipientFingerprints)

        var classical: PGPSecretKeyRing? = null
        var composite: CompositeKeyFacade.Info? = null
        if (signer != null) {
            if (signer.algorithm.isCompositeSign) {
                composite = repo.loadCompositeKeyInfo(signer.fingerprint, signerPassphrase?.toCharArray())
                    ?.takeIf { it.compositeSecret != null }
                    ?: error(tr("d_crypto_err_signer_load", signer.shortFingerprint))
            } else {
                classical = repo.loadSecretKeyRing(signer.fingerprint)
                    ?: error(tr("d_crypto_err_signer_load", signer.shortFingerprint))
            }
        }
        val inV1 = composite != null &&
            crypto.compositeSignatureInSeipdV1(recipients.rings, subkeyChoices, recipients.v4Algo35)
        if (inV1 && compositeInV1Decision == null) throw CompositeV4SignDecisionNeeded()
        return Plan(recipients, classical, composite, inV1, compositeInV1Decision ?: true, subkeyChoices)
    }

    /** Whole-buffer encrypt. Handles every signer kind, composite included. */
    fun encryptBytes(
        plan: Plan,
        data: ByteArray,
        signerPassphrase: String?,
        armor: Boolean,
        filename: String? = null,
        /** 3.0.0 (5d-4): a finished signed message to encrypt as it stands (SOP, several signers). */
        presignedInline: ByteArray? = null
    ): ByteArray = crypto.encrypt(
        data = data,
        recipientPublicKeys = plan.recipients.rings,
        signingSecretKey = plan.classicalSigner,
        passphrase = signerPassphrase,
        filename = filename,
        armor = armor,
        recipientSubkeyChoices = plan.subkeyChoices,
        v4Algo35Recipients = plan.recipients.v4Algo35,
        compositeSignSuite = plan.compositeSigner?.suite,
        compositeSignSecret = plan.compositeSigner?.compositeSecret,
        compositeSignerFingerprint = plan.compositeSigner?.fingerprint,
        compositeSignInSeipdV1 = plan.keepCompositeInSeipdV1,
        presignedInline = presignedInline
    )

    /**
     * Streaming encrypt for a classical signer or none. A composite signer has no streaming
     * path in the engine (Android buffers those too), so callers check [Plan.needsBuffering]
     * and use [encryptBytes] instead.
     */
    fun encryptStream(
        plan: Plan,
        input: InputStream,
        output: OutputStream,
        signerPassphrase: String?,
        armor: Boolean,
        filename: String?,
        enableCompression: Boolean = true
    ) {
        require(!plan.needsBuffering) { "composite signers use encryptBytes" }
        crypto.encryptStream(
            input = input,
            output = output,
            recipientPublicKeys = plan.recipients.rings,
            signingSecretKey = plan.classicalSigner,
            passphrase = signerPassphrase,
            filename = filename,
            armor = armor,
            enableCompression = enableCompression,
            recipientSubkeyChoices = plan.subkeyChoices,
            v4Algo35Recipients = plan.recipients.v4Algo35
        )
    }

    /** One selected recipient's encryption targets (Android 4.5.0 items 2 and 13). */
    data class RecipientTargets(
        val fingerprint: String,
        val label: String,
        val options: List<com.pgpony.android.crypto.EncryptionKeyOption>,
        /** A v4 interop key: it always receives on its ML-KEM (algo 35) subkey. */
        val v4Algo35: Boolean
    )

    companion object {
        /** The encryption targets of [entities], in the engine's order (automatic pick first). */
        suspend fun recipientTargets(repo: DesktopKeyRepository, entities: List<PGPKeyEntity>): List<RecipientTargets> =
            entities.map { e ->
                val ring = repo.loadEncryptionRecipientRing(e.fingerprint)
                RecipientTargets(
                    fingerprint = e.fingerprint.uppercase(),
                    label = e.userName.ifBlank { e.userEmail.ifBlank { e.shortFingerprint } },
                    options = ring?.let { runCatching { PGPCryptoService.shared.encryptionKeyOptions(it) }.getOrNull() }.orEmpty(),
                    v4Algo35 = repo.loadV4Algo35Recipient(e.fingerprint) != null
                )
            }

        /** Whether [t] receives this message post-quantum, given the chosen subkeys. */
        fun receivesPostQuantum(t: RecipientTargets, choices: Map<String, Long>): Boolean {
            if (t.v4Algo35) return true
            val chosen = choices[t.fingerprint]?.let { id -> t.options.firstOrNull { it.keyId == id } } ?: t.options.firstOrNull()
            return chosen?.isPostQuantum == true
        }

        /**
         * Android 4.5.0 item 2 (#36): with two or more recipients where some receive post-quantum
         * and some classical, the message is only as strong as its classical recipients. The
         * labels of those, or empty when the set is uniform.
         */
        fun pqWeakLinks(targets: List<RecipientTargets>, choices: Map<String, Long>): List<String> {
            if (targets.size < 2) return emptyList()
            val (pq, classical) = targets.partition { receivesPostQuantum(it, choices) }
            return if (pq.isNotEmpty() && classical.isNotEmpty()) classical.map { it.label } else emptyList()
        }

        /** A composite signature over a file or folder is built in memory (the engine has no
         *  streaming composite signer). Past this size the operation stops with a clear error
         *  instead of exhausting the heap. */
        const val COMPOSITE_BUFFER_LIMIT: Long = 512L * 1024 * 1024
    }
}
