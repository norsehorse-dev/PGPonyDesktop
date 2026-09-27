// MimeOps.kt
// PGPony Desktop — D3c: PGP/MIME both directions on the vendored mime/ package.
// Compose: body + attachments → MimeBuilder.buildMixed → encrypt (public-key or symmetric) →
// armored message, optionally wrapped as a full .eml (RFC 3156 multipart/encrypted envelope
// via MimeBuilder.wrapEncrypted + minimal outer headers). Decrypt mirrors the Android
// ViewModel routing exactly: pgpMimeEncryptedPayload strips a pasted .eml down to its armored
// payload, and MimeParser.parse on the decrypted bytes yields the structured body+attachments
// (non-MIME plaintext passes through untouched).

package com.pgpony.desktop

import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.mime.MimeAttachment
import com.pgpony.android.crypto.mime.MimeBuilder
import com.pgpony.android.crypto.mime.MimeParser
import java.nio.file.Files
import java.nio.file.Path

class MimeOps(
    private val repo: DesktopKeyRepository,
    private val crypto: PGPCryptoService = PGPCryptoService.shared
) {

    data class Structured(
        val body: String,
        val attachments: List<MimeAttachment>,
        val signatureVerified: Boolean,
        val hasSignature: Boolean,
        val signerKeyID: String?,
        val signatureKeyIDRaw: Long?,
        /** 3.0.0: the signature read once, trust and composite ML-DSA included. */
        val signature: SignatureSummary.Summary? = null
    )

    /** Body + attachments → multipart/mixed → recipient-encrypted armored message. */
    suspend fun encryptBundle(
        body: String,
        attachmentPaths: List<Path>,
        recipientFingerprints: Collection<String>,
        signerFingerprint: String?,
        signerPassphrase: String?,
        compositeInV1Decision: Boolean? = null,
        subkeyChoices: Map<String, Long> = emptyMap()
    ): String {
        // 3.0.0: EncryptOps decides recipients (fail closed, v4 algo-35 channel), the expired-key
        // rule and the signer, including a composite ML-DSA signer (Android 4.5.2). The Phase A3
        // rule holds: a requested signature never silently drops.
        val signer = signerFingerprint?.let {
            repo.byFingerprint(it) ?: error(tr("d_file_err_signing_key", it.take(16)))
        }
        val ops = EncryptOps(repo)
        val plan = ops.plan(recipientFingerprints, signer, signerPassphrase, compositeInV1Decision, subkeyChoices)
        val mimeBytes = MimeBuilder.buildMixed(body.ifBlank { null }, loadAttachments(attachmentPaths))
        return String(ops.encryptBytes(plan, mimeBytes, signerPassphrase, armor = true), Charsets.UTF_8)
    }

    /**
     * D7 — bundle encrypt with the signature leg on the CARD (the vendored encrypt's HW
     * Phase 3 params). Runs with the card connected.
     */
    suspend fun encryptBundleWithCardSigner(
        body: String,
        attachmentPaths: List<Path>,
        recipientFingerprints: Collection<String>,
        session: com.pgpony.android.crypto.card.OpenPgpCardSession,
        cardPin: ByteArray,
        cardSigningPublicKey: org.bouncycastle.openpgp.PGPPublicKey
    ): String {
        val mimeBytes = MimeBuilder.buildMixed(body.ifBlank { null }, loadAttachments(attachmentPaths))
        KeyUsePolicy.requireUsable(recipientFingerprints.mapNotNull { repo.byFingerprint(it) }, null)
        val recipients = repo.requireRecipients(recipientFingerprints)
        val encrypted = crypto.encrypt(
            data = mimeBytes,
            recipientPublicKeys = recipients.rings,
            v4Algo35Recipients = recipients.v4Algo35,
            cardSession = session,
            cardPin = cardPin,
            cardSigningPublicKey = cardSigningPublicKey,
            armor = true
        )
        return String(encrypted, Charsets.UTF_8)
    }

    /** Body + attachments → multipart/mixed → passphrase-encrypted armored message. */
    fun encryptBundleSymmetric(body: String, attachmentPaths: List<Path>, passphrase: String): String {
        val mimeBytes = MimeBuilder.buildMixed(body.ifBlank { null }, loadAttachments(attachmentPaths))
        val encrypted = crypto.encryptSymmetric(mimeBytes, passphrase, armor = true)
        return String(encrypted, Charsets.UTF_8)
    }

    /**
     * Wrap an armored message as a complete .eml: minimal outer headers + the RFC 3156
     * multipart/encrypted entity (whose own MIME-Version/Content-Type lines continue the
     * header block — the composition the Android J4 path performs).
     */
    fun buildEml(armored: String, subject: String = "PGP encrypted message"): String {
        val entity = String(MimeBuilder.wrapEncrypted(armored), Charsets.UTF_8)
        return "Subject: $subject\r\n" + entity
    }

    /**
     * Decrypt text OR a pasted .eml; parse the plaintext for a MIME bundle. Mirrors the
     * Android ViewModel: `pgpMimeEncryptedPayload(raw) ?: raw`, then `MimeParser.parse(bytes)`
     * — body-only MIME surfaces its body, non-MIME plaintext passes through.
     */
    suspend fun decryptStructured(input: String, passphrase: String?, selected: String? = null): Structured {
        val armored = pgpPayload(input)
        // 3.0.0 (plan 3.7): [selected] and its fallbacks first; a failure names the case (#46).
        val result = try {
            repo.decryptText(armored, passphrase, selected)
        } catch (t: Throwable) {
            throw repo.explainDecryptFailure(
                { PGPCryptoService.shared.recipientKeyIDs(armored) }, selected, t
            )
        }
        val mime = MimeParser.parse(result.data)
        val body = when {
            mime == null -> result.plaintext
            mime.hasAttachments -> mime.body ?: ""
            else -> mime.body ?: result.plaintext
        }
        return Structured(
            body = body,
            attachments = mime?.attachments ?: emptyList(),
            signatureVerified = result.signatureVerified,
            hasSignature = result.hasSignature,
            signerKeyID = result.signerKeyID,
            signatureKeyIDRaw = result.signatureKeyIDRaw,
            signature = SignatureSummary.of(
                repo, result.signatureVerified, result.hasSignature, result.signerKeyID, result.signatureKeyIDRaw,
                result.compositeInline, result.compositeInlineBytes, result.compositeClaimedSignerFp
            )
        )
    }

    /**
     * D7 — build the structured view from already-decrypted bytes (the card path decrypts on
     * the hardware, then reuses this MIME parsing so its output matches the software Decrypt
     * tab). [plaintextFallback] is the raw UTF-8 for the non-MIME case.
     */
    fun structuredFromBytes(
        data: ByteArray,
        signatureVerified: Boolean,
        hasSignature: Boolean,
        signerKeyID: String?
    ): Structured {
        val mime = MimeParser.parse(data)
        val plaintext = String(data, Charsets.UTF_8)
        val body = when {
            mime == null -> plaintext
            mime.hasAttachments -> mime.body ?: ""
            else -> mime.body ?: plaintext
        }
        return Structured(
            body = body,
            attachments = mime?.attachments ?: emptyList(),
            signatureVerified = signatureVerified,
            hasSignature = hasSignature,
            signerKeyID = signerKeyID,
            signatureKeyIDRaw = null
        )
    }

    companion object {
        /** Strip a pasted .eml / PGP-MIME envelope to its armored payload, or return [input]
         *  unchanged (the Android `pgpMimeEncryptedPayload(raw) ?: raw` routing). */
        fun pgpPayload(input: String): String = MimeParser.pgpMimeEncryptedPayload(input) ?: input
    }

    private fun loadAttachments(paths: List<Path>): List<MimeAttachment> = paths.map { p ->
        MimeAttachment(
            filename = p.fileName.toString(),
            contentType = runCatching { Files.probeContentType(p) }.getOrNull()
                ?: "application/octet-stream",
            data = Files.readAllBytes(p)
        )
    }
}
