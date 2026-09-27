// DesktopCompositeVerify.kt — composite ML-DSA (RFC 9980) signature verification (P2a).
// The desktop analog of the Android EncryptDecryptViewModel composite-verify pass. BouncyCastle
// cannot parse composite signatures, so every verify site tries these entry points first and
// falls back to VerifyService when the input is not composite (each returns null in that case).

package com.pgpony.desktop

import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.pqc.CompositeDocumentVerifier
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.data.PGPKeyEntity

object DesktopCompositeVerify {

    private fun dearmor(text: String): ByteArray? =
        runCatching { CompositeSigPacket.dearmor(text) }.getOrNull()

    private suspend fun resolveSigner(
        repo: DesktopKeyRepository,
        claimedFp: String?
    ): Pair<PGPKeyEntity, CompositeKeyFacade.CompositeComponent>? {
        if (claimedFp == null) return null
        for (e in repo.allKeys().filter { it.algorithm.isCompositeSign }) {
            val info = repo.loadCompositePublicInfo(e.fingerprint) ?: continue
            for (c in info.compositeSigners) {
                if (c.fingerprintHex.equals(claimedFp, ignoreCase = true)) return e to c
            }
        }
        return null
    }

    private fun verified(e: PGPKeyEntity, claimedFp: String?, content: String?) =
        VerificationResult.Verified(
            signerKeyID = claimedFp?.take(16) ?: e.longKeyId,
            signerFingerprint = e.fingerprint,
            signerName = e.userName.ifBlank { null },
            signerEmail = e.userEmail.ifBlank { null },
            signedContent = content,
            // 3.0.0 (Android 4.5.3, #57): carry the signer's trust so an unconfirmed key reads
            // "Signed, key not verified".
            signerTrust = e.trustLevel
        )

    private fun unknown(claimedFp: String?, content: String?) =
        VerificationResult.UnknownSigner(claimedFp?.take(16) ?: "", claimedFp, content)

    private fun invalid(claimedFp: String?, content: String?) =
        VerificationResult.Invalid("composite signature did not verify", claimedFp?.take(16), content)

    /** Detached armored signature over [data]. Null when the input is not a composite signature. */
    suspend fun verifyDetached(
        repo: DesktopKeyRepository, armoredSig: String, data: ByteArray
    ): VerificationResult? {
        val sig = dearmor(armoredSig) ?: return null
        val sigPacket = runCatching { CompositeDocumentVerifier.rawSignaturePacket(sig) }.getOrNull() ?: return null
        if (!CompositeDocumentVerifier.isCompositeSignature(sigPacket)) return null
        val claimedFp = CompositeDocumentVerifier.claimedSignerOfDetached(sig)
        val (e, c) = resolveSigner(repo, claimedFp) ?: return unknown(claimedFp, null)
        return if (CompositeDocumentVerifier.verifyDetached(c.publicMaterial, sigPacket, data).valid)
            verified(e, claimedFp, null) else invalid(claimedFp, null)
    }

    /** Clear-signed or inline composite message. Null when the input is not composite. */
    suspend fun verifyText(repo: DesktopKeyRepository, armored: String): VerificationResult? {
        if (CompositeDocumentVerifier.isCompositeCleartext(armored)) {
            val content = CompositeDocumentVerifier.cleartextContent(armored)
            val claimedFp = CompositeDocumentVerifier.claimedSignerOfCleartext(armored)
            val (e, c) = resolveSigner(repo, claimedFp) ?: return unknown(claimedFp, content)
            return if (CompositeDocumentVerifier.verifyCleartext(c.publicMaterial, armored).valid)
                verified(e, claimedFp, content) else invalid(claimedFp, content)
        }
        val msg = dearmor(armored) ?: return null
        if (CompositeDocumentVerifier.isCompositeInline(msg)) {
            val content = CompositeDocumentVerifier.inlineContent(msg)?.toString(Charsets.UTF_8)
            val claimedFp = CompositeDocumentVerifier.claimedSignerOfInline(msg)
            val (e, c) = resolveSigner(repo, claimedFp) ?: return unknown(claimedFp, content)
            return if (CompositeDocumentVerifier.verifyInline(c.publicMaterial, msg).valid)
                verified(e, claimedFp, content) else invalid(claimedFp, content)
        }
        return null
    }

    /**
     * 3.0.0 (Android 4.5.3): the composite inline signature inside a DECRYPTED message, which
     * the engine hands back as DecryptResult.compositeInlineBytes because BouncyCastle cannot
     * parse it. Before 3.0.0 the desktop decrypt paths never looked, so these read as unsigned.
     */
    suspend fun verifyInlineBytes(
        repo: DesktopKeyRepository, inlineBytes: ByteArray, claimedFp: String?
    ): VerificationResult {
        val fp = claimedFp ?: CompositeDocumentVerifier.claimedSignerOfInline(inlineBytes)
        val (e, c) = resolveSigner(repo, fp) ?: return unknown(fp, null)
        return if (CompositeDocumentVerifier.verifyInline(c.publicMaterial, inlineBytes).valid)
            verified(e, fp, null) else invalid(fp, null)
    }
}
