// DesktopCompositeVerify.kt: composite ML-DSA (RFC 9980) signature verification (P2a).
// The desktop analog of the Android EncryptDecryptViewModel composite-verify pass. BouncyCastle
// cannot parse composite signatures, so every verify site tries these entry points first and
// falls back to VerifyService when the input is not composite (each returns null in that case).
//
// The math alone is not a verdict. Every entry point goes through the engine's
// CompositeSignerGate, which grades a composite signature the way SignerEvaluator grades a
// classical one: the signature's own policy (document type, hashed creation time, critical
// subpackets, digest, expiration) and then the signer at the signature's time (revoked,
// expired, not a signing key, unbound, older than the key). Only VERIFIED becomes Verified;
// a signature that verified from a key that does not pass becomes Invalid with its reason.

package com.pgpony.desktop

import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.pqc.CompositeDocumentVerifier
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.crypto.pqc.CompositeSignerGate
import com.pgpony.android.data.PGPKeyEntity

object DesktopCompositeVerify {

    private fun dearmor(text: String): ByteArray? =
        runCatching { CompositeSigPacket.dearmor(text) }.getOrNull()

    /** The stored composite certificates, as raw bytes, with the row each one belongs to. */
    private suspend fun certificates(repo: DesktopKeyRepository): Pair<List<PGPKeyEntity>, List<ByteArray>> {
        val rows = ArrayList<PGPKeyEntity>()
        val certs = ArrayList<ByteArray>()
        for (e in repo.allKeys().filter { it.algorithm.isCompositeSign }) {
            val raw = repo.rawPublicBytes(e.fingerprint) ?: continue
            rows += e
            certs += raw
        }
        return rows to certs
    }

    /** [g] as the VerificationResult the screens render, with the row's display identity. */
    internal fun toResult(rows: List<PGPKeyEntity>, g: CompositeSignerGate.Graded, content: String?): VerificationResult {
        val e = rows.getOrNull(g.certIndex)
        return CompositeSignerGate.toVerificationResult(
            g,
            signerName = e?.userName?.ifBlank { null },
            signerEmail = e?.userEmail?.ifBlank { null },
            // 3.0.0 (Android 4.5.3, #57): carry the signer's trust so an unconfirmed key reads
            // "Signed, key not verified".
            signerTrust = e?.trustLevel,
            signedContent = content
        )
    }

    /**
     * Detached signature over [data], as read from a file: armored (.asc) or binary (.sig). Null
     * when it is not a composite signature.
     *
     * 3.0.2: this took the signature as text and dearmored it, and callers handed it the file
     * bytes decoded as UTF-8. A binary .sig is not armor, so the dearmor failed, the composite
     * path returned null, and the caller fell back to BouncyCastle, which cannot read ML-DSA
     * composites and reported the content as not matching. rawSignaturePacket takes either form.
     */
    suspend fun verifyDetached(
        repo: DesktopKeyRepository, signature: ByteArray, data: ByteArray
    ): VerificationResult? {
        val sigPacket = runCatching { CompositeDocumentVerifier.rawSignaturePacket(signature) }.getOrNull() ?: return null
        if (!CompositeDocumentVerifier.isCompositeSignature(sigPacket)) return null
        val (rows, certs) = certificates(repo)
        return toResult(rows, CompositeSignerGate.verifyDetached(certs, sigPacket, data), null)
    }

    /** Detached armored signature pasted as text over [data]. Null when it is not composite. */
    suspend fun verifyDetached(
        repo: DesktopKeyRepository, armoredSig: String, data: ByteArray
    ): VerificationResult? = verifyDetached(repo, armoredSig.toByteArray(Charsets.UTF_8), data)

    /** Clear-signed or inline composite message. Null when the input is not composite. */
    suspend fun verifyText(repo: DesktopKeyRepository, armored: String): VerificationResult? {
        if (CompositeDocumentVerifier.isCompositeCleartext(armored)) {
            val content = CompositeDocumentVerifier.cleartextContent(armored)
            val (rows, certs) = certificates(repo)
            return toResult(rows, CompositeSignerGate.verifyCleartext(certs, armored), content)
        }
        val msg = dearmor(armored) ?: return null
        if (CompositeDocumentVerifier.isCompositeInline(msg)) {
            val (rows, certs) = certificates(repo)
            val g = CompositeSignerGate.verifyInline(certs, msg)
            // The content shown is the one literal the gate checked; a message it refused as
            // malformed shows none.
            return toResult(rows, g, g.content?.toString(Charsets.UTF_8))
        }
        return null
    }

    /**
     * 3.0.0 (Android 4.5.3): the composite inline signature inside a DECRYPTED message, which
     * the engine hands back as DecryptResult.compositeInlineBytes because BouncyCastle cannot
     * parse it. [claimedFp] is kept for callers; the gate takes issuer subpackets as hints only.
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun verifyInlineBytes(
        repo: DesktopKeyRepository, inlineBytes: ByteArray, claimedFp: String?
    ): VerificationResult {
        val (rows, certs) = certificates(repo)
        return toResult(rows, CompositeSignerGate.verifyInline(certs, inlineBytes), null)
    }
}
