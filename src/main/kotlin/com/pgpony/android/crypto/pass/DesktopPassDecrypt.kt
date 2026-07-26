// DesktopPassDecrypt.kt — DESKTOP TWIN of crypto/pass/PassDecryptCoordinator.kt (vendored copy
// excluded: it imports com.pgpony.android.data.repository.KeyRepository, the Android Room
// repository). Same `sealed interface PassRoute`, same `object PassDecryptCoordinator`, the
// SAME routing rules — retyped to DesktopKeyRepository, whose method names differ slightly
// (allKeys() vs getAllKeys()).
//
// FILE NAME must differ from the excluded PassDecryptCoordinator.kt (D1 Fix1 — set-wide excludes).
//
// Routing, unchanged from Android: the message's PKESK key ids decide. A software keypair that
// holds a recipient key wins (no tap needed); else a card-backed key; else no match. A wildcard
// recipient (key id 0) matches every ring — that's the point of a hidden recipient, and BC will
// try each key in turn.

package com.pgpony.android.crypto.pass

import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.desktop.DesktopKeyRepository
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.ByteArrayInputStream

/** How a pass entry should be decrypted, decided by recipient matching. */
sealed interface PassRoute {
    /** A software keypair holds the message's recipient key — decrypt in software. */
    data class Software(val rings: List<PGPSecretKeyRing>) : PassRoute
    /** Only a card-backed key matches — decrypt over PC/SC (D7's CardDecryptService). */
    data object Card : PassRoute
    /** No key in the keyring matches the message's recipients. */
    data object NoMatch : PassRoute
}

object PassDecryptCoordinator {

    /**
     * All software-keypair secret rings. BC picks the one matching the message's PKESK key id,
     * so the caller passes them all. Loaded once so a passphrase retry doesn't re-read the
     * material store.
     */
    suspend fun softwareSecretRings(repo: DesktopKeyRepository): List<PGPSecretKeyRing> =
        repo.allKeys()
            .filter { it.isKeyPair }
            .mapNotNull { repo.loadSecretKeyRing(it.fingerprint) }

    /** Whether the keyring holds any card-backed key (used for routing / messaging). */
    suspend fun hasCardKey(repo: DesktopKeyRepository): Boolean =
        repo.allKeys().any { it.isCardBacked }

    /**
     * Decrypt [bytes] with the given software secret [rings]. [passphrase] is null on the first
     * attempt; if the matching key is passphrase-protected the caller catches the failure,
     * prompts, and retries. Returns the decrypted plaintext. Throws on failure (no matching key
     * or wrong passphrase).
     */
    fun decryptSoftware(bytes: ByteArray, rings: List<PGPSecretKeyRing>, passphrase: String?): String =
        PGPCryptoService.shared.decrypt(bytes, rings, passphrase).plaintext

    /**
     * The recipient key ids of an encrypted message (PKESK packets). A 0 id is a
     * hidden/wildcard recipient. Tolerant: returns empty on any parse failure.
     */
    fun messageRecipientKeyIds(bytes: ByteArray): List<Long> {
        return try {
            val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(bytes))
            val factory = JcaPGPObjectFactory(decoder)
            var obj = factory.nextObject()
            while (obj != null && obj !is PGPEncryptedDataList) obj = factory.nextObject()
            val encList = obj as? PGPEncryptedDataList ?: return emptyList()
            encList.encryptedDataObjects.asSequence()
                .filterIsInstance<PGPPublicKeyEncryptedData>()
                .map { it.keyID }
                .toList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Decide how to decrypt [bytes]: prefer a software keypair that holds a recipient key; else
     * a card-backed key; else no match. A ring matches when it contains a key whose id is one of
     * the message's recipients (the same check CardDecryptService uses), or when the message has
     * a wildcard recipient. Software is preferred because it needs no PIN and no touch.
     */
    suspend fun route(repo: DesktopKeyRepository, bytes: ByteArray): PassRoute {
        val ids = messageRecipientKeyIds(bytes)
        val wildcard = ids.contains(0L)
        val keys = repo.allKeys()

        fun matches(ring: PGPPublicKeyRing): Boolean =
            wildcard || ids.any { ring.getPublicKey(it) != null }

        val swRings = keys.filter { it.isKeyPair }.mapNotNull { k ->
            val pub = repo.loadPublicKeyRing(k.fingerprint) ?: return@mapNotNull null
            if (matches(pub)) repo.loadSecretKeyRing(k.fingerprint) else null
        }
        if (swRings.isNotEmpty()) return PassRoute.Software(swRings)

        val cardMatch = keys.filter { it.isCardBacked }.any { k ->
            repo.loadPublicKeyRing(k.fingerprint)?.let { matches(it) } == true
        }
        return if (cardMatch) PassRoute.Card else PassRoute.NoMatch
    }
}
