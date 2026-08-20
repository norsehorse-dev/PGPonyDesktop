// DesktopKeyRepository.kt
// PGPony Desktop — D2a keyring repository: the desktop twin of the Android KeyRepository's
// import/list/export/delete core, built on the SAME vendored DAO + entities + crypto engine.
// The resolution names deliberately mirror Android's ImportResolution so screens and future
// vendored callers speak one vocabulary. Not yet ported from Android: card pairing
// (PAIRED_WITH_CARD, D7), merge of newer public material (MERGED_NEW_MATERIAL, D2b with the
// dedup service), generate/trust/notes/revocation/expiration (D2b/D2c).
//
// D11b/D11c — localization. Every string here that can reach a human is a key: the
// ImportReport summary and the IllegalStateException / UnsupportedKey messages, which the
// screens surface verbatim through Throwable.message. Two strings stay English on purpose —
// the "<manufacturer> hardware key" label and the "Serial <hex>" e-mail placeholder — because
// they are PERSISTED into PGPKeyEntity, travel inside backups, and cross the phone/desktop
// restore boundary; Android's KeyRepository leaves them English for exactly the same reason,
// and localizing them here would make one restored keyring read differently depending on
// which machine imported the card. The summary clauses are all <plurals> because es/fr/pt-BR
// need number agreement with the implied feminine noun (clave / cle / chave), and each
// continuation clause carries its own leading separator so ja can use a full-width comma.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.KeyExpirationService
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.RevocationError
import com.pgpony.android.crypto.RevocationService
import com.pgpony.android.crypto.SubkeyCapability
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.TrustLevel
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.UUID

/** Mirrors the Android ImportResolution vocabulary (card pairing arrives D7). */
enum class ImportResolution { INSERTED, UPGRADED_TO_KEY_PAIR, MERGED_NEW_MATERIAL, ALREADY_IN_KEYRING, FAILED }

data class ImportReport(
    val inserted: Int,
    val upgraded: Int,
    val already: Int,
    val failed: Int,
    val merged: Int = 0
) {
    val total: Int get() = inserted + upgraded + already + failed + merged
    fun summary(): String {
        val clauses = StringBuilder(trQuantity("d_import_summary_added", inserted))
        if (upgraded > 0) clauses.append(trQuantity("d_import_summary_upgraded", upgraded))
        if (merged > 0) clauses.append(trQuantity("d_import_summary_merged", merged))
        if (already > 0) clauses.append(trQuantity("d_import_summary_already", already))
        if (failed > 0) clauses.append(trQuantity("d_import_summary_failed", failed))
        return trQuantity("d_import_summary_blocks", total, clauses.toString())
    }
}

class DesktopKeyRepository(
    private val db: PGPDatabase,
    private val materials: KeyMaterialStore,
    private val crypto: PGPCryptoService = PGPCryptoService.shared,
    private val revocation: RevocationService = RevocationService.shared,
    private val keyExpiration: KeyExpirationService = KeyExpirationService.shared
) {
    private val dao get() = db.keyDao()

    // ── Generate (D2b — the Android KeyRepository.generateKey port) ─────

    /**
     * Same sequence as Android: generate → store both material halves → derive expiry from the
     * generated master key → pre-cache a NO_REASON revocation certificate while the passphrase
     * is still in scope (Phase A6 semantics; non-fatal on failure) → insert the entity.
     * All six generatable algorithms are supported, including both PQC composites.
     */
    suspend fun generateKey(
        name: String,
        email: String,
        algorithm: KeyAlgorithm,
        passphrase: String?,
        expirationSeconds: Long? = null
    ): PGPKeyEntity {
        val result = crypto.generateKeyPair(name, email, algorithm, passphrase, expirationSeconds)

        materials.storePublic(result.fingerprint, result.armoredPublicKey)
        materials.storeSecret(result.fingerprint, result.armoredPrivateKey)

        val importResult = crypto.importKeyData(result.publicKeyData)
        val masterKey = importResult.publicKeyRing?.publicKey
        val expiresAtMs = masterKey?.let { key ->
            val validSec = key.validSeconds
            if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
        }

        val preCachedRevocationCert: String? = try {
            crypto.importArmoredKey(result.armoredPrivateKey).secretKeyRing?.let { secRing ->
                revocation.generateRevocationCertificate(
                    secretKeyRing = secRing,
                    reason = RevocationReason.NO_REASON,
                    comment = null,
                    passphrase = passphrase
                )
            }
        } catch (_: RevocationError) {
            null
        }

        val parsed = PGPKeyEntity.parseUserID("$name <$email>")
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = result.fingerprint,
            userID = "$name <$email>",
            userName = parsed.first,
            userEmail = parsed.second,
            algorithm = algorithm,
            isKeyPair = true,
            createdAt = System.currentTimeMillis(),
            expiresAt = expiresAtMs,
            armoredPublicKey = result.armoredPublicKey,
            revocationCertificate = preCachedRevocationCert
        )
        dao.insert(entity)
        return entity
    }

    // ── Query ───────────────────────────────────────────────────────────

    suspend fun allKeys(): List<PGPKeyEntity> = dao.getAllKeys()
    suspend fun count(): Int = dao.count()
    suspend fun byFingerprint(fingerprint: String): PGPKeyEntity? =
        dao.getByFingerprint(fingerprint)
            ?: dao.getByFingerprint(fingerprint.lowercase())
            ?: dao.getByFingerprint(fingerprint.uppercase())   // engine emits uppercase; backup meta lowercases

    // ── Import ──────────────────────────────────────────────────────────

    suspend fun importArmoredText(text: String): ImportReport =
        importBlocks(splitArmoredBlocks(text))

    suspend fun importBytes(data: ByteArray): ImportReport {
        val blocks = runCatching { crypto.explodeToArmoredKeys(data) }.getOrDefault(emptyList())
        if (blocks.isNotEmpty()) return importBlocks(blocks)
        val asText = data.toString(Charsets.UTF_8)
        return if (asText.contains("-----BEGIN PGP")) importArmoredText(asText)
        else ImportReport(0, 0, 0, failed = 1)
    }

    private suspend fun importBlocks(blocks: List<String>): ImportReport {
        var inserted = 0; var upgraded = 0; var already = 0; var failed = 0; var merged = 0
        for (block in blocks) {
            when (runCatching { importArmoredKeyDetailed(block) }.getOrElse { ImportResolution.FAILED }) {
                ImportResolution.INSERTED -> inserted++
                ImportResolution.UPGRADED_TO_KEY_PAIR -> upgraded++
                ImportResolution.MERGED_NEW_MATERIAL -> merged++
                ImportResolution.ALREADY_IN_KEYRING -> already++
                ImportResolution.FAILED -> failed++
            }
        }
        return ImportReport(inserted, upgraded, already, failed, merged)
    }

    /**
     * One armored block → one resolution. Same core semantics as Android's
     * importArmoredKeyDetailed: dedupe by fingerprint; secret material arriving for a
     * public-only row upgrades in place; a held secret is never overwritten.
     */
    suspend fun importArmoredKeyDetailed(block: String): ImportResolution {
        val result = crypto.importArmoredKey(block)
        val fingerprint = result.fingerprint
        val publicArmor = result.publicKeyRing?.let { crypto.exportArmoredPublicKey(it) }

        val existing = byFingerprint(fingerprint)
        return when {
            existing == null -> {
                val (name, email) = PGPKeyEntity.parseUserID(result.userID)
                val createdAt = result.creationDate.time
                val expiresAt = result.publicKeyRing?.publicKey?.validSeconds
                    ?.takeIf { it > 0 }?.let { createdAt + it * 1000L }
                publicArmor?.let { materials.storePublic(fingerprint, it) }
                if (result.hasPrivateKey) materials.storeSecret(fingerprint, block)
                dao.insert(
                    PGPKeyEntity(
                        id = UUID.randomUUID().toString(),
                        fingerprint = fingerprint,
                        userID = result.userID,
                        userName = name,
                        userEmail = email,
                        algorithm = result.algorithm,
                        isKeyPair = result.hasPrivateKey,
                        createdAt = createdAt,
                        expiresAt = expiresAt,
                        armoredPublicKey = publicArmor
                    )
                )
                ImportResolution.INSERTED
            }
            result.hasPrivateKey && !existing.isKeyPair -> {
                materials.storeSecret(fingerprint, block)
                publicArmor?.let { materials.storePublic(fingerprint, it) }
                dao.update(existing.copy(isKeyPair = true, armoredPublicKey = publicArmor ?: existing.armoredPublicKey))
                ImportResolution.UPGRADED_TO_KEY_PAIR
            }
            else -> mergeIfNewMaterial(existing, result.publicKeyRing)
        }
    }

    /**
     * D2c — the dedup-service subset for re-imports: byte-identical public material reports
     * ALREADY_IN_KEYRING; differing material (new sigs, UIDs, subkeys, revocations) joins into
     * the stored ring via BC's ring merge — trust, notes, secret material, and card backing all
     * survive because only armoredPublicKey/material change. A held secret is never touched.
     */
    private suspend fun mergeIfNewMaterial(
        existing: PGPKeyEntity,
        incomingRing: PGPPublicKeyRing?
    ): ImportResolution {
        if (incomingRing == null) return ImportResolution.ALREADY_IN_KEYRING
        val storedRing = loadPublicKeyRing(existing.fingerprint)
        if (storedRing == null) {
            // D7 Fix — the row exists but holds NO public material yet: a card-backed row from
            // pairing (or the moment after on-card keygen). This IS the arrival of its public
            // certificate, so store it rather than no-op'ing to ALREADY_IN_KEYRING (which left
            // the card key unusable as a recipient / verify key).
            val armor = crypto.exportArmoredPublicKey(incomingRing)
            materials.storePublic(existing.fingerprint, armor)
            val nowRevoked = runCatching { incomingRing.publicKey.hasRevocation() }.getOrDefault(false)
            val expiresAt = incomingRing.publicKey?.let { k ->
                k.validSeconds.takeIf { it > 0 }?.let { k.creationTime.time + it * 1000L }
            }
            dao.update(
                existing.copy(
                    armoredPublicKey = armor,
                    expiresAt = expiresAt,
                    isRevoked = existing.isRevoked || nowRevoked,
                    revokedAt = if (!existing.isRevoked && nowRevoked) System.currentTimeMillis() else existing.revokedAt
                )
            )
            return ImportResolution.MERGED_NEW_MATERIAL
        }
        if (storedRing.encoded.contentEquals(incomingRing.encoded)) {
            return ImportResolution.ALREADY_IN_KEYRING
        }
        val mergedRing = runCatching { PGPPublicKeyRing.join(storedRing, incomingRing) }
            .getOrNull() ?: return ImportResolution.ALREADY_IN_KEYRING
        if (mergedRing.encoded.contentEquals(storedRing.encoded)) {
            return ImportResolution.ALREADY_IN_KEYRING   // nothing actually new
        }
        val mergedArmor = crypto.exportArmoredPublicKey(mergedRing)
        materials.storePublic(existing.fingerprint, mergedArmor)
        val nowRevoked = runCatching { mergedRing.publicKey.hasRevocation() }.getOrDefault(false)
        // D4 (Fix1) — expiry comes from the INCOMING ring's primary: the exact value Android
        // hands to resolveDuplicate (KeyRefreshService derives fetchedExpiresAtMs from the
        // FETCHED ring), so an upstream extension/removal lands on merge. Not the joined
        // ring: BC's getValidSeconds picks the newest self-sig with a strict > on creation
        // time, so a re-sign in the same second as the original ties and resolves by
        // iteration order — the joined ring can report the stale value.
        val newExpiresAt = incomingRing.publicKey?.let { k ->
            k.validSeconds.takeIf { it > 0 }?.let { k.creationTime.time + it * 1000L }
        }
        dao.update(
            existing.copy(
                armoredPublicKey = mergedArmor,
                expiresAt = newExpiresAt,
                isRevoked = existing.isRevoked || nowRevoked,
                revokedAt = if (!existing.isRevoked && nowRevoked) System.currentTimeMillis() else existing.revokedAt
            )
        )
        return ImportResolution.MERGED_NEW_MATERIAL
    }

    // ── D4 — keyserver support (Android KeyRepository keyserver section, ported) ──

    /**
     * The refresh pipeline's merge step — Android's mergeFetchedPublicMaterial contract on the
     * desktop merge path: byte-identical → unchanged; new material joins the stored ring
     * (trust, notes, secrets, card backing preserved). Returns the post-merge row plus whether
     * material actually changed.
     */
    suspend fun mergeFetchedPublicMaterial(
        existing: PGPKeyEntity,
        fetchedRing: PGPPublicKeyRing?
    ): Pair<PGPKeyEntity, Boolean> {
        val resolution = mergeIfNewMaterial(existing, fetchedRing)
        val row = byFingerprint(existing.fingerprint) ?: existing
        return row to (resolution == ImportResolution.MERGED_NEW_MATERIAL)
    }

    /**
     * Stamp upstream revocation onto [fingerprint]'s row (fetched keyserver copy carried a
     * 0x20 key-revocation signature). CALLER GUARDS the "already revoked locally" case from
     * the PRE-merge row — the desktop merge path may itself have flagged isRevoked from the
     * joined ring, and this stamp records the authoritative revokedAt (signature creation
     * time) + reason on top of that. A locally revoked key never reaches here, so its own
     * stamps survive (the Android contract).
     */
    suspend fun markRevokedFromUpstream(
        fingerprint: String,
        revokedAtMs: Long,
        reason: RevocationReason?
    ): PGPKeyEntity? {
        val entity = byFingerprint(fingerprint) ?: return null
        val updated = entity.copy(
            isRevoked = true,
            revokedAt = revokedAtMs,
            revocationReason = reason
        )
        dao.update(updated)
        return updated
    }

    /** 3.0.0-KS1 — record a publish so the detail screen shows "Last uploaded". */
    suspend fun markKeyServerUploaded(fingerprint: String) {
        byFingerprint(fingerprint)?.let { key ->
            dao.update(
                key.copy(
                    keyServerUploaded = true,
                    lastUploadedAt = System.currentTimeMillis()
                )
            )
        }
    }

    /** 3.0.0-KS1 — record a check/refresh attempt (found or not; the timestamp marks the
     *  attempt) so the detail screen shows "Last checked". */
    suspend fun markKeyServerChecked(fingerprint: String) {
        byFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(lastCheckedAt = System.currentTimeMillis()))
        }
    }

    // ── D7 — hardware keys (the Android KeyRepository card section, ported) ──

    /**
     * Import (or link) a physical OpenPGP card as a card-backed key — the Android
     * importCardKey port, incl. the 3.1.0 Phase 7 A1 offline-primary rule: the card's slot
     * fingerprints may all be SUBKEYS, so linking scans every stored ring's full key set
     * before creating a fresh card-contact row. An existing row (public cert imported
     * earlier) gets the card fields stamped on; otherwise a public-only card-backed row is
     * inserted (no material writes — the secrets live on the card).
     */
    suspend fun importCardKey(cardInfo: com.pgpony.android.crypto.card.CardInfo): PGPKeyEntity {
        val primaryFp = cardInfo.primaryFingerprint
            ?: throw IllegalStateException(tr("d_repo_err_no_card_keys"))

        val sigFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.SIGNATURE)
        val decFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.DECRYPTION)
        val authFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.AUTHENTICATION)

        val existing = byFingerprint(primaryFp)
            ?: findEntityBySubkeyFingerprint(listOfNotNull(sigFp, decFp, authFp))
        if (existing != null) {
            val linked = existing.copy(
                isCardBacked = true,
                cardSerial = cardInfo.serialHex,
                cardAid = cardInfo.aidHex,
                cardManufacturer = cardInfo.manufacturerName,
                cardSigFingerprint = sigFp,
                cardDecFingerprint = decFp,
                cardAuthFingerprint = authFp
            )
            dao.update(linked)
            return linked
        }

        val algorithm = cardInfo.slotFor(com.pgpony.android.crypto.card.CardSlot.SIGNATURE)?.algorithm
            ?: cardInfo.slots.firstOrNull { it.algorithm != null }?.algorithm
            ?: KeyAlgorithm.ED25519_CV25519

        // Deliberately NOT localized: this label and the serial placeholder below are
        // persisted into the entity and travel in backups across devices — see the header note.
        val label = "${cardInfo.manufacturerName} hardware key"
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = primaryFp,
            userID = label,
            userName = label,
            userEmail = "Serial ${cardInfo.serialHex}",
            algorithm = algorithm,
            isKeyPair = false,
            createdAt = cardInfo.slotFor(com.pgpony.android.crypto.card.CardSlot.SIGNATURE)?.generationTime
                ?: System.currentTimeMillis(),
            isCardBacked = true,
            cardSerial = cardInfo.serialHex,
            cardAid = cardInfo.aidHex,
            cardManufacturer = cardInfo.manufacturerName,
            cardSigFingerprint = sigFp,
            cardDecFingerprint = decFp,
            cardAuthFingerprint = authFp
        )
        dao.insert(entity)
        return entity
    }

    /**
     * Persist a key just generated ON a card (the Android importGeneratedCardKey port):
     * parse-validate the assembled transferable public key, create/identify the card-backed
     * row, then fold the real public key + UID onto it through the normal import path.
     */
    suspend fun importGeneratedCardKey(
        publicKeyBinary: ByteArray,
        cardInfo: com.pgpony.android.crypto.card.CardInfo
    ): PGPKeyEntity {
        val parsed = crypto.importKeyData(publicKeyBinary)
        val ring = parsed.publicKeyRing
            ?: throw IllegalStateException(tr("d_repo_err_no_public_ring"))
        val armored = crypto.exportArmoredPublicKey(ring)
        importCardKey(cardInfo)                 // creates/links the card-backed row (placeholder label)
        importArmoredKeyDetailed(armored)       // folds the real public material onto it
        val fp = cardInfo.primaryFingerprint ?: ""
        val row = byFingerprint(fp)
            ?: throw IllegalStateException(tr("d_repo_err_card_row_missing"))
        // The merge path preserves identity fields, so the row still carries importCardKey's
        // "<manufacturer> hardware key" placeholder. Replace it with the generated key's real
        // UID (the software generate path names the row from name <email>; match that).
        val uid = parsed.userID.takeIf { it.isNotBlank() } ?: return row
        val (name, email) = PGPKeyEntity.parseUserID(uid)
        val named = row.copy(userID = uid, userName = name, userEmail = email)
        dao.update(named)
        return named
    }

    /**
     * The stored entity whose public ring contains ANY of [fingerprints] — primary or subkey
     * (the Android findEntityBySubkeyFingerprint). Linear over the keyring; keyrings are small.
     */
    suspend fun findEntityBySubkeyFingerprint(fingerprints: List<String>): PGPKeyEntity? {
        if (fingerprints.isEmpty()) return null
        val wanted = fingerprints.map { it.uppercase() }.toSet()
        for (entity in allKeys()) {
            val ring = loadPublicKeyRing(entity.fingerprint) ?: continue
            val ringFps = ring.publicKeys.asSequence().map {
                org.bouncycastle.util.encoders.Hex.toHexString(it.fingerprint).uppercase()
            }
            if (ringFps.any { it in wanted }) return entity
        }
        return null
    }

    /**
     * Text encrypt with the SIGNATURE LEG on the card (the vendored encrypt's HW Phase 3
     * params). Must run with the card connected — the content signer calls into it.
     */
    fun encryptTextWithCardSigner(
        message: String,
        recipientRings: List<PGPPublicKeyRing>,
        cardSession: com.pgpony.android.crypto.card.OpenPgpCardSession,
        cardPin: ByteArray,
        cardSigningPublicKey: org.bouncycastle.openpgp.PGPPublicKey
    ): String = String(
        crypto.encrypt(
            data = message.toByteArray(Charsets.UTF_8),
            recipientPublicKeys = recipientRings,
            cardSession = cardSession,
            cardPin = cardPin,
            cardSigningPublicKey = cardSigningPublicKey,
            armor = true
        ),
        Charsets.UTF_8
    )

    // ── D3a text-mode crypto (thin wrappers over the vendored engine) ───

    fun encryptText(
        message: String,
        recipientRings: List<PGPPublicKeyRing>,
        signerRing: PGPSecretKeyRing?,
        signerPassphrase: String?
    ): String = crypto.encryptMessage(message, recipientRings, signerRing, signerPassphrase)

    fun encryptTextSymmetric(message: String, passphrase: String): String =
        crypto.encryptSymmetricMessage(message, passphrase)

    /** Decrypt with every held secret ring; all public rings serve as verification keys. */
    suspend fun decryptText(armored: String, passphrase: String?): com.pgpony.android.crypto.DecryptResult {
        val all = allKeys()
        val secretRings = all.filter { it.isKeyPair }.mapNotNull { loadSecretKeyRing(it.fingerprint) }
        val publicRings = all.mapNotNull { loadPublicKeyRing(it.fingerprint) }
        return crypto.decryptArmored(armored, secretRings, passphrase, publicRings)
    }

    // ── Ring loaders (desktop analogs of the Android load*KeyRing) ──────

    suspend fun loadPublicKeyRing(fingerprint: String): PGPPublicKeyRing? =
        exportArmoredPublicKey(fingerprint)
            ?.let { runCatching { crypto.importArmoredKey(it).publicKeyRing }.getOrNull() }

    fun loadSecretKeyRing(fingerprint: String): PGPSecretKeyRing? =
        materials.loadSecret(fingerprint)
            ?.let { runCatching { crypto.importArmoredKey(it).secretKeyRing }.getOrNull() }

    // ── Mutations (D2c — Android KeyRepository update section, ported) ──

    suspend fun setDefaultKey(fingerprint: String) {
        dao.getDefaultKey()?.let { old -> dao.update(old.copy(isDefault = false)) }
        byFingerprint(fingerprint)?.let { key -> dao.update(key.copy(isDefault = true)) }
    }

    suspend fun updateTrustLevel(fingerprint: String, trust: TrustLevel) {
        byFingerprint(fingerprint)?.let { key -> dao.update(key.copy(trustLevel = trust)) }
    }

    suspend fun updateNotes(fingerprint: String, notes: String?) {
        byFingerprint(fingerprint)?.let { key -> dao.update(key.copy(notes = notes)) }
    }

    /**
     * Apply a revocation — the Android applyRevocation sequence: fresh cert with the chosen
     * reason → apply to the public ring → persist ring (material store + entity armor cache) →
     * stamp the entity. Returns the armored cert. Throws RevocationError on crypto failure.
     */
    suspend fun applyRevocation(
        fingerprint: String,
        reason: RevocationReason,
        comment: String?,
        passphrase: String?
    ): String {
        val entity = byFingerprint(fingerprint)
            ?: throw IllegalStateException(tr("d_repo_err_key_not_found", fingerprint))
        if (!entity.isKeyPair) {
            throw RevocationError.UnsupportedKey(
                tr("d_repo_err_revoke_public_only")
            )
        }
        val secRing = loadSecretKeyRing(fingerprint)
            ?: throw RevocationError.UnsupportedKey(tr("d_repo_err_secret_ring_load", fingerprint))
        val pubRing = loadPublicKeyRing(fingerprint)
            ?: throw RevocationError.UnsupportedKey(tr("d_repo_err_public_ring_load", fingerprint))

        val armoredCert = revocation.generateRevocationCertificate(
            secretKeyRing = secRing, reason = reason, comment = comment, passphrase = passphrase
        )
        val revokedRing = revocation.applyRevocation(pubRing, armoredCert)
        val updatedArmored = revocation.armorPublicKeyRing(revokedRing)
        materials.storePublic(fingerprint, updatedArmored)
        dao.update(
            entity.copy(
                armoredPublicKey = updatedArmored,
                isRevoked = true,
                revokedAt = System.currentTimeMillis(),
                revocationReason = reason,
                revocationCertificate = armoredCert
            )
        )
        return armoredCert
    }

    suspend fun exportRevocationCertificate(fingerprint: String): String? =
        byFingerprint(fingerprint)?.revocationCertificate

    /**
     * Change a software key pair's expiration (null = never) — the Android
     * setKeyExpirationSoftware port: re-sign via the vendored KeyExpirationService, persist
     * both rings, stamp entity.expiresAt. Throws KeyExpirationService.ExpirationError.
     */
    suspend fun setKeyExpirationSoftware(
        fingerprint: String,
        expiresAtEpochSeconds: Long?,
        passphrase: String?
    ) {
        val entity = byFingerprint(fingerprint)
            ?: throw IllegalStateException(tr("d_repo_err_key_not_found", fingerprint))
        if (!entity.isKeyPair) {
            throw KeyExpirationService.ExpirationError.UnsupportedKey(
                tr("d_repo_err_expiry_public_only")
            )
        }
        if (entity.isCardBacked) {
            throw KeyExpirationService.ExpirationError.UnsupportedKey(
                tr("d_repo_err_expiry_card")
            )
        }
        val secRing = loadSecretKeyRing(fingerprint)
            ?: throw KeyExpirationService.ExpirationError.UnsupportedKey(
                tr("d_repo_err_secret_ring_load", fingerprint)
            )
        val pubRing = loadPublicKeyRing(fingerprint)
            ?: throw KeyExpirationService.ExpirationError.UnsupportedKey(
                tr("d_repo_err_public_ring_load", fingerprint)
            )

        val updated = keyExpiration.setExpirationSoftware(
            secretRing = secRing,
            publicRing = pubRing,
            expiresAtEpochSeconds = expiresAtEpochSeconds,
            passphrase = passphrase
        )
        materials.storePublic(fingerprint, crypto.exportArmoredPublicKey(updated.publicRing))
        // UpdatedRings.secretRing is nullable (the card path has none) — guard like Android's
        // persistExpiration; the software path always produces one.
        updated.secretRing?.let { materials.storeSecret(fingerprint, crypto.exportArmoredPrivateKey(it)) }
        dao.update(
            entity.copy(
                armoredPublicKey = crypto.exportArmoredPublicKey(updated.publicRing),
                expiresAt = expiresAtEpochSeconds?.let { it * 1000L }
            )
        )
    }

    // ── Export / delete ─────────────────────────────────────────────────

    suspend fun exportArmoredPublicKey(fingerprint: String): String? =
        materials.loadPublic(fingerprint) ?: byFingerprint(fingerprint)?.armoredPublicKey

    /** The user-facing export variant (armor Comment header per settings) — Android's
     *  ForSharing path, reused for copy/share/save surfaces. */
    suspend fun exportArmoredPublicKeyForSharing(fingerprint: String): String? {
        val armor = exportArmoredPublicKey(fingerprint) ?: return null
        val ring = runCatching { crypto.importArmoredKey(armor).publicKeyRing }.getOrNull()
            ?: return armor
        return runCatching { crypto.exportArmoredPublicKeyForSharing(ring) }.getOrDefault(armor)
    }

    fun exportArmoredPrivateKey(fingerprint: String): String? = materials.loadSecret(fingerprint)

    /** issue #2 symptom D: export a composite secret in GnuPG's native format
     *  so gpg 2.5.x / GPG4WIN can import it. [exportPassphrase] both unlocks a
     *  protected source and, when non-blank, AES-128-OCB protects the export. */
    fun exportArmoredPrivateKeyGpgCompat(fingerprint: String, exportPassphrase: String?): String? {
        val armor = materials.loadSecret(fingerprint) ?: return null
        val ring = runCatching { crypto.importArmoredKey(armor).secretKeyRing }.getOrNull() ?: return null
        val source = if (crypto.isPassphraseProtected(ring)) exportPassphrase else null
        val protect = exportPassphrase?.takeIf { it.isNotBlank() }
        return runCatching { crypto.exportArmoredPrivateKeyGpgCompat(ring, source, protect) }.getOrNull()
    }

    // ── Key detail (D2b read view) ──────────────────────────────────────

    data class SubkeyInfo(
        val isPrimary: Boolean,
        val keyIdHex: String,
        val fingerprintHex: String,
        val algorithmLabel: String,
        val capabilitiesLabel: String,
        val createdAtMs: Long,
        val expiresAtMs: Long?
    )

    /**
     * Parse the stored public armor into per-key rows (primary first) using the same vendored
     * helpers Android's key detail relies on: detectAlgorithm, SubkeyCapability (self-sig key
     * flags with heuristic fallback), fingerprintHex.
     */
    suspend fun subkeyInfos(fingerprint: String): List<SubkeyInfo> {
        val armor = exportArmoredPublicKey(fingerprint) ?: return emptyList()
        val ring = runCatching { crypto.importArmoredKey(armor).publicKeyRing }.getOrNull()
            ?: return emptyList()
        val infos = mutableListOf<SubkeyInfo>()
        for (pubKey in ring.publicKeys) {
            val algo = crypto.detectAlgorithm(pubKey)
            val capsBits = SubkeyCapability.fromPgpPublicKey(pubKey, algo, pubKey.isMasterKey)
            val createdMs = pubKey.creationTime.time
            val expiresMs = pubKey.validSeconds.takeIf { it > 0 }?.let { createdMs + it * 1000L }
            infos += SubkeyInfo(
                isPrimary = pubKey.isMasterKey,
                keyIdHex = String.format("%016X", pubKey.keyID),
                fingerprintHex = crypto.fingerprintHex(pubKey),
                algorithmLabel = algo.displayName,
                capabilitiesLabel = SubkeyCapability.displayString(capsBits),
                createdAtMs = createdMs,
                expiresAtMs = expiresMs
            )
        }
        return infos.sortedByDescending { it.isPrimary }
    }

    suspend fun deleteByFingerprint(fingerprint: String) {
        byFingerprint(fingerprint)?.let { dao.delete(it) }
        materials.delete(fingerprint)
    }

    // ── D1 → D2a store migration ────────────────────────────────────────

    /**
     * One-shot import of the D1 bootstrap store (keyring.json: metadata + full armored blocks).
     * On success the file is renamed *.migrated so this never runs twice. Returns null when
     * there was nothing to migrate.
     */
    suspend fun migrateLegacyJson(file: Path): ImportReport? {
        if (!Files.exists(file)) return null
        val entries = runCatching {
            Json { ignoreUnknownKeys = true }
                .decodeFromString<List<LegacyJsonKey>>(Files.readString(file))
        }.getOrElse { return null }
        if (entries.isEmpty()) {
            Files.move(file, file.resolveSibling(file.fileName.toString() + ".migrated"),
                StandardCopyOption.REPLACE_EXISTING)
            return null
        }
        val report = importBlocks(entries.map { it.armored })
        Files.move(file, file.resolveSibling(file.fileName.toString() + ".migrated"),
            StandardCopyOption.REPLACE_EXISTING)
        return report
    }

    @Serializable
    private data class LegacyJsonKey(val fingerprint: String, val armored: String)

    companion object {
        /** Split concatenated armored blocks; tolerant of surrounding prose (e.g. email bodies). */
        fun splitArmoredBlocks(text: String): List<String> {
            val begin = Regex("-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----")
            val blocks = mutableListOf<String>()
            var searchFrom = 0
            while (true) {
                val start = begin.find(text, searchFrom) ?: break
                val endMarker = "-----END PGP ${start.groupValues[1]} KEY BLOCK-----"
                val end = text.indexOf(endMarker, start.range.first)
                if (end < 0) break
                blocks += text.substring(start.range.first, end + endMarker.length)
                searchFrom = end + endMarker.length
            }
            return blocks
        }
    }
}
