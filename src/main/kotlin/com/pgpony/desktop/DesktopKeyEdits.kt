// DesktopKeyEdits.kt
// PGPony Desktop 3.0.0, stage 2: the key-management mutations Android shipped in 4.2.0 through
// 4.6.0, ported from PGPonyAndroid's KeyRepository (which is excluded from the vendor build, see
// vendor/README.md). The engine calls are the vendored ones (UserIdService, RevocationService,
// ClassicalSubkeyGen, CompositePrimaryKeyGen, CompositeKeyFacade, V4Algo35Edit, V4Algo35Carry);
// what lives here is the storage and the rules around them.
//
// Desktop storage differences from Android:
//   * key material is armored at rest (KeyMaterialStore), so every write armors the octets as
//     they are (CompositeSigPacket.armor), never through a BouncyCastle re-encode, which would
//     drop packets it cannot parse (a v4 algo-35 subkey);
//   * V4Algo35Carry is applied on every edit of a classical key (Android 4.6.0 item 19), so a v4
//     ML-KEM subkey survives User ID, expiry, passphrase and revocation edits.
// Every mutation stamps lastLocalEditAt (Android 4.6.0 item 11), which drives the stage 3
// "published copy is out of date" marker.

package com.pgpony.desktop

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.RevocationError
import com.pgpony.android.crypto.RevocationService
import com.pgpony.android.crypto.SubkeyCapability
import com.pgpony.android.crypto.UserIdService
import com.pgpony.android.crypto.V6SubkeyGen
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositeKeyGen
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.crypto.pqc.CompositeSignSubkeyGen
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import com.pgpony.android.crypto.pqc.V4Algo35Carry
import com.pgpony.android.crypto.pqc.V4Algo35Edit
import com.pgpony.android.data.FallbackKeyEntity
import com.pgpony.android.data.KeyPublicationStore
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.RemovedUserIdStore
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.SigningDefaultsEntity
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing

/** A key edit refused before anything was written. The message is user-facing. */
open class KeyEditException(message: String) : Exception(message)

/** Taking out [subkeyFingerprint] would leave the key unable to receive mail. The UI confirms,
 *  then retries with allowLastEncryptionSubkey = true (Android item 16, #54). */
class LastEncryptionSubkeyException(val subkeyFingerprint: String) :
    KeyEditException(tr("d_edit_err_last_encryption_subkey"))

class DesktopKeyEdits(private val repo: DesktopKeyRepository) {

    private val crypto = PGPCryptoService.shared
    private val revocation = RevocationService.shared
    private val userIds = UserIdService.shared
    private val dao get() = repo.db.keyDao()
    private val fallbackDao get() = repo.db.fallbackKeyDao()
    private val signingDefaultsDao get() = repo.db.signingDefaultsDao()

    // ── Storage helpers ─────────────────────────────────────────────────

    private fun armorPublic(raw: ByteArray) =
        CompositeSigPacket.armor("-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----", raw)

    private fun armorPrivate(raw: ByteArray) =
        CompositeSigPacket.armor("-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", raw)

    /** Store edited public octets, carrying a v4 ML-KEM subkey BouncyCastle dropped. Returns the armor. */
    private suspend fun storeEditedPublic(fingerprint: String, bytes: ByteArray): String {
        val armor = armorPublic(V4Algo35Carry.carry(repo.rawPublicBytes(fingerprint), bytes))
        repo.materials.storePublic(fingerprint, armor)
        return armor
    }

    private fun storeEditedSecret(fingerprint: String, bytes: ByteArray, reprotect: ((ByteArray) -> ByteArray)? = null) {
        repo.materials.storeSecret(fingerprint, armorPrivate(V4Algo35Carry.carry(repo.rawSecretBytes(fingerprint), bytes, reprotect)))
    }

    private suspend fun stampLocalEdit(fingerprint: String) {
        repo.byFingerprint(fingerprint)?.let { dao.update(it.copy(lastLocalEditAt = System.currentTimeMillis())) }
    }

    private suspend fun requireOwnSoftwareKey(fingerprint: String): PGPKeyEntity {
        val entity = repo.byFingerprint(fingerprint)
            ?: throw KeyEditException(tr("d_repo_err_key_not_found", fingerprint))
        if (!entity.isKeyPair) throw KeyEditException(tr("d_edit_err_public_only"))
        if (entity.isCardBacked) throw KeyEditException(tr("d_edit_err_card"))
        return entity
    }

    private fun secretRing(fingerprint: String): PGPSecretKeyRing =
        repo.loadSecretKeyRing(fingerprint)
            ?: throw KeyEditException(tr("d_repo_err_secret_ring_load", fingerprint))

    private suspend fun publicRing(fingerprint: String): PGPPublicKeyRing =
        repo.loadPublicKeyRing(fingerprint)
            ?: throw KeyEditException(tr("d_repo_err_public_ring_load", fingerprint))

    // ── Recently Deleted (Android 4.3.0 / 4.6.0, #36 #58) ───────────────

    /** Move a key to Recently Deleted. Material and related rows stay, so a restore is lossless;
     *  the DAO clears the default flag. */
    suspend fun softDelete(fingerprint: String) {
        repo.byFingerprint(fingerprint)?.let { dao.softDelete(it.id, System.currentTimeMillis()) }
        PassphraseCache.clear(fingerprint)
    }

    suspend fun deletedKeys(): List<PGPKeyEntity> = dao.getDeletedKeys()
    suspend fun deletedCount(): Int = dao.deletedCount()
    suspend fun restore(id: String) = dao.restoreFromBin(id)

    /** Destroy a binned key for good: material, related rows, the row itself. */
    suspend fun purge(entity: PGPKeyEntity) {
        RemovedUserIdStore.clear(entity.fingerprint)
        KeyPublicationStore.clear(entity.fingerprint)
        repo.materials.delete(entity.fingerprint)
        fallbackDao.deleteAllReferencing(entity.fingerprint)
        signingDefaultsDao.deleteFor(entity.fingerprint)
        dao.purgeById(entity.id)
    }

    suspend fun emptyBin() = deletedKeys().forEach { purge(it) }

    /** Purge keys binned longer than the retention window. Returns how many. */
    suspend fun purgeExpiredDeleted(nowMs: Long = System.currentTimeMillis()): Int {
        val cutoff = nowMs - RETENTION_DAYS * DAY_MS
        val expired = deletedKeys().filter { (it.deletedAt ?: 0L) < cutoff }
        expired.forEach { purge(it) }
        return expired.size
    }

    /** Whole days left before a binned key is destroyed (Android 4.7.0 item 4); 0 = under a day. */
    fun daysLeft(entity: PGPKeyEntity, nowMs: Long = System.currentTimeMillis()): Int {
        val deletedAt = entity.deletedAt ?: return RETENTION_DAYS
        val left = deletedAt + RETENTION_DAYS * DAY_MS - nowMs
        return if (left <= 0) 0 else (left / DAY_MS).toInt()
    }

    /** Clear All Data, database half (Android 4.2.0 RC5, plan 3.2): every key, live or in Recently
     *  Deleted, with its material and related rows, then the Autocrypt peer and API client tables.
     *  Settings and the files beside the database are ClearAllData's. */
    suspend fun purgeEverything() {
        // The DAO's purge only deletes rows already in the bin, so live keys go there first.
        val now = System.currentTimeMillis()
        repo.allKeys().forEach { dao.softDelete(it.id, now) }
        deletedKeys().forEach { purge(it) }
        repo.db.autocryptPeerDao().clear()
        val clients = repo.db.apiClientDao()
        clients.getAll().forEach { clients.deleteByPackage(it.packageName) }
    }

    // ── Last backed up (Android 4.3.0) ──────────────────────────────────

    suspend fun markBackedUp(fingerprints: Collection<String>, atMs: Long = System.currentTimeMillis()) {
        fingerprints.forEach { dao.setLastBackedUp(it, atMs) }
    }

    // ── Fallback decryption keys and signing defaults (Android 4.2.0, #34 #22) ──

    suspend fun fallbacksFor(primary: String): List<String> =
        fallbackDao.fallbacksFor(primary).map { it.fallbackFingerprint }

    suspend fun setFallbacks(primary: String, fingerprints: List<String>) {
        fallbackDao.clearFor(primary)
        if (fingerprints.isNotEmpty()) {
            fallbackDao.insertAll(fingerprints.mapIndexed { i, fp -> FallbackKeyEntity(primary, fp, i) })
        }
    }

    suspend fun signingDefaultsFor(fingerprint: String): SigningDefaultsEntity? = signingDefaultsDao.forKey(fingerprint)
    suspend fun setSigningDefaults(row: SigningDefaultsEntity) = signingDefaultsDao.upsert(row)

    // ── Passphrase (Android 4.3.0 §1.1, #26) ────────────────────────────

    /**
     * Set, change or remove a key's passphrase ([oldPassphrase] / [newPassphrase] empty = none).
     * A wrong old passphrase throws from the engine and nothing is written. Card-backed keys use
     * the card PIN instead and are refused. The key's remembered passphrase (PassphraseCache)
     * is dropped, so nothing keeps unlocking with the old one.
     */
    suspend fun changePassphrase(fingerprint: String, oldPassphrase: String, newPassphrase: String) {
        requireOwnSoftwareKey(fingerprint)
        val oldChars = oldPassphrase.ifEmpty { null }?.toCharArray()
        val newChars = newPassphrase.ifEmpty { null }?.toCharArray()
        val raw = repo.rawSecretBytes(fingerprint)
        if (raw != null && CompositeKeyFacade.isCompositePrimary(raw)) {
            val reprotected = CompositeKeyFacade.reprotect(raw, oldChars, newChars)
            repo.materials.storeSecret(fingerprint, armorPrivate(reprotected))
        } else {
            val ring = secretRing(fingerprint)
            val changed = crypto.changePassphrase(ring, oldPassphrase, newPassphrase)
            // Android 4.6.0 (item 19): a v4 ML-KEM subkey is re-protected with the rest of the key.
            storeEditedSecret(fingerprint, changed.encoded) { body ->
                V4Algo35Carry.reprotectBody(body, oldChars, newChars)
            }
        }
        PassphraseCache.clear(fingerprint)
        stampLocalEdit(fingerprint)
    }

    fun isPassphraseProtected(fingerprint: String): Boolean {
        val raw = repo.rawSecretBytes(fingerprint) ?: return false
        if (CompositeKeyFacade.isCompositePrimary(raw)) return CompositeKeyFacade.isProtected(raw)
        val ring = repo.loadSecretKeyRing(fingerprint) ?: return false
        return crypto.isPassphraseProtected(ring)
    }

    // ── User IDs (Android 4.2.0 #29, 4.5.0 #55, 4.5.1) ─────────────────

    data class UserIdRow(val raw: String, val isPrimary: Boolean, val isRevoked: Boolean)

    /** Every User ID on the key, primary first-flagged, read from the stored key. */
    suspend fun userIdRows(entity: PGPKeyEntity): List<UserIdRow> {
        if (entity.algorithm.isCompositeSign) {
            val uids = repo.loadCompositePublicInfo(entity.fingerprint)?.userIds.orEmpty()
            if (uids.isNotEmpty()) return uids.mapIndexed { i, u -> UserIdRow(u, i == 0, false) }
        }
        val primary: PGPPublicKey? = repo.loadPublicKeyRing(entity.fingerprint)?.publicKey
        val raws = primary?.userIDs?.asSequence()?.filter { it.isNotEmpty() }?.toList().orEmpty()
        if (raws.isEmpty()) return listOf(UserIdRow(entity.userID, true, false))
        val primaryUid = userIds.currentPrimaryUserId(primary!!)
        val primaryIndex = raws.indexOf(primaryUid).let { if (it >= 0) it else 0 }
        return raws.mapIndexed { i, u -> UserIdRow(u, i == primaryIndex, userIds.isRevoked(primary, u)) }
    }

    /** Add a User ID. A non-primary addition pins the original as primary (Android 4.5.0: a fresh
     *  key's first UID is only implicitly primary, so the newer self-signature won on upload). */
    suspend fun addUserId(fingerprint: String, userId: String, makePrimary: Boolean, passphrase: String?) {
        val entity = requireOwnSoftwareKey(fingerprint)
        RemovedUserIdStore.forget(fingerprint, userId)
        if (entity.algorithm.isCompositeSign) {
            val raw = repo.rawSecretBytes(fingerprint)
                ?: throw KeyEditException(tr("d_repo_err_secret_ring_load", fingerprint))
            val pass = passphrase?.takeIf { it.isNotEmpty() }?.toCharArray()
            val updated = CompositePrimaryKeyGen.addUserId(raw, userId, pass)
            val restored = if (pass != null) CompositeKeyFacade.reprotect(updated, null, pass) else updated
            storeCompositeEdit(entity, restored)
        } else {
            val result = userIds.addUserId(secretRing(fingerprint), publicRing(fingerprint), userId, makePrimary, passphrase)
            persistUserIdChange(entity, result, newPrimaryUserId = if (makePrimary) userId else null)
        }
        stampLocalEdit(fingerprint)
    }

    suspend fun revokeUserId(fingerprint: String, userId: String, reason: RevocationReason, comment: String?, passphrase: String?) {
        val entity = requireOwnSoftwareKey(fingerprint)
        val result = userIds.revokeUserId(secretRing(fingerprint), publicRing(fingerprint), userId, reason, comment, passphrase)
        persistUserIdChange(entity, result, newPrimaryUserId = null)
        stampLocalEdit(fingerprint)
    }

    /** Remove a User ID locally (no signature), with a tombstone so a key-server refresh cannot
     *  bring it back (Android 4.5.1). To retire it for other people, revoke it instead. */
    suspend fun removeUserId(fingerprint: String, userId: String) {
        val entity = requireOwnSoftwareKey(fingerprint)
        val removedWasCached = userId == entity.userID
        if (entity.algorithm.isCompositeSign) {
            val raw = repo.rawSecretBytes(fingerprint)
                ?: throw KeyEditException(tr("d_repo_err_secret_ring_load", fingerprint))
            val updated = CompositePrimaryKeyGen.removeUserId(raw, userId)
            val newPrimary = if (removedWasCached) CompositeKeyFacade.parse(updated).userIds.firstOrNull() else null
            storeCompositeEdit(entity, updated, newPrimary)
        } else {
            val result = userIds.removeUserId(secretRing(fingerprint), publicRing(fingerprint), userId)
            val newPrimary = if (removedWasCached) result.publicRing.publicKey.userIDs.asSequence().firstOrNull() else null
            persistUserIdChange(entity, result, newPrimary)
        }
        RemovedUserIdStore.addRemoved(fingerprint, userId)
        stampLocalEdit(fingerprint)
    }

    suspend fun setPrimaryUserId(fingerprint: String, userId: String, passphrase: String?) {
        val entity = requireOwnSoftwareKey(fingerprint)
        val result = userIds.setPrimaryUserId(secretRing(fingerprint), publicRing(fingerprint), userId, passphrase)
        persistUserIdChange(entity, result, newPrimaryUserId = userId)
        stampLocalEdit(fingerprint)
    }

    // ── Notations (Android 4.3.0 §5.6.7) ────────────────────────────────

    suspend fun readNotations(fingerprint: String): List<UserIdService.Notation> =
        repo.loadPublicKeyRing(fingerprint)?.let { userIds.readNotations(it.publicKey) } ?: emptyList()

    suspend fun setNotations(fingerprint: String, notations: List<UserIdService.Notation>, passphrase: String?) {
        val entity = requireOwnSoftwareKey(fingerprint)
        val result = userIds.setNotations(secretRing(fingerprint), publicRing(fingerprint), notations, passphrase)
        persistUserIdChange(entity, result, newPrimaryUserId = null)
        stampLocalEdit(fingerprint)
    }

    private suspend fun persistUserIdChange(entity: PGPKeyEntity, updated: UserIdService.UpdatedRings, newPrimaryUserId: String?) {
        val armor = storeEditedPublic(entity.fingerprint, updated.publicRing.encoded)
        storeEditedSecret(entity.fingerprint, updated.secretRing.encoded)
        val parsed = newPrimaryUserId?.let { PGPKeyEntity.parseUserID(it) }
        dao.update(
            entity.copy(
                armoredPublicKey = armor,
                userID = newPrimaryUserId ?: entity.userID,
                userName = parsed?.first ?: entity.userName,
                userEmail = parsed?.second ?: entity.userEmail
            )
        )
    }

    private suspend fun storeCompositeEdit(entity: PGPKeyEntity, secretRaw: ByteArray, newPrimaryUserId: String? = null) {
        val publicRaw = CompositeKeyFacade.publicRingOf(secretRaw)
        val armor = armorPublic(publicRaw)
        repo.materials.storeSecret(entity.fingerprint, armorPrivate(secretRaw))
        repo.materials.storePublic(entity.fingerprint, armor)
        val parsed = newPrimaryUserId?.let { PGPKeyEntity.parseUserID(it) }
        dao.update(
            entity.copy(
                armoredPublicKey = armor,
                userID = newPrimaryUserId ?: entity.userID,
                userName = parsed?.first ?: entity.userName,
                userEmail = parsed?.second ?: entity.userEmail
            )
        )
    }

    // ── Add subkey (Android 4.2.0 RC3 H, 4.5.0 item 7 #55, 4.6.0 items 16 and 21) ──

    /** Add the subkey kind the Add Subkey dialog picked, then stamp lastLocalEditAt. */
    suspend fun addSubkey(fingerprint: String, choice: AddSubkeyChoice, expirationSeconds: Long?, passphrase: String?) {
        when (choice) {
            is AddSubkeyChoice.Classical -> addClassicalSubkeyEdit(fingerprint, choice.type, expirationSeconds, passphrase)
            is AddSubkeyChoice.PqEncryption -> addPqEncryptionSubkeyEdit(fingerprint, choice.suite, expirationSeconds, passphrase)
            is AddSubkeyChoice.PqSigning -> addPqSigningSubkeyEdit(fingerprint, choice.suite, expirationSeconds, passphrase)
        }
        stampLocalEdit(fingerprint)
    }

    /** Keygen's SSH authentication subkey (Android 4.6.0 item 16): the same edit without the
     *  local-edit stamp, since a brand-new key has nothing published to fall behind. An RSA key
     *  gets an RSA subkey of the same size, every other key Ed25519. */
    suspend fun addSshAuthSubkeyAtGeneration(
        fingerprint: String,
        algorithm: KeyAlgorithm,
        expirationSeconds: Long?,
        passphrase: String?
    ) = addClassicalSubkeyEdit(fingerprint, ClassicalSubkeyGen.sshAuthTypeFor(algorithm), expirationSeconds, passphrase)

    private suspend fun addClassicalSubkeyEdit(
        fingerprint: String,
        type: ClassicalSubkeyGen.ClassicalSubkeyType,
        expirationSeconds: Long?,
        passphrase: String?
    ) {
        val entity = requireOwnSoftwareKey(fingerprint)
        if (entity.algorithm.isCompositeSign) {
            storeCompositeSubkeyEdit(entity, passphrase) { raw, pass ->
                CompositePrimaryKeyGen.addClassicalSubkey(raw, type, expirationSeconds, pass)
            }
            return
        }
        val secRing = secretRing(fingerprint)
        // A v6 primary needs a v6 binding signature, which ClassicalSubkeyGen (v4) cannot emit.
        val updated = if (entity.isV6Key) {
            val v6Type = when (type) {
                ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN -> V6SubkeyGen.V6SubkeyType.ED25519_SIGN
                ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT -> V6SubkeyGen.V6SubkeyType.X25519_ENCRYPT
                ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH -> V6SubkeyGen.V6SubkeyType.ED25519_AUTH
                else -> throw KeyEditException(tr("d_edit_err_v6_subkey_type"))
            }
            V6SubkeyGen.addSubkey(secRing, v6Type, passphrase, expirationSeconds)
        } else {
            ClassicalSubkeyGen.addSubkey(
                secretRing = secRing,
                type = type,
                passphrase = passphrase,
                expirationSeconds = expirationSeconds
            )
        }
        storeRingEdit(entity, updated)
    }

    /** ML-KEM encryption subkey. v6 keeps a BouncyCastle-parseable ring; v4 takes the RFC 9980
     *  algo-35 shape, converts to raw-octet storage and relabels as MLKEM768_X25519_V4. */
    private suspend fun addPqEncryptionSubkeyEdit(
        fingerprint: String,
        suite: CompositeSuite,
        expirationSeconds: Long?,
        passphrase: String?
    ) {
        val entity = requireOwnSoftwareKey(fingerprint)
        if (entity.algorithm.isCompositeSign) {
            storeCompositeSubkeyEdit(entity, passphrase) { raw, pass ->
                CompositePrimaryKeyGen.addCompositeEncryptionSubkey(raw, suite, expirationSeconds, pass)
            }
            return
        }
        val secRing = secretRing(fingerprint)
        if (entity.isV6Key) {
            storeRingEdit(
                entity,
                CompositeKeyGen.addCompositeSubkey(
                    secretRing = secRing,
                    suite = suite,
                    passphrase = passphrase,
                    expirationSeconds = expirationSeconds
                )
            )
            return
        }
        if (suite.ietfAlgId != 35) throw KeyEditException(tr("d_edit_err_v4_mlkem768_only"))
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(
            baseSecretRing = secRing,
            passphrase = passphrase,
            expirationSeconds = expirationSeconds
        )
        // Android 4.6.0 (item 19): the carry keeps an earlier ML-KEM subkey beside the new one.
        val armor = storeEditedPublic(fingerprint, rings.publicRaw)
        storeEditedSecret(fingerprint, rings.secretRaw)
        dao.update(entity.copy(algorithm = KeyAlgorithm.MLKEM768_X25519_V4, armoredPublicKey = armor))
    }

    /** ML-DSA + EdDSA signing subkey (algo 30/31). v6 primaries only. */
    private suspend fun addPqSigningSubkeyEdit(
        fingerprint: String,
        suite: CompositeSignSuite,
        expirationSeconds: Long?,
        passphrase: String?
    ) {
        val entity = requireOwnSoftwareKey(fingerprint)
        if (!entity.isV6Key) throw KeyEditException(tr("d_edit_err_pq_sign_needs_v6"))
        if (entity.algorithm.isCompositeSign) {
            storeCompositeSubkeyEdit(entity, passphrase) { raw, pass ->
                CompositePrimaryKeyGen.addCompositeSigningSubkey(raw, suite, expirationSeconds, pass)
            }
            return
        }
        storeRingEdit(
            entity,
            CompositeSignSubkeyGen.addCompositeSigningSubkey(
                secretRing = secretRing(fingerprint),
                suite = suite,
                passphrase = passphrase,
                expirationSeconds = expirationSeconds
            )
        )
    }

    private suspend fun storeRingEdit(entity: PGPKeyEntity, updatedSecretRing: PGPSecretKeyRing) {
        val updatedPublicRing = PGPPublicKeyRing(updatedSecretRing.publicKeys.asSequence().toList())
        val armor = storeEditedPublic(entity.fingerprint, updatedPublicRing.encoded)
        storeEditedSecret(entity.fingerprint, updatedSecretRing.encoded)
        dao.update(entity.copy(armoredPublicKey = armor))
    }

    /** Composite ML-DSA primaries are not BouncyCastle rings (#55): edit the raw octets. */
    private suspend fun storeCompositeSubkeyEdit(
        entity: PGPKeyEntity,
        passphrase: String?,
        edit: (ByteArray, CharArray?) -> ByteArray
    ) {
        val raw = repo.rawSecretBytes(entity.fingerprint)
            ?: throw KeyEditException(tr("d_repo_err_secret_ring_load", entity.fingerprint))
        val pass = passphrase?.takeIf { it.isNotEmpty() }?.toCharArray()
        val updated = edit(raw, pass)
        val restored = if (pass != null) CompositeKeyFacade.reprotect(updated, pass, pass) else updated
        storeCompositeEdit(entity, restored)
    }

    // ── Subkeys: list, revoke, remove (Android 4.5.0 item 16 #54, 4.6.0 item 19) ──

    data class SubkeyRow(
        val fingerprint: String,
        val keyId: String,
        val algorithmLabel: String,
        val capabilities: Int,
        val createdAt: Long,
        val expiresAt: Long?,
        val isRevoked: Boolean
    )

    /**
     * The key's subkeys, read so every kind shows: composite ML-DSA keys from CompositeKeyFacade,
     * any key carrying a composite ML-KEM subkey from its certificate (CertificateBindings, the
     * Android SubkeyRows logic), everything else through BouncyCastle. Before 3.0.0 desktop showed
     * no subkeys for a composite key and dropped a v4 key's ML-KEM subkey.
     */
    suspend fun subkeyRows(entity: PGPKeyEntity): List<SubkeyRow> {
        val raw = repo.rawPublicBytes(entity.fingerprint) ?: return emptyList()
        if (entity.algorithm.isCompositeSign || CompositeKeyFacade.isCompositePrimary(raw)) {
            return runCatching { CompositeKeyFacade.listSubkeys(raw) }.getOrDefault(emptyList()).map { d ->
                val fp = d.fingerprintHex.uppercase()
                val caps = if (d.keyFlags != 0) SubkeyCapability.fromBcKeyFlags(d.keyFlags) else fallbackCaps(d.algId)
                SubkeyRow(fp, fp.take(16), algoLabel(d.algId, null), caps, d.createdAtMillis,
                    d.expirationSeconds?.let { d.createdAtMillis + it * 1000L }, d.isRevoked)
            }
        }
        if (hasCompositeSubkey(raw)) {
            val report = CertificateBindings.analyze(raw)
            if (report != null && report.supported) {
                return report.subkeys.filter { it.bound }.map { st ->
                    val caps = st.keyFlags?.takeIf { it != 0 }?.let { SubkeyCapability.fromBcKeyFlags(it) }
                        ?: fallbackCaps(st.algorithm)
                    SubkeyRow(st.fingerprintHex.uppercase(), String.format("%016X", st.keyId),
                        algoLabel(st.algorithm, st.publicBody.takeIf { st.version == 4 }), caps,
                        st.createdAtMs, st.expiresAtMs, st.revoked)
                }
            }
        }
        val ring = repo.loadPublicKeyRing(entity.fingerprint) ?: return emptyList()
        return ring.publicKeys.asSequence().drop(1).mapNotNull { k ->
            runCatching {
                val algo = crypto.detectAlgorithm(k)
                SubkeyRow(
                    k.fingerprint.joinToString("") { String.format("%02X", it) },
                    String.format("%016X", k.keyID),
                    when (k.algorithm) {
                        org.bouncycastle.bcpg.PublicKeyAlgorithmTags.ECDH -> "X25519"
                        org.bouncycastle.bcpg.PublicKeyAlgorithmTags.EDDSA_LEGACY -> "Ed25519"
                        else -> algo.shortName
                    },
                    SubkeyCapability.fromPgpPublicKey(k, algo, false),
                    k.creationTime.time,
                    k.validSeconds.takeIf { it > 0 }?.let { k.creationTime.time + it * 1000L },
                    k.hasRevocation()
                )
            }.getOrNull()
        }.toList()
    }

    private fun hasCompositeSubkey(raw: ByteArray): Boolean {
        val parsed = CertificateBindings.parse(raw) ?: return false
        return parsed.components.any { c ->
            if (!CertificateBindings.isSubkeyTag(c.tag)) return@any false
            val pub = CertificateBindings.publicPart(c.tag, c.body) ?: return@any false
            val version = pub[0].toInt() and 0xFF
            val algo = pub.getOrNull(if (version in 4..6) 5 else -1)?.toInt()?.and(0xFF) ?: return@any false
            algo == 35 || algo == 36 || (algo == 8 && version == 5)
        }
    }

    private fun fallbackCaps(algo: Int): Int = when (algo) {
        35, 36, 25, 26, 18, 8, 16 -> SubkeyCapability.Encrypt.flag
        30, 31, 27, 28, 22, 19, 17 -> SubkeyCapability.Sign.flag
        else -> 0
    }

    private fun algoLabel(algo: Int, v4Body: ByteArray?): String = when (algo) {
        35 -> "ML-KEM-768 + X25519"
        36 -> "ML-KEM-1024 + X448"
        30 -> "ML-DSA-65 + Ed25519"
        31 -> "ML-DSA-87 + Ed448"
        25, 18 -> "X25519"
        26 -> "X448"
        27, 22 -> "Ed25519"
        28 -> "Ed448"
        19 -> "ECDSA"
        1, 2, 3 -> v4Body?.takeIf { it.size >= 8 }?.let {
            "RSA " + (((it[6].toInt() and 0xFF) shl 8) or (it[7].toInt() and 0xFF))
        } ?: "RSA"
        8 -> "ML-KEM (LibrePGP)"
        else -> "Subkey"
    }

    /** Revoke a subkey (a 0x28 signature by the primary). Correspondents who refresh the key stop
     *  using it; prefer this over [removeSubkey] for a published key. */
    suspend fun revokeSubkey(
        fingerprint: String,
        subkeyFingerprint: String,
        reason: RevocationReason,
        comment: String?,
        passphrase: String?,
        allowLastEncryptionSubkey: Boolean = false
    ) {
        val entity = requireOwnSoftwareKey(fingerprint)
        val targetHex = subkeyFingerprint.uppercase()
        if (targetHex == fingerprint.uppercase()) throw KeyEditException(tr("d_edit_err_primary_as_subkey"))
        if (entity.algorithm.isCompositeSign) {
            if (!allowLastEncryptionSubkey && isLastUsableEncryption(fingerprint, targetHex) != false) {
                throw LastEncryptionSubkeyException(targetHex)
            }
            val raw = repo.rawSecretBytes(fingerprint)
                ?: throw KeyEditException(tr("d_repo_err_secret_ring_load", fingerprint))
            val pass = passphrase?.takeIf { it.isNotEmpty() }?.toCharArray()
            val updated = CompositePrimaryKeyGen.revokeSubkey(
                raw, hexToBytes(targetHex), reasonCode = reason.rfcCode, reasonText = comment.orEmpty(), passphrase = pass
            )
            storeCompositeEdit(entity, if (pass != null) CompositeKeyFacade.reprotect(updated, null, pass) else updated)
            stampLocalEdit(fingerprint)
            return
        }
        val secRing = secretRing(fingerprint)
        val v4Body = repo.rawPublicBytes(fingerprint)?.let { V4Algo35Edit.find(it, targetHex) }
        if (v4Body != null) {
            if (!allowLastEncryptionSubkey && isLastUsableEncryption(fingerprint, targetHex) == true) {
                throw LastEncryptionSubkeyException(targetHex)
            }
            val priv = unlockPrimary(secRing, passphrase)
            val sig = V4Algo35Edit.revocation(secRing, priv, v4Body, reason, comment)
            applyV4Algo35Edits(fingerprint) { V4Algo35Edit.edit(it, v4Body, addSignature = sig) }
            stampLocalEdit(fingerprint)
            return
        }
        val pubRing = publicRing(fingerprint)
        val target = secRing.publicKeys.asSequence().firstOrNull { !it.isMasterKey && fpHex(it) == targetHex }
            ?: throw KeyEditException(tr("d_edit_err_subkey_not_found", targetHex))
        val last = isLastUsableEncryption(fingerprint, targetHex) ?: isLastEncryptionSubkey(pubRing, target.keyID)
        if (!allowLastEncryptionSubkey && last) throw LastEncryptionSubkeyException(targetHex)
        val cert = revocation.generateSubkeyRevocation(secRing, target.keyID, reason, comment, passphrase)
        val updatedPub = revocation.applySubkeyRevocation(pubRing, target.keyID, cert)
        val armor = storeEditedPublic(fingerprint, updatedPub.encoded)
        dao.update(entity.copy(armoredPublicKey = armor))
        stampLocalEdit(fingerprint)
    }

    /** Remove a subkey locally (no revocation). People who already hold the key keep it. */
    suspend fun removeSubkey(fingerprint: String, subkeyFingerprint: String, allowLastEncryptionSubkey: Boolean = false) {
        val entity = requireOwnSoftwareKey(fingerprint)
        val targetHex = subkeyFingerprint.uppercase()
        if (targetHex == fingerprint.uppercase()) throw KeyEditException(tr("d_edit_err_primary_as_subkey"))
        if (entity.algorithm.isCompositeSign) {
            if (!allowLastEncryptionSubkey && isLastUsableEncryption(fingerprint, targetHex) != false) {
                throw LastEncryptionSubkeyException(targetHex)
            }
            val raw = repo.rawSecretBytes(fingerprint)
                ?: throw KeyEditException(tr("d_repo_err_secret_ring_load", fingerprint))
            storeCompositeEdit(entity, CompositePrimaryKeyGen.removeSubkey(raw, hexToBytes(targetHex)))
            stampLocalEdit(fingerprint)
            return
        }
        val v4Body = repo.rawPublicBytes(fingerprint)?.let { V4Algo35Edit.find(it, targetHex) }
        if (v4Body != null) {
            if (!allowLastEncryptionSubkey && isLastUsableEncryption(fingerprint, targetHex) == true) {
                throw LastEncryptionSubkeyException(targetHex)
            }
            applyV4Algo35Edits(fingerprint) { V4Algo35Edit.edit(it, v4Body, remove = true) }
            // The last ML-KEM subkey gone: the key is an ordinary v4 key again.
            val left = repo.rawPublicBytes(fingerprint)
            if (left != null && V4Algo35Edit.publicBodies(left).isEmpty()) {
                runCatching { crypto.importKeyData(left).algorithm }.getOrNull()?.let { algo ->
                    repo.byFingerprint(fingerprint)?.let { dao.update(it.copy(algorithm = algo)) }
                }
            }
            stampLocalEdit(fingerprint)
            return
        }
        val secRing = secretRing(fingerprint)
        val target = secRing.publicKeys.asSequence().firstOrNull { !it.isMasterKey && fpHex(it) == targetHex }
            ?: throw KeyEditException(tr("d_edit_err_subkey_not_found", targetHex))
        val last = isLastUsableEncryption(fingerprint, targetHex)
            ?: isLastEncryptionSubkey(PGPPublicKeyRing(secRing.publicKeys.asSequence().toList()), target.keyID)
        if (!allowLastEncryptionSubkey && last) throw LastEncryptionSubkeyException(targetHex)
        val updatedSec = ClassicalSubkeyGen.removeSubkey(secRing, target.keyID)
        val updatedPub = PGPPublicKeyRing(updatedSec.publicKeys.asSequence().toList())
        storeEditedSecret(fingerprint, updatedSec.encoded)
        val armor = storeEditedPublic(fingerprint, updatedPub.encoded)
        dao.update(entity.copy(armoredPublicKey = armor))
        stampLocalEdit(fingerprint)
    }

    /** Would taking [targetHex] out leave no usable encryption subkey? Read from the stored
     *  certificate (so v4 and composite ML-KEM subkeys count). Null when it cannot be evaluated. */
    private suspend fun isLastUsableEncryption(fingerprint: String, targetHex: String): Boolean? {
        val raw = repo.rawPublicBytes(fingerprint) ?: return null
        val report = CertificateBindings.analyze(raw) ?: return null
        if (!report.supported) return null
        val now = System.currentTimeMillis()
        val usable = report.subkeys.filter { s ->
            s.bound && !s.revoked && (s.expiresAtMs == null || now < s.expiresAtMs) &&
                (s.keyFlags?.let { (it and 0x0C) != 0 } ?: (s.algorithm in ENCRYPTION_ALGORITHMS))
        }.map { it.fingerprintHex.uppercase() }
        return usable.isNotEmpty() && usable.all { it == targetHex }
    }

    private fun isLastEncryptionSubkey(ring: PGPPublicKeyRing, targetKeyId: Long): Boolean {
        val enc = ring.publicKeys.asSequence()
            .filter { !it.isMasterKey && it.isEncryptionKey && !it.hasRevocation() }.map { it.keyID }.toList()
        return enc.isNotEmpty() && enc.all { it == targetKeyId }
    }

    internal fun unlockPrimary(secRing: PGPSecretKeyRing, passphrase: String?): org.bouncycastle.openpgp.PGPPrivateKey = try {
        secRing.secretKey.extractPrivateKey(
            org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
            ).build((passphrase ?: "").toCharArray())
        )
    } catch (e: org.bouncycastle.openpgp.PGPException) {
        throw if (passphrase.isNullOrEmpty()) RevocationError.PassphraseRequired() else RevocationError.InvalidPassphrase()
    }

    /** Apply [transform] to the stored public and secret octets and refresh the cached armor. */
    internal suspend fun applyV4Algo35Edits(fingerprint: String, transform: (ByteArray) -> ByteArray) {
        repo.rawPublicBytes(fingerprint)?.let { repo.materials.storePublic(fingerprint, armorPublic(transform(it))) }
        repo.rawSecretBytes(fingerprint)?.let { repo.materials.storeSecret(fingerprint, armorPrivate(transform(it))) }
        repo.byFingerprint(fingerprint)?.let { e ->
            dao.update(e.copy(armoredPublicKey = repo.exportArmoredPublicKey(fingerprint) ?: e.armoredPublicKey))
        }
    }

    private fun fpHex(k: PGPPublicKey): String = k.fingerprint.joinToString("") { String.format("%02X", it) }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        require(clean.length % 2 == 0) { "odd-length fingerprint hex" }
        return ByteArray(clean.length / 2) {
            ((Character.digit(clean[it * 2], 16) shl 4) + Character.digit(clean[it * 2 + 1], 16)).toByte()
        }
    }

    companion object {
        /** Android KeyRepository.RECYCLE_BIN_RETENTION_DAYS. */
        const val RETENTION_DAYS = 14
        private const val DAY_MS = 24L * 60 * 60 * 1000
        private val ENCRYPTION_ALGORITHMS = setOf(1, 2, 8, 16, 18, 25, 26, 35, 36)
    }
}
