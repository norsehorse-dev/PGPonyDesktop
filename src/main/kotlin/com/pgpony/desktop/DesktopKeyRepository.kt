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

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.CertificateMerge
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.KeyExpirationService
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.RevocationError
import com.pgpony.android.crypto.RevocationService
import com.pgpony.android.crypto.SubkeyCapability
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.V4Algo35Recipient
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.RemovedUserIdStore
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.TrustLevel
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.UUID

/** Mirrors the Android ImportResolution vocabulary (card pairing arrives D7). */
/** 3.0.0: a selected recipient gave no key to encrypt to. The operation stops; nothing is
 *  encrypted to the others (Android 4.6.1, #67). The message names every such key. */
class RecipientLoadException(val keys: List<String>) :
    Exception(tr("d_err_recipient_unusable", keys.joinToString(", ")))

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
    internal val db: PGPDatabase,
    internal val materials: KeyMaterialStore,
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
        if (algorithm.isCompositeSign) {
            return generateCompositeSigningKey(name, email, algorithm, passphrase, expirationSeconds)
        }
        // 3.0.0 (Android item 14, #56): the v4 Ed25519 + algo-35 interop shape takes the raw path.
        if (algorithm == KeyAlgorithm.MLKEM768_X25519_V4) {
            return generateV4Algo35Key(name, email, passphrase, expirationSeconds)
        }
        val result = crypto.generateKeyPair(name, email, algorithm, passphrase, expirationSeconds)

        materials.storePublic(result.fingerprint, result.armoredPublicKey)
        materials.storeSecret(result.fingerprint, result.armoredPrivateKey)

        val importResult = crypto.importKeyData(result.publicKeyData)
        val masterKey = importResult.publicKeyRing?.publicKey
        val expiresAtMs = masterKey?.let { key ->
            val validSec = key.validSeconds
            if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
        }

        // Android 4.1.0 Phase 12a: parse the BINARY secret ring, not the armor, which is not always
        // the framing BouncyCastle produced (v5 composite rings go through the LibrePGP exporter).
        val preCachedRevocationCert: String? = try {
            runCatching { crypto.importKeyData(result.privateKeyData).secretKeyRing }.getOrNull()?.let { secRing ->
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

        // 3.0.0 (Android 4.5.0 item 3): the email is optional, so a name-only User ID.
        val uid = PGPKeyEntity.composeUserID(name, email)
        val parsed = PGPKeyEntity.parseUserID(uid)
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = result.fingerprint,
            userID = uid,
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

    /**
     * Composite ML-DSA signing keygen (P2c; the desktop port of the Android
     * KeyRepository.generateCompositeSigningKey). BouncyCastle cannot build or sign with a
     * composite primary, so the key is assembled, described, and stored via the raw-bytes
     * composite path and kept as ASCII armor at rest like every other desktop key.
     */
    private suspend fun generateCompositeSigningKey(
        name: String,
        email: String,
        algorithm: KeyAlgorithm,
        passphrase: String?,
        expirationSeconds: Long?
    ): PGPKeyEntity {
        val suite = if (algorithm == KeyAlgorithm.MLDSA87_ED448_V6)
            CompositeSignSuite.MLDSA87_ED448 else CompositeSignSuite.MLDSA65_ED25519
        val uid = PGPKeyEntity.composeUserID(name, email)
        var secretRing = CompositePrimaryKeyGen.assemble(uid, suite, expirationSeconds = expirationSeconds)
        if (!passphrase.isNullOrEmpty()) {
            secretRing = CompositeKeyFacade.reprotect(secretRing, null, passphrase.toCharArray())
        }
        val publicRing = CompositeKeyFacade.publicRingOf(secretRing)
        val info = CompositeKeyFacade.parse(secretRing)
        val fingerprintHex = info.fingerprintHex.uppercase()

        val armoredPublic = CompositeSigPacket.armor(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----", publicRing
        )
        val armoredSecret = CompositeSigPacket.armor(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", secretRing
        )
        materials.storePublic(fingerprintHex, armoredPublic)
        materials.storeSecret(fingerprintHex, armoredSecret)

        val expiresAtMs = info.expirationSeconds?.let { info.creationTimeMillis + it * 1000 }
        val parsed = PGPKeyEntity.parseUserID(uid)
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = fingerprintHex,
            userID = uid,
            userName = parsed.first,
            userEmail = parsed.second,
            algorithm = algorithm,
            isKeyPair = true,
            createdAt = System.currentTimeMillis(),
            expiresAt = expiresAtMs,
            armoredPublicKey = armoredPublic,
            revocationCertificate = null
        )
        dao.insert(entity)
        return entity
    }

    /**
     * 3.0.0 (Android item 14, #56): a v4 Ed25519 + algo-35 ML-KEM-768+X25519 interop key. The v4
     * base keeps a classical Cv25519 subkey for older senders and advertises SEIPDv2, then the
     * algo-35 subkey is grafted on. BouncyCastle cannot parse that subkey, so the key is stored as
     * raw octets like the composite signing keys.
     */
    private suspend fun generateV4Algo35Key(
        name: String,
        email: String,
        passphrase: String?,
        expirationSeconds: Long?
    ): PGPKeyEntity {
        val uid = PGPKeyEntity.composeUserID(name, email)
        val baseRing = crypto.buildV4InteropBaseSecretRing(uid, passphrase, expirationSeconds = expirationSeconds)
        val rings = com.pgpony.android.crypto.pqc.CompositeKeyGen.addV4Algo35SubkeyRings(
            baseRing, passphrase, expirationSeconds = expirationSeconds
        )
        val fingerprintHex = rings.primaryFingerprintHex.uppercase()
        val armoredPublic = CompositeSigPacket.armor(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----", rings.publicRaw
        )
        materials.storePublic(fingerprintHex, armoredPublic)
        materials.storeSecret(
            fingerprintHex,
            CompositeSigPacket.armor("-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", rings.secretRaw)
        )
        val parsed = PGPKeyEntity.parseUserID(uid)
        val now = System.currentTimeMillis()
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = fingerprintHex,
            userID = uid,
            userName = parsed.first,
            userEmail = parsed.second,
            algorithm = KeyAlgorithm.MLKEM768_X25519_V4,
            isKeyPair = true,
            createdAt = now,
            expiresAt = expirationSeconds?.let { now + it * 1000 },
            armoredPublicKey = armoredPublic,
            revocationCertificate = null
        )
        dao.insert(entity)
        return entity
    }

    /**
     * 3.0.0 (Android 4.5.0 item 7, #55): granular keygen. A v6 Ed25519 primary, its default
     * X25519 encryption subkey kept or stripped, then each chosen subkey grafted on. Every shape
     * stays a BouncyCastle ring, so it is stored like any v6 key and labelled V6_ED25519.
     */
    suspend fun generateGranularKey(
        name: String,
        email: String,
        includeDefaultEncryptionSubkey: Boolean,
        subkeys: List<com.pgpony.android.crypto.GranularSubkeySpec>,
        passphrase: String?,
        expirationSeconds: Long? = null
    ): PGPKeyEntity {
        val uid = PGPKeyEntity.composeUserID(name, email)
        val ring = crypto.assembleGranularV6Ring(
            userID = uid,
            includeDefaultEncryptionSubkey = includeDefaultEncryptionSubkey,
            subkeys = subkeys,
            passphrase = passphrase,
            expirationSeconds = expirationSeconds
        )
        val publicRing = PGPPublicKeyRing(ring.publicKeys.asSequence().toList())
        val primary = publicRing.publicKey
        val fpHex = primary.fingerprint.joinToString("") { "%02X".format(it) }
        val armoredPublic = crypto.exportArmoredPublicKey(publicRing)
        materials.storePublic(fpHex, armoredPublic)
        materials.storeSecret(
            fpHex,
            CompositeSigPacket.armor("-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", ring.encoded)
        )
        val validSec = primary.validSeconds
        val parsed = PGPKeyEntity.parseUserID(uid)
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = fpHex,
            userID = uid,
            userName = parsed.first,
            userEmail = parsed.second,
            algorithm = KeyAlgorithm.V6_ED25519,
            isKeyPair = true,
            createdAt = System.currentTimeMillis(),
            expiresAt = if (validSec > 0) primary.creationTime.time + validSec * 1000 else null,
            armoredPublicKey = armoredPublic,
            revocationCertificate = runCatching {
                revocation.generateRevocationCertificate(ring, RevocationReason.NO_REASON, null, passphrase)
            }.getOrNull()
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
        // 3.0.0: a BINARY composite ML-DSA or v4 algo-35 key cannot go through BouncyCastle's
        // explode; armor it as-is and take the raw-octet import path.
        val looksArmored = data.take(64).toByteArray().toString(Charsets.ISO_8859_1).contains("-----BEGIN PGP")
        if (!looksArmored && runCatching {
                CompositeKeyFacade.isCompositePrimary(data) || CompositeKeyFacade.hasV4Algo35Subkey(data)
            }.getOrDefault(false)
        ) {
            val header = if (CompositeKeyFacade.hasSecret(data)) "PRIVATE" else "PUBLIC"
            return importBlocks(
                listOf(
                    CompositeSigPacket.armor(
                        "-----BEGIN PGP $header KEY BLOCK-----", "-----END PGP $header KEY BLOCK-----", data
                    )
                )
            )
        }
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
        // 3.0.0 (Android 4.4.0 RC3 #30/#31 and 4.5.0 item 14 #56): composite ML-DSA keys and v4
        // Ed25519 + algo-35 interop keys are not BouncyCastle rings. They are recognized first
        // and stored as raw octets, exactly as Android does; everything else falls through to
        // the BouncyCastle path below. Before 3.0.0 desktop sent them down that path, which
        // failed on a composite key and silently dropped the algo-35 subkey of a v4 key.
        compositeFromArmored(block)?.let { (bytes, info) ->
            val expiresAt = info.expirationSeconds?.let { info.creationTimeMillis + it * 1000 }
            return importRawKey(
                bytes = bytes,
                publicBytes = CompositeKeyFacade.publicRingOf(bytes),
                fingerprint = info.fingerprintHex.uppercase(),
                userId = info.userIds.firstOrNull() ?: "",
                algorithm = if (info.primaryAlgId == 31) KeyAlgorithm.MLDSA87_ED448_V6 else KeyAlgorithm.MLDSA65_ED25519_V6,
                createdAt = info.creationTimeMillis,
                expiresAt = expiresAt
            )
        }
        v4Algo35FromArmored(block)?.let { bytes ->
            val meta = v4Algo35Meta(bytes) ?: return ImportResolution.FAILED
            return importRawKey(
                bytes = bytes,
                publicBytes = CompositeKeyFacade.v4Algo35PublicRingOf(bytes),
                fingerprint = meta.fingerprintHex,
                userId = meta.userId,
                algorithm = KeyAlgorithm.MLKEM768_X25519_V4,
                createdAt = meta.createdAtMs,
                expiresAt = meta.expiresAtMs
            )
        }
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

    // ── Raw-octet key types (composite ML-DSA, v4 algo-35), Android KeyRepository ported ──

    private fun compositeFromArmored(armoredText: String): Pair<ByteArray, CompositeKeyFacade.Info>? =
        try {
            // Android 4.6.0 (item 17.1): only components the primary verifiably bound.
            val bytes = CertificateBindings.sanitized(CompositeSigPacket.dearmor(armoredText))
            if (CompositeKeyFacade.isCompositePrimary(bytes)) bytes to CompositeKeyFacade.parse(bytes) else null
        } catch (_: Exception) { null }

    private fun v4Algo35FromArmored(armoredText: String): ByteArray? =
        try {
            val bytes = CertificateBindings.sanitized(CompositeSigPacket.dearmor(armoredText))
            if (CompositeKeyFacade.hasV4Algo35Subkey(bytes) && !CompositeKeyFacade.isCompositePrimary(bytes)) bytes
            else null
        } catch (_: Exception) { null }

    private data class V4Algo35Meta(
        val fingerprintHex: String,
        val userId: String,
        val createdAtMs: Long,
        val expiresAtMs: Long?
    )

    private fun v4Algo35Meta(bytes: ByteArray): V4Algo35Meta? {
        return try {
            // BouncyCastle cannot parse the algo-35 subkey, so read the primary from the
            // packets before it (public or secret).
            val base = CompositeKeyFacade.v4Algo35BaseBytes(bytes) ?: return null
            val pubKey = if (CompositeKeyFacade.hasSecret(bytes)) {
                PGPSecretKeyRing(base, BcKeyFingerprintCalculator()).publicKey
            } else {
                PGPPublicKeyRing(base, BcKeyFingerprintCalculator()).publicKey
            }
            val fpHex = pubKey.fingerprint.joinToString("") { "%02X".format(it) }
            val uid = pubKey.userIDs.asSequence().firstOrNull() ?: ""
            val createdMs = pubKey.creationTime.time
            val valid = pubKey.validSeconds
            V4Algo35Meta(fpHex, uid, createdMs, if (valid > 0) createdMs + valid * 1000 else null)
        } catch (_: Exception) { null }
    }

    /** Store a raw-octet key (armored at rest like every desktop key) and resolve it against
     *  the keyring: insert, upgrade a public-only row to a key pair, or already present. */
    private suspend fun importRawKey(
        bytes: ByteArray,
        publicBytes: ByteArray,
        fingerprint: String,
        userId: String,
        algorithm: KeyAlgorithm,
        createdAt: Long,
        expiresAt: Long?
    ): ImportResolution {
        val hasPrivate = CompositeKeyFacade.hasSecret(bytes)
        val armoredPublic = CompositeSigPacket.armor(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----", publicBytes
        )
        val armoredSecret = if (hasPrivate) CompositeSigPacket.armor(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", bytes
        ) else null
        val existing = byFingerprint(fingerprint)
        if (existing != null) {
            if (hasPrivate && !existing.isKeyPair) {
                materials.storePublic(existing.fingerprint, armoredPublic)
                materials.storeSecret(existing.fingerprint, armoredSecret!!)
                dao.update(existing.copy(isKeyPair = true, armoredPublicKey = armoredPublic))
                return ImportResolution.UPGRADED_TO_KEY_PAIR
            }
            return ImportResolution.ALREADY_IN_KEYRING
        }
        materials.storePublic(fingerprint, armoredPublic)
        armoredSecret?.let { materials.storeSecret(fingerprint, it) }
        val parsed = PGPKeyEntity.parseUserID(userId)
        dao.insert(
            PGPKeyEntity(
                id = UUID.randomUUID().toString(),
                fingerprint = fingerprint,
                userID = userId,
                userName = parsed.first,
                userEmail = parsed.second,
                algorithm = algorithm,
                isKeyPair = hasPrivate,
                createdAt = createdAt,
                expiresAt = expiresAt,
                armoredPublicKey = armoredPublic
            )
        )
        return ImportResolution.INSERTED
    }

    /**
     * The re-import and refresh merge, ported from Android 4.6.0
     * (KeyDeduplicationService.resolveDuplicate, items 17.1, 12 and 24).
     *
     * The stored copy is no longer joined with whatever arrived. The result is
     * CertificateMerge's verified union of the two sanitized copies, so a server can neither
     * add a component the owner never bound nor drop one they did:
     *   * public-only keys keep everything stored and gain new subkeys, new User IDs (unless
     *     the user removed them, RemovedUserIdStore) and new signatures;
     *   * the user's own key pairs are authoritative: a fetched copy adds only revocations and
     *     third-party certifications, never User IDs, subkeys, self-signatures or expiry.
     * A fetched copy that would remove or shorten a primary expiry the row already has is
     * refused (the item 24 guard), unless it carries a revocation the row does not have yet:
     * a revocation always lands. Trust, notes, secret material and card backing survive
     * because only armoredPublicKey, expiresAt and the revocation flags change.
     */
    private suspend fun mergeIfNewMaterial(
        existing: PGPKeyEntity,
        incomingRing: PGPPublicKeyRing?
    ): ImportResolution {
        if (incomingRing == null) return ImportResolution.ALREADY_IN_KEYRING
        // The merge runs on the stored OCTETS, not a BouncyCastle ring: a v4 key's algo-35
        // subkey does not survive a BouncyCastle round trip, and must survive a refresh.
        val stored = rawPublicBytes(existing.fingerprint)
        if (stored == null) {
            // D7 Fix: the row exists but holds NO public material yet: a card-backed row from
            // pairing (or the moment after on-card keygen). This IS the arrival of its public
            // certificate, so store it (in its verified form) rather than no-op'ing to
            // ALREADY_IN_KEYRING, which left the card key unusable as a recipient / verify key.
            val clean = runCatching {
                PGPPublicKeyRing(CertificateBindings.sanitized(incomingRing.encoded), BcKeyFingerprintCalculator())
            }.getOrNull() ?: incomingRing
            val armor = crypto.exportArmoredPublicKey(clean)
            materials.storePublic(existing.fingerprint, armor)
            val nowRevoked = runCatching { clean.publicKey.hasRevocation() }.getOrDefault(false)
            dao.update(
                existing.copy(
                    armoredPublicKey = armor,
                    expiresAt = primaryExpiry(clean),
                    isRevoked = existing.isRevoked || nowRevoked,
                    revokedAt = if (!existing.isRevoked && nowRevoked) System.currentTimeMillis() else existing.revokedAt
                )
            )
            return ImportResolution.MERGED_NEW_MATERIAL
        }
        // Composite ML-DSA primaries do not round-trip the BouncyCastle refresh path (Android
        // makes the same exception); they keep what is stored.
        if (CompositeKeyFacade.isCompositePrimary(stored)) return ImportResolution.ALREADY_IN_KEYRING
        if (stored.contentEquals(incomingRing.encoded)) return ImportResolution.ALREADY_IN_KEYRING
        val merged = CertificateMerge.merge(
            stored = stored,
            fetched = incomingRing.encoded,
            isKeyPair = existing.isKeyPair,
            removedUserIds = RemovedUserIdStore.removed(existing.fingerprint)
        )
        if (merged.contentEquals(stored) || merged.contentEquals(CertificateBindings.sanitized(stored))) {
            return ImportResolution.ALREADY_IN_KEYRING
        }
        val mergedRing = runCatching { PGPPublicKeyRing(merged, BcKeyFingerprintCalculator()) }
            .getOrNull() ?: return ImportResolution.ALREADY_IN_KEYRING
        val nowRevoked = runCatching { mergedRing.publicKey.hasRevocation() }.getOrDefault(false)
        val newlyRevoked = nowRevoked && !existing.isRevoked
        // The expiry the fetched copy asserts. Taken from the INCOMING ring's primary, not the
        // union (D4 Fix1): BC's getValidSeconds picks the newest self-sig with a strict > on
        // creation time, so a re-sign in the same second as the original ties and the union can
        // report the stale value.
        val fetchedExpiresAt = primaryExpiry(incomingRing)
        val downgrade = isExpiryDowngrade(existing.expiresAt, fetchedExpiresAt)
        if (downgrade && !newlyRevoked) return ImportResolution.ALREADY_IN_KEYRING
        val expiresAt = if (existing.isKeyPair || downgrade) existing.expiresAt else fetchedExpiresAt
        // Armor the merged octets as they are, so packets BouncyCastle would drop are kept.
        val mergedArmor = CompositeSigPacket.armor(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----", merged
        )
        materials.storePublic(existing.fingerprint, mergedArmor)
        dao.update(
            existing.copy(
                armoredPublicKey = mergedArmor,
                expiresAt = expiresAt,
                isRevoked = existing.isRevoked || nowRevoked,
                revokedAt = if (newlyRevoked) System.currentTimeMillis() else existing.revokedAt
            )
        )
        return ImportResolution.MERGED_NEW_MATERIAL
    }

    private fun primaryExpiry(ring: PGPPublicKeyRing): Long? = ring.publicKey?.let { k ->
        k.validSeconds.takeIf { it > 0 }?.let { k.creationTime.time + it * 1000L }
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
    /**
     * 3.0.0 (Android 4.6.0 item 9): what goes to the key servers, or why not. A key whose live
     * User IDs carry more than one primary flag, or whose flagged primary is not the one shown
     * here, would publish under a name its owner does not expect; the publish dialog says so and
     * points at Make Primary.
     */
    sealed class PublishPayload {
        data class Ready(val armored: String) : PublishPayload()
        data class NeedsRepair(val flagged: List<String>, val shown: String) : PublishPayload()
        object Unavailable : PublishPayload()
    }

    suspend fun publishPayload(fingerprint: String, shownUserId: String): PublishPayload {
        val armored = exportArmoredPublicKey(fingerprint) ?: return PublishPayload.Unavailable
        // Composite ML-DSA keys are not BouncyCastle rings; there is nothing further to check.
        val primary = loadPublicKeyRing(fingerprint)?.publicKey ?: return PublishPayload.Ready(armored)
        val flagged = com.pgpony.android.crypto.UserIdService.shared.primaryFlaggedLiveUserIds(primary)
        val ok = when (flagged.size) {
            0 -> true
            1 -> flagged[0] == shownUserId
            else -> false
        }
        return if (ok) PublishPayload.Ready(armored) else PublishPayload.NeedsRepair(flagged, shownUserId)
    }

    /** The addresses of the key's certified User IDs, for the per-server confirmation lines. */
    suspend fun publishedAddresses(fingerprint: String): List<String> =
        rawPublicBytes(fingerprint)
            ?.let { CertificateBindings.analyze(it)?.certifiedUserIds }
            ?.map { CertificateBindings.mailboxOf(it) }
            ?.filter { it.contains('@') }
            ?.distinct()
            .orEmpty()

    /** 3.0.0 (Android 4.6.0 item 9): [markKeyServerUploaded] plus the per-server record. */
    suspend fun markKeyServerUploaded(fingerprint: String, serverId: String) {
        com.pgpony.android.data.KeyPublicationStore.record(fingerprint, serverId)
        markKeyServerUploaded(fingerprint)
    }

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
        cardSigningPublicKey: org.bouncycastle.openpgp.PGPPublicKey,
        v4Algo35Recipients: List<V4Algo35Recipient> = emptyList()
    ): String = String(
        crypto.encrypt(
            data = message.toByteArray(Charsets.UTF_8),
            recipientPublicKeys = recipientRings,
            v4Algo35Recipients = v4Algo35Recipients,
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

    /**
     * Decrypt with the held secret rings in DecryptOrder (3.0.0, plan 3.7): [selected] first, its
     * fallbacks, then the rest unless strict. All public rings serve as verification keys.
     */
    suspend fun decryptText(
        armored: String,
        passphrase: String?,
        selected: String? = null
    ): com.pgpony.android.crypto.DecryptResult {
        val k = decryptKeys(selected)
        return DecryptOrder.cascade(k.secretRings) { rings ->
            crypto.decryptArmored(armored, rings, passphrase, k.verificationRings, k.compositeRings)
        }
    }

    /**
     * The keys a decrypt tries, in order (Android fallbackOrderedKeys, #34): [selected], then
     * its enabled fallbacks, then every other key pair unless the selected key is strict.
     */
    suspend fun decryptKeys(selected: String? = null): DecryptKeys {
        val all = allKeys()
        val available = all.filter { it.isKeyPair }
        val fallbacks = selected?.let { fp -> db.fallbackKeyDao().fallbacksFor(fp).map { it.fallbackFingerprint } }.orEmpty()
        val strict = selected != null && com.pgpony.android.crypto.FallbackPrefs.isStrict(selected)
        val ordered = DecryptOrder.ordered(selected, available, fallbacks, strict)
        return DecryptKeys(
            keys = ordered,
            secretRings = ordered.mapNotNull { secretRingForDecrypt(it) },
            compositeRings = ordered.mapNotNull { compositeDecryptRing(it) },
            verificationRings = all.mapNotNull { loadPublicKeyRing(it.fingerprint) }
        )
    }

    /**
     * The BouncyCastle ring a decrypt tries for [e] (Android 4.6.0 item 21). A composite ML-DSA
     * key is not a BouncyCastle ring; its ML-KEM subkey goes through [compositeDecryptRing] and
     * its classical encryption subkeys (an RSA or X25519 subkey added for other clients) come
     * as a separate ring here. Before 3.0.0 desktop could not open mail sent to those.
     */
    fun secretRingForDecrypt(e: PGPKeyEntity): PGPSecretKeyRing? =
        loadSecretKeyRing(e.fingerprint)
            ?: if (e.algorithm.isCompositeSign) loadCompositeClassicalDecryptionRing(e.fingerprint) else null

    /**
     * 3.0.0 (plan section 5, Android 4.6.0 item 16): the secret ring holding an SSH
     * authentication subkey: the ordinary ring, or for a composite ML-DSA primary the carrier
     * ring of its classical subkeys.
     */
    fun loadSshAuthSecretRing(fingerprint: String): PGPSecretKeyRing? =
        loadSecretKeyRing(fingerprint) ?: rawSecretBytes(fingerprint)
            ?.takeIf { CompositeKeyFacade.isCompositePrimary(it) && CompositeKeyFacade.hasSecret(it) }
            ?.let { runCatching { CompositeKeyFacade.classicalAuthRing(it) }.getOrNull() }

    /** What Key Detail shows for SSH: the authorized_keys line and its SHA256 fingerprint. */
    data class SshPublicKey(val line: String, val fingerprint: String)

    /**
     * The key's SSH public key (Android KeyDetailViewModel.deriveSshPublicKey): its newest
     * dedicated authentication subkey as an authorized_keys line, the email (else the name) as
     * the comment. Null when it has none.
     */
    suspend fun sshPublicKey(entity: PGPKeyEntity): SshPublicKey? = runCatching {
        val cert = rawPublicBytes(entity.fingerprint) ?: return@runCatching null
        val sub = com.pgpony.android.crypto.ssh.SshAuth.authSubkey(cert) ?: return@runCatching null
        val m = com.pgpony.android.crypto.ssh.SshAuth.material(sub.publicBody) ?: return@runCatching null
        SshPublicKey(
            com.pgpony.android.crypto.ssh.SshAuth.authorizedKeysLine(m, entity.userEmail.ifBlank { entity.userName }),
            com.pgpony.android.crypto.ssh.SshAuth.sshFingerprint(m)
        )
    }.getOrNull()

    /** True when the key has Authenticate subkeys but every one can also sign or certify. */
    suspend fun sshOnlyDualUse(entity: PGPKeyEntity): Boolean = runCatching {
        rawPublicBytes(entity.fingerprint)?.let { com.pgpony.android.crypto.ssh.SshAuth.onlyDualUseAuthSubkeys(it) } ?: false
    }.getOrDefault(false)

    /** Android KeyRepository.loadCompositeClassicalDecryptionRing. */
    fun loadCompositeClassicalDecryptionRing(fingerprint: String): PGPSecretKeyRing? =
        rawSecretBytes(fingerprint)
            ?.takeIf { CompositeKeyFacade.isCompositePrimary(it) && CompositeKeyFacade.hasSecret(it) }
            ?.let { runCatching { CompositeKeyFacade.classicalDecryptionRing(it) }.getOrNull() }

    /** Android loadCompositePrivateRing: a composite primary with secret material, or a v4
     *  interop key (decrypt matches its 20-octet algo-35 subkey fingerprint). */
    fun compositeDecryptRing(e: PGPKeyEntity): ByteArray? =
        rawSecretBytes(e.fingerprint)?.takeIf { raw ->
            (CompositeKeyFacade.isCompositePrimary(raw) && CompositeKeyFacade.hasSecret(raw)) ||
                CompositeKeyFacade.hasV4Algo35Subkey(raw)
        }

    /**
     * Android #46: when a decrypt with [selected] failed, say which of the two usual cases it
     * was. The selected key is not a recipient (no recipient key ID is one of its keys, and no
     * recipient is hidden), or it is and the passphrase was wrong. Anything else, or a key
     * whose key IDs cannot be read here (composite, v4 algo-35), keeps [error].
     */
    suspend fun explainDecryptFailure(
        recipientKeyIds: () -> List<Long>,
        selected: String?,
        error: Throwable
    ): Throwable {
        val entity = selected?.let { byFingerprint(it) } ?: return error
        val label = entity.userName.ifBlank { entity.userEmail }.ifBlank { entity.shortFingerprint }
        val recipients = runCatching { recipientKeyIds() }.getOrDefault(emptyList())
        val ring = loadPublicKeyRing(entity.fingerprint)
        if (ring != null && recipients.isNotEmpty() && 0L !in recipients) {
            val ids = ring.publicKeys.asSequence().map { it.keyID }.toSet()
            if (recipients.none { it in ids }) {
                return IllegalStateException(tr("encdec_error_selected_key_not_recipient_format", label), error)
            }
        }
        if (error is com.pgpony.android.crypto.PGPCryptoError.InvalidPassphrase ||
            error is com.pgpony.android.crypto.PGPCryptoError.PassphraseRequired
        ) {
            return IllegalStateException(tr("encdec_error_incorrect_passphrase_for_format", label), error)
        }
        return error
    }

    /**
     * 3.0.0 (plan 3.8): the key that signs when [base] would, after [base]'s signing defaults
     * (SigningDefaults.pick).
     */
    suspend fun signerAfterDefaults(base: PGPKeyEntity, recipients: List<PGPKeyEntity>, signOnly: Boolean): PGPKeyEntity =
        SigningDefaults.pick(base, db.signingDefaultsDao().forKey(base.fingerprint), recipients, signOnly, allKeys())

    /**
     * The keyring row whose primary OR any subkey has the 64-bit key id [keyIdHex] (16 hex).
     * Signatures name the signing subkey, which is usually not the primary.
     */
    suspend fun findByKeyId(keyIdHex: String): PGPKeyEntity? {
        val id = keyIdHex.trim()
        val all = allKeys()
        all.firstOrNull { it.longKeyId.equals(id, ignoreCase = true) }?.let { return it }
        all.firstOrNull { it.fingerprint.endsWith(id, ignoreCase = true) }?.let { return it }
        val wanted = runCatching { java.lang.Long.parseUnsignedLong(id, 16) }.getOrNull() ?: return null
        for (e in all) {
            val ring = loadPublicKeyRing(e.fingerprint) ?: continue
            if (ring.publicKeys.asSequence().any { it.keyID == wanted }) return e
        }
        return null
    }

    // ── Ring loaders (desktop analogs of the Android load*KeyRing) ──────

    suspend fun loadPublicKeyRing(fingerprint: String): PGPPublicKeyRing? =
        exportArmoredPublicKey(fingerprint)
            ?.let { runCatching { crypto.importArmoredKey(it).publicKeyRing }.getOrNull() }

    /**
     * The public key ring to encrypt TO for a recipient (4.4.1, #36; the desktop
     * twin of the Android KeyRepository.loadEncryptionRecipientRing). Normal keys
     * and standalone ML-KEM keys load through loadPublicKeyRing. A composite ML-DSA
     * signing key cannot (BouncyCastle rejects its algo-30/31 primary), yet it
     * carries an ML-KEM encryption subkey; that subkey is lifted out via
     * CompositeKeyFacade and returned as a bare ring. Returns null only when the key
     * truly has no encryption subkey to receive a message.
     */
    suspend fun loadEncryptionRecipientRing(fingerprint: String): PGPPublicKeyRing? {
        loadPublicKeyRing(fingerprint)?.let { return it }
        val raw = rawPublicBytes(fingerprint) ?: return null
        return CompositeKeyFacade.encryptionSubkeyRing(raw)
    }

    internal suspend fun rawPublicBytes(fingerprint: String): ByteArray? {
        val armored = exportArmoredPublicKey(fingerprint) ?: return null
        return runCatching { CompositeSigPacket.dearmor(armored) }.getOrNull()
    }

    /**
     * Parse a composite ML-DSA key's public material (P2a). BouncyCastle cannot load a
     * composite primary, so the key is stored armored and parsed here via CompositeKeyFacade.
     * Null for a non-composite or unreadable key.
     */
    suspend fun loadCompositePublicInfo(fingerprint: String): CompositeKeyFacade.Info? {
        val raw = rawPublicBytes(fingerprint) ?: return null
        return runCatching { CompositeKeyFacade.parse(raw) }.getOrNull()
    }

    internal fun rawSecretBytes(fingerprint: String): ByteArray? {
        val armored = materials.loadSecret(fingerprint) ?: return null
        return runCatching { CompositeSigPacket.dearmor(armored) }.getOrNull()
    }

    /**
     * Composite ML-DSA key metadata + secret material from the stored SECRET half (P2b).
     * Threads [passphrase] into CompositeKeyFacade.parse: a wrong passphrase propagates (the
     * sign path shows it as an error), a locked key with no passphrase yields Info with a null
     * compositeSecret. Null when there is no stored secret for this key.
     */
    fun loadCompositeKeyInfo(fingerprint: String, passphrase: CharArray? = null): CompositeKeyFacade.Info? {
        val raw = rawSecretBytes(fingerprint) ?: return null
        return CompositeKeyFacade.parse(raw, passphrase)
    }

    /**
     * Raw (still passphrase-protected) secret rings of held composite ML-DSA key pairs (P2d).
     * A composite signing key carries an ML-KEM encryption subkey, so a message can be encrypted
     * to it; the message-decrypt path passes these to PGPCryptoService, which trials the subkey
     * packet-level (BouncyCastle cannot load the composite primary) and unlocks with the passphrase.
     */
    suspend fun compositePrimarySecretRings(): List<ByteArray> =
        allKeys().filter { it.isKeyPair }.mapNotNull { compositeDecryptRing(it) }

    fun loadSecretKeyRing(fingerprint: String): PGPSecretKeyRing? {
        val armored = materials.loadSecret(fingerprint) ?: return null
        runCatching { crypto.importArmoredKey(armored).secretKeyRing }.getOrNull()?.let { return it }
        // Android item 7 (#55): a v4 interop key carries an algo-35 subkey BouncyCastle cannot
        // parse, so the whole ring fails to load. Fall back to the BouncyCastle-parseable base
        // ring (Ed25519 primary + any classical subkey) so signing and classical decrypt still
        // work; the algo-35 subkey is opened through the raw paths (decryptionRawRings).
        val raw = runCatching { CompositeSigPacket.dearmor(armored) }.getOrNull() ?: return null
        if (!CompositeKeyFacade.hasV4Algo35Subkey(raw)) return null
        val base = CompositeKeyFacade.v4Algo35BaseBytes(raw) ?: return null
        return runCatching { PGPSecretKeyRing(base, BcKeyFingerprintCalculator()) }.getOrNull()
    }

    /**
     * 3.0.0: a v4 Ed25519 + algo-35 recipient's encryption material (Android
     * KeyRepository.loadV4Algo35Recipient, 4.5.0 item 14 / 4.6.0 item 17.1). Such a key is not a
     * BouncyCastle ring, so the encrypt paths carry it on the v4Algo35Recipients channel. The
     * newest algo-35 subkey the primary bound with a verified, unrevoked, unexpired binding,
     * under a usable primary. Null when the stored key has no such subkey.
     */
    suspend fun loadV4Algo35Recipient(fingerprint: String): V4Algo35Recipient? {
        val raw = rawPublicBytes(fingerprint) ?: return null
        if (!CompositeKeyFacade.hasV4Algo35Subkey(raw) || CompositeKeyFacade.isCompositePrimary(raw)) return null
        val bindings = CertificateBindings.analyze(raw) ?: return null
        val now = System.currentTimeMillis()
        val subBody = CompositeKeyFacade.v4Algo35SubkeyBodies(raw).lastOrNull { body ->
            if (!bindings.supported) return@lastOrNull true
            val fpHex = org.bouncycastle.util.encoders.Hex.toHexString(CompositeKeyFacade.v4Algo35SubkeyFingerprint(body))
            bindings.isUsableEncryptionKey(fpHex, now)
        } ?: return null
        return V4Algo35Recipient(
            CompositeKeyFacade.v4Algo35PublicMaterial(subBody),
            CompositeKeyFacade.v4Algo35SubkeyFingerprint(subBody)
        )
    }

    /** What an encrypt site gets for its selected recipients (Android ShareRecipients.Loaded). */
    class LoadedRecipients(
        val rings: List<PGPPublicKeyRing>,
        val v4Algo35: List<V4Algo35Recipient>,
        /** Selected fingerprints that gave no encryption key at all. */
        val unusable: List<String>
    ) {
        val isComplete: Boolean get() = unusable.isEmpty()
    }

    /**
     * 3.0.0: the ONE recipient loader every desktop encrypt site uses (GUI text and files,
     * folders, MIME bundles, watch folders, the CLI). A v4 algo-35 key goes on its own channel;
     * everything else loads through loadEncryptionRecipientRing, which also reaches a composite
     * ML-DSA key's ML-KEM subkey. The rule from Android 4.6.1 (#67): a selected recipient that
     * cannot be loaded stops the operation and is named; it is never dropped.
     */
    suspend fun loadRecipients(fingerprints: Collection<String>): LoadedRecipients {
        val rings = mutableListOf<PGPPublicKeyRing>()
        val v4 = mutableListOf<V4Algo35Recipient>()
        val unusable = mutableListOf<String>()
        for (fp in fingerprints) {
            loadV4Algo35Recipient(fp)?.let { v4.add(it); continue }
            val r = loadEncryptionRecipientRing(fp)
            if (r != null) rings.add(r) else unusable.add(fp)
        }
        return LoadedRecipients(rings, v4, unusable)
    }

    /** [loadRecipients], failing closed with an error that names every unusable key. */
    suspend fun requireRecipients(fingerprints: Collection<String>): LoadedRecipients {
        val loaded = loadRecipients(fingerprints)
        if (!loaded.isComplete) {
            val names = loaded.unusable.map { fp ->
                byFingerprint(fp)?.let { it.userID.ifBlank { it.shortFingerprint } } ?: fp.take(16)
            }
            throw RecipientLoadException(names)
        }
        return loaded
    }

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
        // 3.0.0 (Android 4.6.0 item 19): carry a v4 ML-KEM subkey BouncyCastle cannot see.
        val updatedArmored = storeCarriedPublic(fingerprint, revokedRing.encoded)
        dao.update(
            entity.copy(
                armoredPublicKey = updatedArmored,
                lastLocalEditAt = System.currentTimeMillis(),
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
        // 3.0.0 (Android 4.6.0 item 19 follow-up): new bindings for any v4 ML-KEM subkey are made
        // FIRST, so a failure leaves the stored key untouched; then everything is stored with the
        // ML-KEM subkey carried over and its binding replaced.
        val v4Bindings = v4Algo35Bindings(fingerprint, secRing, passphrase, expiresAtEpochSeconds)
        val armor = storeCarriedPublic(fingerprint, updated.publicRing.encoded)
        // UpdatedRings.secretRing is nullable (the card path has none); guard like Android's
        // persistExpiration. The software path always produces one.
        updated.secretRing?.let { storeCarriedSecret(fingerprint, it.encoded) }
        dao.update(
            entity.copy(
                armoredPublicKey = armor,
                expiresAt = expiresAtEpochSeconds?.let { it * 1000L },
                lastLocalEditAt = System.currentTimeMillis()
            )
        )
        if (v4Bindings.isNotEmpty()) {
            DesktopKeyEdits(this).applyV4Algo35Edits(fingerprint) { raw ->
                v4Bindings.fold(raw) { acc, (body, sig) ->
                    com.pgpony.android.crypto.pqc.V4Algo35Edit.edit(acc, body, replaceBinding = sig)
                }
            }
        }
    }

    private suspend fun v4Algo35Bindings(
        fingerprint: String,
        secRing: PGPSecretKeyRing,
        passphrase: String?,
        expiresAtEpochSeconds: Long?
    ): List<Pair<ByteArray, ByteArray>> {
        val raw = rawPublicBytes(fingerprint) ?: return emptyList()
        val bodies = com.pgpony.android.crypto.pqc.V4Algo35Edit.publicBodies(raw)
        if (bodies.isEmpty()) return emptyList()
        val priv = try {
            secRing.secretKey.extractPrivateKey(
                org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder(
                    org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider()
                ).build((passphrase ?: "").toCharArray())
            )
        } catch (e: org.bouncycastle.openpgp.PGPException) {
            throw if (passphrase.isNullOrEmpty()) KeyExpirationService.ExpirationError.PassphraseRequired()
            else KeyExpirationService.ExpirationError.InvalidPassphrase()
        }
        return bodies.map { body ->
            body to com.pgpony.android.crypto.pqc.V4Algo35Edit.binding(secRing, priv, body, expiresAtEpochSeconds)
        }
    }

    /** Store edited public octets armored as-is, carrying a v4 ML-KEM subkey. Returns the armor. */
    private suspend fun storeCarriedPublic(fingerprint: String, bytes: ByteArray): String {
        val armor = CompositeSigPacket.armor(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----",
            com.pgpony.android.crypto.pqc.V4Algo35Carry.carry(rawPublicBytes(fingerprint), bytes)
        )
        materials.storePublic(fingerprint, armor)
        return armor
    }

    private fun storeCarriedSecret(fingerprint: String, bytes: ByteArray) {
        materials.storeSecret(
            fingerprint,
            CompositeSigPacket.armor(
                "-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----",
                com.pgpony.android.crypto.pqc.V4Algo35Carry.carry(rawSecretBytes(fingerprint), bytes)
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
        // A composite or v4 algo-35 key would lose packets in a BouncyCastle round trip; share
        // the stored armor as it is.
        val raw = runCatching { CompositeSigPacket.dearmor(armor) }.getOrNull()
        if (raw != null && (CompositeKeyFacade.isCompositePrimary(raw) || CompositeKeyFacade.hasV4Algo35Subkey(raw))) {
            return armor
        }
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
        /** Android KeyDeduplicationService.isExpiryDowngrade (item 24): a fetched copy that
         *  removes (null) or shortens a primary expiry the row already has. */
        internal fun isExpiryDowngrade(existingExpiresAtMs: Long?, fetchedExpiresAtMs: Long?): Boolean {
            val existing = existingExpiresAtMs ?: return false
            return fetchedExpiresAtMs == null || fetchedExpiresAtMs < existing
        }

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
