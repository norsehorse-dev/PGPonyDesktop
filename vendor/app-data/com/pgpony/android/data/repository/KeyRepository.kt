// KeyRepository.kt
// PGPony Android
//
// Central repository bridging PGPCryptoService (crypto), SecureKeyStore (key material),
// and PGPKeyDao (Room metadata). This is the single entry point for all key operations.
// ViewModels call this — never the crypto service or storage directly.
//
// Matches iOS pattern: KeychainService + SwiftData model context operations.

package com.pgpony.android.data.repository

import android.content.SharedPreferences
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.KeyExpirationService
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.RevocationError
import com.pgpony.android.crypto.RevocationService
import com.pgpony.android.crypto.card.CardInfo
import com.pgpony.android.data.*
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.util.UUID

sealed class KeyRepoError(message: String) : Exception(message) {
    class AlreadyExists(fp: String) : KeyRepoError("Key $fp already exists in keyring")
    class NotFound(fp: String) : KeyRepoError("Key $fp not found")
    class StorageFailed(msg: String) : KeyRepoError("Storage failed: $msg")
}

data class StoredKey(
    val entity: PGPKeyEntity,
    val publicKeyRing: PGPPublicKeyRing?,
    val secretKeyRing: PGPSecretKeyRing?
)

/**
 * Phase A10a — metadata for the Import preview UI before commit.
 *
 * Populated by [KeyRepository.previewArmoredKey] (in-memory parse,
 * no persistence). The UI displays these fields so the user can
 * verify they're about to import what they intended, then taps
 * Import → [KeyRepository.importArmoredKey] is called with
 * [armoredText] to persist.
 *
 * Field map:
 *   • fingerprint, userId, userName, userEmail — same shape as
 *     PGPKeyEntity for direct UI reuse (KeyCard composable).
 *   • algorithmShortName — string like "Ed25519+Cv25519" / "RSA-4096"
 *     for the preview row. Avoids the UI needing to enum-resolve.
 *   • hasPrivateKey — drives the "Key Pair (Public + Private)" vs
 *     "Public Key Only" header on the preview card.
 *   • isDuplicate — true if a row with this fingerprint already
 *     exists in the keyring.
 *   • willUpgradeToKeyPair — true when isDuplicate AND the existing
 *     row is public-only AND the incoming material includes a
 *     private key. The commit will upgrade rather than fail.
 *   • armoredText — original armor, held so the commit re-parses
 *     the exact same input the user previewed.
 */
data class ImportPreview(
    val fingerprint: String,
    val userId: String,
    val userName: String,
    val userEmail: String,
    val algorithmShortName: String,
    val hasPrivateKey: Boolean,
    val isDuplicate: Boolean,
    val willUpgradeToKeyPair: Boolean,
    /** HW Phase 1.5 — true when the duplicate is an unpaired/paired
     *  card-backed record and this import carries the matching public
     *  key, so confirming will pair the key onto the card record (via
     *  importArmoredKey's card branch) rather than collide. Lets the UI
     *  keep the Import button enabled for the pairing case. */
    val willPairWithCard: Boolean = false,
    val armoredText: String
) {
    /** Last 8 hex chars, uppercased — same convention as PGPKeyEntity.shortFingerprint. */
    val shortFingerprint: String get() = fingerprint.takeLast(8).uppercase()
}

/**
 * 4.0.0 Phase 1 (iOS v7.1.1 F3) — how an import commit resolved.
 * Screens that care (Import sheet's duplicate alert, Contacts and
 * Exchange snackbar copy) read this off [ImportOutcome]; legacy call
 * sites keep using [KeyRepository.importArmoredKey] and just get the
 * entity.
 */
enum class ImportResolution {
    /** No row existed for this fingerprint; a fresh row was inserted. */
    INSERTED,
    /** Private material arrived for an existing public-only row; upgraded in place. */
    UPGRADED_TO_KEY_PAIR,
    /** Public key folded onto an existing card-backed record (HW 1.5 pairing). */
    PAIRED_WITH_CARD,
    /** Byte-identical to the stored material — nothing new. */
    ALREADY_IN_KEYRING,
    /** Same fingerprint, newer/different public material — merged into the existing row. */
    MERGED_NEW_MATERIAL
}

/** Entity + resolution pair returned by [KeyRepository.importArmoredKeyDetailed]. */
data class ImportOutcome(
    val entity: PGPKeyEntity,
    val resolution: ImportResolution
)

class KeyRepository(
    private val dao: PGPKeyDao,
    private val store: SecureKeyStore,
    private val crypto: PGPCryptoService = PGPCryptoService.shared,
    // Phase A6: revocation primitives. Default to the shared instance
    // since RevocationService is stateless; the parameter is here so
    // tests can inject a stub.
    private val revocation: RevocationService = RevocationService.shared,
    private val keyExpiration: KeyExpirationService = KeyExpirationService.shared
) {

    // 4.0.0 Phase 1 (iOS v7.1.1 F3) — fingerprint-identity guard for
    // every import path, plus the merge engine Phases 2/5/7 reuse.
    // Built on the same dao + store this repository already owns, so
    // the "ViewModels call the repository, never storage directly"
    // rule holds for dedup too.
    private val dedup = KeyDeduplicationService(dao, store)

    // ── Generate ───────────────────────────────────────────────────────

    suspend fun generateKey(
        name: String,
        email: String,
        algorithm: KeyAlgorithm,
        passphrase: String?,
        expirationSeconds: Long? = null
    ): PGPKeyEntity {
        val result = crypto.generateKeyPair(name, email, algorithm, passphrase, expirationSeconds)

        // Store key material in encrypted storage
        store.storePublicKey(result.fingerprint, result.publicKeyData)
        store.storePrivateKey(result.fingerprint, result.privateKeyData)

        // Determine expiration from the generated key
        val importResult = crypto.importKeyData(result.publicKeyData)
        val masterKey = importResult.publicKeyRing?.publicKey
        val expiresAtMs = masterKey?.let { key ->
            val validSec = key.getValidSeconds()
            if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
        }

        // Phase A6: pre-cache a revocation certificate at generation
        // time, while the passphrase (if any) is still in scope. This
        // gives the user something to fall back on if they later lose
        // access to their passphrase but still want to declare the key
        // revoked. Generated with reason=NO_REASON; revoke-from-UI
        // overwrites this with a user-chosen-reason cert.
        //
        // If pre-cache generation fails (very rare — same crypto path
        // that just succeeded at key generation), we fall back to
        // entity = null cert. The KeyDetailScreen revoke flow can
        // always generate fresh.
        // 4.1.0 Phase 12a — this block had never run. `importResult` above is
        // parsed from result.publicKeyData, so importResult.secretKeyRing is
        // ALWAYS null: a public-only import cannot carry a secret ring. Every
        // key generated since 4.0.3 stored a null revocation certificate, so
        // the "revoke even after losing your passphrase" fallback the
        // pre-cache exists for did not exist. The revoke-from-UI flow was
        // unaffected, which is why nothing looked broken.
        // PLANNING_4_2_0.md §10.2.
        //
        // Parsed from result.privateKeyData, the BINARY secret ring, and
        // deliberately NOT from result.armoredPrivateKey: exportArmoredPrivateKey
        // runs v5 composite rings through LibrePGPV5Interop.toLibrePGPFormat,
        // so the armored form is not always the framing BC produced, while
        // privateKeyData is exactly what storePrivateKey just persisted and
        // what loadSecretKeyRing reads back.
        val generatedSecretRing = try {
            crypto.importKeyData(result.privateKeyData).secretKeyRing
        } catch (_: Exception) {
            null
        }

        val preCachedRevocationCert: String? = try {
            generatedSecretRing?.let { secRing ->
                revocation.generateRevocationCertificate(
                    secretKeyRing = secRing,
                    reason = RevocationReason.NO_REASON,
                    comment = null,
                    passphrase = passphrase
                )
            }
        } catch (_: RevocationError) {
            // Non-fatal — user can still revoke later via the sheet
            // which generates fresh on demand. Logged-as-null in DB.
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
            // Phase A6: pre-cached cert lives here until revoke time
            revocationCertificate = preCachedRevocationCert
        )

        dao.insert(entity)
        return entity
    }

    // ── Import ─────────────────────────────────────────────────────────

    /**
     * Phase A10a — metadata-only parse for the Import preview UI.
     *
     * Mirrors iOS ImportKeyView.previewArmoredKey: takes armored
     * text, runs the in-memory PGP parse via [PGPCryptoService.importArmoredKey],
     * and returns just the user-visible metadata + a duplicate flag.
     * NO key material is persisted to disk or DB — that happens only
     * when the user confirms via [importArmoredKey].
     *
     * The duplicate flag distinguishes three cases:
     *   • duplicate=false → not in keyring; import will add a new row
     *   • duplicate=true, willUpgrade=true → public key in keyring,
     *     preview text contains a matching private key → import will
     *     upgrade the existing row to a key pair
     *   • duplicate=true, willUpgrade=false → the commit resolves
     *     through KeyDeduplicationService: byte-identical material
     *     reports "already in keyring", differing material merges
     *     into the existing row (4.0.0 Phase 1; pre-4.0 this threw
     *     AlreadyExists and the UI disabled the Import button)
     *
     * Returns null only when the parse failed entirely (malformed
     * armor, unsupported key type). Caller surfaces the parse error
     * separately if needed.
     */
    suspend fun previewArmoredKey(armoredText: String): ImportPreview? {
        return try {
            val importResult = crypto.importArmoredKey(armoredText)
            // 4.0.0 Phase 1 — normalized lookup (case/format variants
            // count as the same identity, matching the commit path).
            val existing = dedup.findExisting(importResult.fingerprint)
            val parsed = PGPKeyEntity.parseUserID(importResult.userID)
            val willUpgrade = existing != null
                    && importResult.hasPrivateKey
                    && !existing.isKeyPair
            // HW Phase 1.5 — a duplicate that's actually a card record we
            // can pair the public key onto (not a true collision).
            val willPairWithCard = existing != null
                    && existing.isCardBacked
                    && importResult.publicKeyRing != null
            ImportPreview(
                fingerprint = importResult.fingerprint,
                userId = importResult.userID,
                userName = parsed.first,
                userEmail = parsed.second,
                algorithmShortName = importResult.algorithm.shortName,
                hasPrivateKey = importResult.hasPrivateKey,
                isDuplicate = existing != null,
                willUpgradeToKeyPair = willUpgrade,
                willPairWithCard = willPairWithCard,
                armoredText = armoredText
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Legacy-shaped commit entry: returns just the entity. Every
     * pre-4.0.0 call site keeps its signature; the behavior change is
     * that a same-fingerprint duplicate no longer throws
     * [KeyRepoError.AlreadyExists] — it resolves through
     * [KeyDeduplicationService] (already-present, or merge of the
     * newer public material). Call sites that want to distinguish the
     * outcome use [importArmoredKeyDetailed] instead.
     */
    suspend fun importArmoredKey(armoredText: String): PGPKeyEntity =
        importArmoredKeyDetailed(armoredText).entity

    /**
     * 4.0.0 Phase 1 (iOS v7.1.1 F3) — outcome-aware import commit.
     * Same acquisition + card-pairing + secret-upgrade semantics as
     * before; the plain-duplicate branch that used to throw
     * AlreadyExists now resolves via the dedup service so a re-import
     * doubles as a manual refresh and the UI can say what happened.
     */
    suspend fun importArmoredKeyDetailed(armoredText: String): ImportOutcome {
        val importResult = crypto.importArmoredKey(armoredText)

        // Check for duplicate — normalized fingerprint identity via
        // the dedup service (exact DAO hit fast path, case/format
        // variant scan fallback).
        val existing = dedup.findExisting(importResult.fingerprint)
        if (existing != null) {
            // HW Phase 1.5 — pair a real public key onto a card-backed
            // record. A card scanned in Phase 1 is stored as identity +
            // fingerprints only (no key material). When the user then
            // imports the matching public key (exported from gpg, fetched
            // from a keyserver, etc.) we fold it into the existing card
            // row instead of colliding — order-independent with the
            // scan-after-import path in importCardKey. The row STAYS
            // card-backed and public-only (isKeyPair = false): on-card
            // sign/decrypt is Phase 2/3, so even if the imported blob
            // carried a private key we don't store software secret
            // material for a card key. We do refresh the identity
            // (userID/name/email/algorithm/expiry) from the real key,
            // replacing the "<manufacturer> hardware key" placeholder.
            if (existing.isCardBacked) {
                val pub = importResult.publicKeyRing
                    ?: throw KeyRepoError.StorageFailed(
                        "Imported data has no public key to pair with the card"
                    )
                store.storePublicKey(importResult.fingerprint, pub.encoded)
                val parsed = PGPKeyEntity.parseUserID(importResult.userID)
                val masterKey = pub.publicKey
                val expiresAtMs = masterKey?.let { key ->
                    val validSec = key.getValidSeconds()
                    if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
                }
                val merged = existing.copy(
                    userID = importResult.userID,
                    userName = parsed.first,
                    userEmail = parsed.second,
                    algorithm = importResult.algorithm,
                    expiresAt = expiresAtMs,
                    armoredPublicKey = crypto.exportArmoredPublicKey(pub),
                    isKeyPair = false
                )
                dao.update(merged)
                return ImportOutcome(merged, ImportResolution.PAIRED_WITH_CARD)
            }
            // If we're importing a private key for an existing public key, upgrade it
            if (importResult.hasPrivateKey && !existing.isKeyPair) {
                store.storePrivateKey(importResult.fingerprint, importResult.secretKeyRing!!.encoded)
                val upgraded = existing.copy(isKeyPair = true)
                dao.update(upgraded)
                return ImportOutcome(upgraded, ImportResolution.UPGRADED_TO_KEY_PAIR)
            }
            // 4.0.0 Phase 1 (iOS v7.1.1 F3) — the plain-duplicate branch
            // no longer throws AlreadyExists. Byte-identical public
            // material reports already-in-keyring; differing material
            // merges into the existing row, preserving trust, contact
            // link, secret material, notes, and local metadata. A
            // private-only blob for a row that is already a pair
            // carries nothing to merge — the secret-upgrade path above
            // only fires for public-only rows, matching iOS
            // (resolveDuplicate never touches secret material).
            val dupPub = importResult.publicKeyRing
                ?: return ImportOutcome(existing, ImportResolution.ALREADY_IN_KEYRING)
            val dupExpiresAtMs = dupPub.publicKey?.let { key ->
                val validSec = key.getValidSeconds()
                if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
            }
            val (resolved, resolution) = dedup.resolveDuplicate(
                existing = existing,
                newPublicRing = dupPub,
                newArmoredPublicKey = crypto.exportArmoredPublicKey(dupPub),
                newExpiresAtMs = dupExpiresAtMs
            )
            return ImportOutcome(
                resolved,
                when (resolution) {
                    KeyDeduplicationService.DuplicateResolution.ALREADY_IN_KEYRING ->
                        ImportResolution.ALREADY_IN_KEYRING
                    KeyDeduplicationService.DuplicateResolution.MERGED_NEW_MATERIAL ->
                        ImportResolution.MERGED_NEW_MATERIAL
                }
            )
        }

        // Store key material
        if (importResult.publicKeyRing != null) {
            store.storePublicKey(importResult.fingerprint, importResult.publicKeyRing.encoded)
        }
        if (importResult.secretKeyRing != null) {
            store.storePrivateKey(importResult.fingerprint, importResult.secretKeyRing.encoded)
        }

        // Determine expiration
        val masterKey = importResult.publicKeyRing?.publicKey
        val expiresAtMs = masterKey?.let { key ->
            val validSec = key.getValidSeconds()
            if (validSec > 0) (key.creationTime.time + validSec * 1000) else null
        }

        val parsed = PGPKeyEntity.parseUserID(importResult.userID)
        val entity = PGPKeyEntity(
            id = UUID.randomUUID().toString(),
            fingerprint = importResult.fingerprint,
            userID = importResult.userID,
            userName = parsed.first,
            userEmail = parsed.second,
            algorithm = importResult.algorithm,
            isKeyPair = importResult.hasPrivateKey,
            createdAt = importResult.creationDate.time,
            expiresAt = expiresAtMs,
            armoredPublicKey = importResult.publicKeyRing?.let {
                crypto.exportArmoredPublicKey(it)
            }
        )

        dao.insert(entity)
        return ImportOutcome(entity, ImportResolution.INSERTED)
    }

    // ── 4.0.0 Phase 3 (Succession) — multi-key import ──────────────────
    //
    // OpenKeychain's "export all keys" and its decrypted encrypted-backup
    // payload are MANY armored key blocks concatenated in one file;
    // importArmoredKeyDetailed only ever consumes the first. These split
    // a blob into its individual BEGIN/END key blocks and merge-import
    // each through the normal dedup path, so a whole OpenKeychain keyring
    // migrates in one shot.

    private val armoredKeyBlockRegex = Regex(
        "-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----" +
            ".*?" +
            "-----END PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----",
        RegexOption.DOT_MATCHES_ALL
    )

    /** Every armored key block in [text], in order (empty if none). */
    fun splitArmoredKeyBlocks(text: String): List<String> =
        armoredKeyBlockRegex.findAll(text).map { it.value }.toList()

    /**
     * Merge-import EVERY key block in [armoredText]. Each block runs
     * through [importArmoredKeyDetailed] (so held secrets are never
     * overwritten, public-only rows upgrade in place, etc.). A block that
     * fails to parse is skipped, not fatal. Falls back to treating the
     * whole text as one key when no BEGIN/END blocks are found.
     */
    suspend fun importAllArmoredKeysDetailed(armoredText: String): List<ImportOutcome> {
        val perRing = explodePerRing(armoredText)
        val outcomes = ArrayList<ImportOutcome>(perRing.size)
        for (ring in perRing) {
            runCatching { importArmoredKeyDetailed(ring) }.getOrNull()?.let { outcomes.add(it) }
        }
        return outcomes
    }

    /**
     * Split [armoredText] into one armored string per KEY RING.
     *
     * Two levels of nesting have to be undone, and conflating them is
     * what made 4.0.x import only the first key of a multi-key file:
     *
     *   1. A file may hold several BEGIN/END armor blocks (concatenated
     *      exports) — [splitArmoredKeyBlocks] handles that.
     *   2. A SINGLE armor block may hold several rings. This is the
     *      common case, not the exotic one: `gpg --export alice bob` emits
     *      all the rings inside one block, and a binary export gets
     *      wrapped into one block before it reaches here. The OpenKeychain
     *      backup payload (public ring + secret ring + …) is the same
     *      shape.
     *
     * A block BC cannot explode is passed through whole, so a parse
     * failure degrades to the old single-key behavior instead of
     * dropping the block.
     */
    private fun explodePerRing(armoredText: String): List<String> {
        val blocks = splitArmoredKeyBlocks(armoredText).ifEmpty { listOf(armoredText) }
        val perRing = ArrayList<String>()
        for (block in blocks) {
            val rings = crypto.explodeToArmoredKeys(block.toByteArray(Charsets.UTF_8))
            if (rings.isEmpty()) perRing.add(block) else perRing.addAll(rings)
        }
        return perRing
    }

    /**
     * How many key rings [armoredText] actually contains.
     *
     * Callers route on this rather than on [splitArmoredKeyBlocks]`.size`:
     * the block count is 1 for the most common multi-key file there is
     * (a single `gpg --export` of several keys), so routing on it sends
     * that file down the single-key path and silently discards every key
     * but the first.
     *
     * Shares [explodePerRing] with [importAllArmoredKeysDetailed] so the
     * number reported here can never disagree with the number imported.
     */
    fun countKeyRings(armoredText: String): Int = explodePerRing(armoredText).size

    // ── HW Phase 1: Import a hardware-key (OpenPGP card) record ────────

    /**
     * Import (or link) a physical OpenPGP card as a card-backed key.
     *
     * Phase 1 is read-only discovery: no on-card crypto is wired yet, so
     * the resulting row has isKeyPair = false and stores NO private (or
     * public-ring) material in SecureKeyStore. What it does store is the
     * card identity (serial / AID / manufacturer) and the per-slot
     * fingerprints the card reported, plus isCardBacked = true so the
     * future sign/decrypt routing branch can find it.
     *
     * The row is keyed on the signature slot's fingerprint (the card's
     * primary identity); if that slot is empty we fall back to the first
     * populated slot. If no slot has a key, this throws — a blank card
     * has nothing to import.
     *
     * Linking behavior: if a key with the same fingerprint already exists
     * in the keyring (e.g. the user imported the public cert earlier),
     * we stamp the card fields onto that existing row rather than create
     * a duplicate. Otherwise we insert a fresh card-backed contact row.
     */
    suspend fun importCardKey(cardInfo: CardInfo): PGPKeyEntity {
        return importCardKeyInternal(cardInfo)
    }

    /**
     * Persist a key just generated ON a card (Phase B1). [publicKeyBinary] is the
     * assembled transferable public key from CardKeygenService; [cardInfo] is the
     * post-generation card state (carrying the new fingerprints). The generated
     * secret keys live only on the card, so the stored row is public-only and
     * card-backed. Parsing the binary with BC also validates the assembled key
     * before anything is persisted. Reuses the order-independent card pair-up:
     * importCardKey creates/identifies the card-backed row, then importArmoredKey
     * folds the real public key (and UID) onto it.
     */
    suspend fun importGeneratedCardKey(publicKeyBinary: ByteArray, cardInfo: CardInfo): PGPKeyEntity {
        val ring = crypto.importKeyData(publicKeyBinary).publicKeyRing
            ?: throw KeyRepoError.StorageFailed("Generated key produced no public key ring")
        val armored = crypto.exportArmoredPublicKey(ring)
        importCardKeyInternal(cardInfo)
        return importArmoredKey(armored)
    }

    /**
     * 3.1.0 Phase 7 Fix1 (origin: Token2 offline-primary device test):
     * load a public key ring given ANY fingerprint a card can hand us —
     * the primary, a stored card slot fingerprint, or a subkey buried
     * in a stored ring. Card flows derive lookup fingerprints from the
     * card's slots, which are SUBKEYS on offline-primary layouts, so
     * the plain primary-keyed loadPublicKeyRing() missed and every
     * card flow (encrypt+sign, decrypt, share-in decrypt) reported
     * "pair this card first" despite a correct A1 link. Resolution
     * order: direct primary hit → entity whose stored card slot
     * fingerprints match → ring-subkey scan (covers keys imported as
     * plain public keys, never card-linked).
     *
     * NOT for the main thread (runBlocking over the DAO) — card
     * operation lambdas run on the NFC reader thread, which is the
     * intended caller.
     */
    fun loadPublicKeyRingByCardFingerprint(fp: String): org.bouncycastle.openpgp.PGPPublicKeyRing? {
        loadPublicKeyRing(fp)?.let { return it }
        val entity = kotlinx.coroutines.runBlocking {
            getAllKeys().firstOrNull {
                it.cardSigFingerprint.equals(fp, ignoreCase = true) ||
                    it.cardDecFingerprint.equals(fp, ignoreCase = true) ||
                    it.cardAuthFingerprint.equals(fp, ignoreCase = true)
            } ?: findEntityBySubkeyFingerprint(listOf(fp))
        }
        return entity?.let { loadPublicKeyRing(it.fingerprint) }
    }

    /**
     * 3.1.0 Phase 7 (A1): find the stored key entity whose public key
     * ring contains ANY of [fingerprints] — primary or subkey. Used to
     * link a hardware key onto an offline-primary keyring where the
     * card's slot fingerprints are all subkeys. Linear over the keyring
     * (import-time only; keyrings are small).
     */
    private suspend fun findEntityBySubkeyFingerprint(
        fingerprints: List<String>
    ): PGPKeyEntity? {
        if (fingerprints.isEmpty()) return null
        val wanted = fingerprints.map { it.uppercase() }.toSet()
        for (entity in getAllKeys()) {
            val ring = loadPublicKeyRing(entity.fingerprint) ?: continue
            val ringFps = ring.publicKeys.asSequence().map {
                org.bouncycastle.util.encoders.Hex.toHexString(it.fingerprint).uppercase()
            }
            if (ringFps.any { it in wanted }) return entity
        }
        return null
    }

    private suspend fun importCardKeyInternal(cardInfo: CardInfo): PGPKeyEntity {
        val primaryFp = cardInfo.primaryFingerprint
            ?: throw KeyRepoError.StorageFailed(
                "No OpenPGP keys found on this card"
            )

        val sigFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.SIGNATURE)
        val decFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.DECRYPTION)
        val authFp = cardInfo.fingerprintFor(com.pgpony.android.crypto.card.CardSlot.AUTHENTICATION)

        // Link path — fold card identity onto an existing keyring row.
        //
        // 3.1.0 Phase 7 (A1): primaryFp here is derived from the card's
        // SIGNATURE-slot fingerprint. For offline-primary layouts (the
        // primary key stays in a vault; only subkeys live on the card)
        // that slot holds a SUBKEY fingerprint, so the primary-fp lookup
        // below misses and a duplicate card-contact row used to be
        // created next to the real keyring entry. The fallback scan
        // matches ANY card slot fingerprint against each stored ring's
        // full key set (primary + subkeys) and links onto the owning
        // entity, keeping ITS primary fingerprint.
        val existing = dao.getByFingerprint(primaryFp)
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

        // Fresh card-backed contact row. No SecureKeyStore writes — the
        // private key lives on the card and there's no cert to cache yet.
        val algorithm = cardInfo.slotFor(com.pgpony.android.crypto.card.CardSlot.SIGNATURE)?.algorithm
            ?: cardInfo.slots.firstOrNull { it.algorithm != null }?.algorithm
            ?: KeyAlgorithm.ED25519_CV25519

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

    // ── Load Key Rings ─────────────────────────────────────────────────

    fun loadPublicKeyRing(fingerprint: String): PGPPublicKeyRing? {
        val data = store.loadPublicKey(fingerprint) ?: return null
        return try {
            crypto.importKeyData(data).publicKeyRing
        } catch (_: Exception) { null }
    }

    fun loadSecretKeyRing(fingerprint: String): PGPSecretKeyRing? {
        val data = store.loadPrivateKey(fingerprint) ?: return null
        return try {
            crypto.importKeyData(data).secretKeyRing
        } catch (_: Exception) { null }
    }

    fun loadStoredKey(entity: PGPKeyEntity): StoredKey {
        return StoredKey(
            entity = entity,
            publicKeyRing = loadPublicKeyRing(entity.fingerprint),
            secretKeyRing = if (entity.isKeyPair) loadSecretKeyRing(entity.fingerprint) else null
        )
    }

    // ── Export ──────────────────────────────────────────────────────────

    fun exportArmoredPublicKey(fingerprint: String): String? {
        val ring = loadPublicKeyRing(fingerprint) ?: return null
        return crypto.exportArmoredPublicKey(ring)
    }

    /**
     * 4.0.0 Phase 9b (iOS 7.1.x parity) — armored public key for a
     * user-facing copy / share / save, honoring the "Include comment in
     * exported public keys" setting. Keyserver uploads, QR encodes, and
     * cache refreshes keep using [exportArmoredPublicKey] (comment-free).
     */
    fun exportArmoredPublicKeyForSharing(fingerprint: String): String? {
        val ring = loadPublicKeyRing(fingerprint) ?: return null
        return crypto.exportArmoredPublicKeyForSharing(ring)
    }

    fun exportArmoredPrivateKey(fingerprint: String): String? {
        val ring = loadSecretKeyRing(fingerprint) ?: return null
        return crypto.exportArmoredPrivateKey(ring)
    }

    // ── Delete ─────────────────────────────────────────────────────────

    suspend fun deleteKey(entity: PGPKeyEntity) {
        store.deleteKeys(entity.fingerprint)
        dao.delete(entity)
    }

    suspend fun deleteByFingerprint(fingerprint: String) {
        store.deleteKeys(fingerprint)
        dao.getByFingerprint(fingerprint)?.let { dao.delete(it) }
    }

    // ── Query ──────────────────────────────────────────────────────────

    suspend fun getAllKeys(): List<PGPKeyEntity> = dao.getAllKeys()
    suspend fun getKeyPairs(): List<PGPKeyEntity> = dao.getKeyPairs()
    suspend fun getByFingerprint(fp: String): PGPKeyEntity? = dao.getByFingerprint(fp)
    suspend fun getByEmail(email: String): List<PGPKeyEntity> = dao.getByEmail(email)
    suspend fun getDefaultKey(): PGPKeyEntity? = dao.getDefaultKey()
    suspend fun keyCount(): Int = dao.count()

    /**
     * Phase AU-1 — record a successful decrypt for [fingerprint], bumping its
     * usage counter so the "Decrypt With" picker can default to the most-used
     * key. No-op if the fingerprint has no row.
     */
    suspend fun incrementDecryptUseCount(fingerprint: String) =
        dao.incrementDecryptUseCount(fingerprint)

    // ── Update ─────────────────────────────────────────────────────────

    suspend fun setDefaultKey(fingerprint: String) {
        // Clear previous default
        dao.getDefaultKey()?.let { old ->
            dao.update(old.copy(isDefault = false))
        }
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(isDefault = true))
        }
    }

    suspend fun updateTrustLevel(fingerprint: String, trust: TrustLevel) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(trustLevel = trust))
        }
    }

    suspend fun updateNotes(fingerprint: String, notes: String?) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(notes = notes))
        }
    }

    suspend fun markKeyServerUploaded(fingerprint: String) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            // 3.0.0-KS1: also stamp the upload time so the detail screen can
            // show "Last uploaded: <date>".
            dao.update(
                key.copy(
                    keyServerUploaded = true,
                    lastUploadedAt = System.currentTimeMillis(),
                )
            )
        }
    }

    /**
     * 3.0.0-KS1 — record that the user checked/refreshed this key against a
     * keyserver. Drives the "Last checked: <date>" line. Independent of
     * whether the lookup found the key; the timestamp marks the attempt.
     */
    suspend fun markKeyServerChecked(fingerprint: String) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(lastCheckedAt = System.currentTimeMillis()))
        }
    }

    suspend fun updateContactLink(
        fingerprint: String,
        contactId: String?,
        contactName: String?,
        contactPhotoUri: String?
    ) {
        dao.getByFingerprint(fingerprint)?.let { key ->
            dao.update(key.copy(
                contactId = contactId,
                contactName = contactName,
                contactPhotoUri = contactPhotoUri
            ))
        }
    }

    // ── Phase A6: Revocation ───────────────────────────────────────────

    /**
     * Apply a revocation to the key with the supplied fingerprint:
     *   1. Generate a fresh armored revocation certificate with the
     *      user-chosen reason + comment.
     *   2. Apply it to the cached public key ring → updated ring carries
     *      the revocation as a self-signature on the primary key.
     *   3. Re-armor the updated ring and write it back to both the
     *      secure key store (as raw bytes) AND the entity's
     *      armoredPublicKey field.
     *   4. Stamp isRevoked / revokedAt / revocationReason /
     *      revocationCertificate on the entity.
     *
     * Returns the armored revocation certificate so the UI can display
     * and offer to share it. Throws RevocationError on crypto failure
     * (passphrase wrong, key not a key pair, etc.).
     */
    suspend fun applyRevocation(
        fingerprint: String,
        reason: RevocationReason,
        comment: String?,
        passphrase: String?
    ): String {
        val entity = dao.getByFingerprint(fingerprint)
            ?: throw KeyRepoError.NotFound(fingerprint)
        if (!entity.isKeyPair) {
            throw RevocationError.UnsupportedKey(
                "Cannot revoke a public-only key — the private key is required to sign"
            )
        }

        val secRing = loadSecretKeyRing(fingerprint)
            ?: throw RevocationError.UnsupportedKey(
                "Secret key ring could not be loaded for $fingerprint"
            )
        val pubRing = loadPublicKeyRing(fingerprint)
            ?: throw RevocationError.UnsupportedKey(
                "Public key ring could not be loaded for $fingerprint"
            )

        // 1. Generate the cert
        val armoredCert = revocation.generateRevocationCertificate(
            secretKeyRing = secRing,
            reason = reason,
            comment = comment,
            passphrase = passphrase
        )

        // 2. Apply it to the public ring
        val revokedRing = revocation.applyRevocation(pubRing, armoredCert)

        // 3. Re-armor + persist. Two writes:
        //    (a) SecureKeyStore — so future loadPublicKeyRing reads
        //        return the post-revocation ring.
        //    (b) Entity.armoredPublicKey — so QR sheets and share
        //        actions surface the post-revocation form too.
        //
        // SecureKeyStore stores raw bytes; PGPPublicKeyRing.encoded
        // gives us the binary serialization directly. Earlier draft
        // round-tripped through importKeyData() but ImportResult exposes
        // `publicKeyRing` not `publicKeyData` — same bytes either way,
        // just less work.
        val updatedArmored = revocation.armorPublicKeyRing(revokedRing)
        store.storePublicKey(fingerprint, revokedRing.encoded)

        // 4. Stamp entity
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

    // ── Key expiration editing ──────────────────────────────────────────

    /**
     * Change a software key pair's expiration. [expiresAtEpochSeconds] null
     * = never. Re-signs the self-cert + subkey bindings with the primary
     * secret key (passphrase if protected), then persists the updated
     * secret + public rings and stamps entity.expiresAt. Throws
     * ExpirationError on crypto failure (passphrase, etc.).
     */
    suspend fun setKeyExpirationSoftware(
        fingerprint: String,
        expiresAtEpochSeconds: Long?,
        passphrase: String?
    ) {
        val entity = dao.getByFingerprint(fingerprint)
            ?: throw KeyRepoError.NotFound(fingerprint)
        if (!entity.isKeyPair) {
            throw KeyExpirationService.ExpirationError.UnsupportedKey(
                "Cannot edit expiration on a public-only key — the private key is required to re-sign."
            )
        }
        if (entity.isCardBacked) {
            throw KeyExpirationService.ExpirationError.UnsupportedKey(
                "This key lives on a hardware key — use the card flow to edit its expiration."
            )
        }
        val secRing = loadSecretKeyRing(fingerprint)
            ?: throw KeyExpirationService.ExpirationError.UnsupportedKey(
                "Secret key ring could not be loaded for $fingerprint"
            )
        val pubRing = loadPublicKeyRing(fingerprint)
            ?: throw KeyExpirationService.ExpirationError.UnsupportedKey(
                "Public key ring could not be loaded for $fingerprint"
            )

        val updated = keyExpiration.setExpirationSoftware(
            secretRing = secRing,
            publicRing = pubRing,
            expiresAtEpochSeconds = expiresAtEpochSeconds,
            passphrase = passphrase
        )
        persistExpiration(entity, updated.publicRing, updated.secretRing, expiresAtEpochSeconds)
    }

    /**
     * Persist the result of a card-backed expiration edit. The NFC op (run
     * by the UI) calls KeyExpirationService.setExpirationCard and hands the
     * updated public ring here. No secret ring exists for card keys.
     */
    suspend fun persistCardExpiration(
        fingerprint: String,
        updatedPublicRing: org.bouncycastle.openpgp.PGPPublicKeyRing,
        expiresAtEpochSeconds: Long?
    ) {
        val entity = dao.getByFingerprint(fingerprint)
            ?: throw KeyRepoError.NotFound(fingerprint)
        persistExpiration(entity, updatedPublicRing, null, expiresAtEpochSeconds)
    }

    private suspend fun persistExpiration(
        entity: PGPKeyEntity,
        publicRing: org.bouncycastle.openpgp.PGPPublicKeyRing,
        secretRing: org.bouncycastle.openpgp.PGPSecretKeyRing?,
        expiresAtEpochSeconds: Long?
    ) {
        store.storePublicKey(entity.fingerprint, publicRing.encoded)
        secretRing?.let { store.storePrivateKey(entity.fingerprint, it.encoded) }
        dao.update(
            entity.copy(
                armoredPublicKey = crypto.exportArmoredPublicKey(publicRing),
                expiresAt = expiresAtEpochSeconds?.let { it * 1000L }
            )
        )
    }

    /**
     * Return the stored revocation certificate (either pre-cached at
     * key generation or applied via applyRevocation), or null if none
     * exists. Surfaced in Danger Zone as "Export Revocation Certificate"
     * once the key is revoked.
     */
    suspend fun exportRevocationCertificate(fingerprint: String): String? {
        return dao.getByFingerprint(fingerprint)?.revocationCertificate
    }

    // ── 4.0.0 Phase 2: keyserver refresh support (iOS v7.1.1 F5) ────────

    /**
     * Merge public material fetched from a keyserver into [existing].
     * Same engine as duplicate imports (KeyDeduplicationService), so
     * trust level, contact link, secret material, notes, and card
     * backing all survive. Returns the (possibly updated) row plus
     * whether anything actually changed. KeyRefreshService is the
     * intended caller and has already fingerprint-verified
     * [fetchedRing] against [existing] — this method trusts that check.
     */
    suspend fun mergeFetchedPublicMaterial(
        existing: PGPKeyEntity,
        fetchedRing: PGPPublicKeyRing,
        fetchedArmored: String?,
        fetchedExpiresAtMs: Long?
    ): Pair<PGPKeyEntity, Boolean> {
        val (row, resolution) = dedup.resolveDuplicate(
            existing = existing,
            newPublicRing = fetchedRing,
            newArmoredPublicKey = fetchedArmored,
            newExpiresAtMs = fetchedExpiresAtMs
        )
        return row to (resolution == KeyDeduplicationService.DuplicateResolution.MERGED_NEW_MATERIAL)
    }

    /**
     * Stamp upstream revocation onto [fingerprint]'s row: the fetched
     * keyserver copy carried a key-revocation signature (0x20). The
     * revocation-bearing ring itself has already been merged into the
     * secure store + armored cache by [mergeFetchedPublicMaterial];
     * this records the flags the UI reads. revocationCertificate stays
     * untouched — no isolated cert armor exists on this path, and the
     * stored ring now carries the signature (matches iOS F5). No-op
     * (returns the row unchanged) when already revoked, so a locally
     * revoked key keeps its own revokedAt / reason.
     */
    suspend fun markRevokedFromUpstream(
        fingerprint: String,
        revokedAtMs: Long,
        reason: RevocationReason?
    ): PGPKeyEntity? {
        val entity = dao.getByFingerprint(fingerprint) ?: return null
        if (entity.isRevoked) return entity
        val updated = entity.copy(
            isRevoked = true,
            revokedAt = revokedAtMs,
            revocationReason = reason
        )
        dao.update(updated)
        return updated
    }

    // ── 4.0.0 Phase 1: one-time duplicate sweep ─────────────────────────

    /**
     * Collapse duplicate keyring rows left behind by pre-3.1.0 imports
     * (the offline-primary card-linking bug fixed forward in 3.1.0
     * Phase 7 A1 created duplicate card-contact rows on existing
     * installs). Delegates to [KeyDeduplicationService.runSweepIfNeeded];
     * run-once via a SharedPreferences flag, safe to call on every
     * launch. PGPonyApp fires this off applicationScope at startup so
     * the DB work stays off the main thread.
     */
    suspend fun runDedupeSweepIfNeeded(prefs: SharedPreferences) {
        dedup.runSweepIfNeeded(prefs)
    }
}
