// DesktopBackupService.kt
// PGPony Desktop — D6: the `.pgpony` backup, desktop twin of the Android BackupService
// (that file is app-coupled: KeyRepository, org.json, Android settings). Format per
// BACKUP_FORMAT_4_0_0.md and mirrored line-for-line from the Android implementation:
//   · container: armored OpenPGP message, `Comment: PGPony Backup v1`, SKESK v4 / AES-256 /
//     iterated-salted SHA-256 (no Argon2, no AEAD), SEIPDv1 + MDC — the gpg -c posture
//   · plaintext: strict ustar — pgpony-meta.json first, keys/<fp>.asc per key
//   · recovery code: 120-bit Crockford (vendored CrockfordBase32); the S2K passphrase is the
//     normalized STRING
//   · card-backed keys export public-only; restore is merge-import (secret never overwritten),
//     trust reapplied from meta for changed rows only
//   · OpenKeychain restore (the Succession): numeric9x4 code WITH hyphens, payload exploded
//     into per-ring merge imports
// D11b — localized. MergeReport.summary() assembles per-clause plurals, each clause carrying
// its OWN leading separator (the DesktopKeyRepository pattern). BackupError computes its
// message on ACCESS rather than at construction: the `object` singletons below initialize once
// per process, so a message baked in at construction would freeze the language for the run.
//
// Desktop writes NO pgpony-settings.json yet (network settings arrive at D4; the entry is
// additive-optional by spec) and ignores one on restore — settingsApplied stays false.

package com.pgpony.desktop

import com.pgpony.android.backup.CrockfordBase32
import com.pgpony.android.backup.UstarArchive
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.TrustLevel
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.bouncycastle.bcpg.ArmoredOutputStream
import java.io.ByteArrayOutputStream
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/** A per-key line in the restore merge report. */
data class RestoredKey(val fingerprint: String, val label: String)

/** Plain-language outcome of a restore (mirrors iOS/Android's merge report). */
data class MergeReport(
    val added: List<RestoredKey>,
    val upgraded: List<RestoredKey>,
    val updated: List<RestoredKey>,
    val unchanged: List<RestoredKey>,
    val failed: List<RestoredKey>,
    val settingsApplied: Boolean
) {
    val totalRestored: Int get() = added.size + upgraded.size + updated.size
    fun summary(): String = buildString {
        append(trQuantity("d_restore_summary_added", added.size))
        if (upgraded.isNotEmpty()) append(trQuantity("d_restore_summary_upgraded", upgraded.size))
        if (updated.isNotEmpty()) append(trQuantity("d_restore_summary_updated", updated.size))
        if (unchanged.isNotEmpty()) append(trQuantity("d_restore_summary_unchanged", unchanged.size))
        if (failed.isNotEmpty()) append(trQuantity("d_restore_summary_failed", failed.size))
    }
}

/** Which app's backup a file is — drives code format + payload parsing. */
enum class BackupKind { PGPONY, OPENKEYCHAIN, UNKNOWN }

sealed class BackupError(private val key: String, private val detail: String? = null) : Exception() {
    // Resolved on ACCESS, not at construction — see the D11b note at the top of this file.
    override val message: String get() = detail?.let { tr(key, it) } ?: tr(key)

    object NotABackup : BackupError("d_backup_err_not_a_backup")
    object WrongCode : BackupError("d_backup_err_wrong_code")
    class Corrupt(detail: String) : BackupError("d_backup_err_corrupt", detail)
    object EmptyKeyring : BackupError("d_backup_err_empty_keyring")
}

class DesktopBackupService(
    private val repo: DesktopKeyRepository,
    private val crypto: PGPCryptoService = PGPCryptoService.shared
) {

    companion object {
        const val ARMOR_COMMENT = "PGPony Backup v1"
        const val FORMAT_VERSION = 1
        const val FILE_EXTENSION = "pgpony"

        private const val META_NAME = "pgpony-meta.json"
        private const val SETTINGS_NAME = "pgpony-settings.json"
        private const val KEYS_DIR = "keys/"
    }

    // ── Export ───────────────────────────────────────────────────────

    suspend fun exportBackup(recoveryCanonical: String): ByteArray {
        val keys = repo.allKeys()
        if (keys.isEmpty()) throw BackupError.EmptyKeyring

        val entries = ArrayList<UstarArchive.Entry>()
        val metaKeys = buildJsonArray {
            for (e in keys) {
                val fp = e.fingerprint.lowercase()
                // Card/hardware keys have no exportable secret → public-only.
                val wantSecret = e.isKeyPair && !e.isCardBacked
                val armored: String = (if (wantSecret) {
                    repo.exportArmoredPrivateKey(fp) ?: repo.exportArmoredPublicKey(fp)
                } else {
                    repo.exportArmoredPublicKey(fp)
                }) ?: continue

                val hasSecret = armored.contains("PRIVATE KEY BLOCK")
                entries.add(UstarArchive.Entry("$KEYS_DIR$fp.asc", armored.toByteArray(Charsets.UTF_8)))
                add(buildJsonObject {
                    put("fingerprint", fp)
                    put("userID", e.userID)
                    put("algorithm", e.algorithm.displayName)
                    put("hasSecret", hasSecret)
                    put("trustLevel", e.trustLevel.displayName)
                    if (e.userEmail.isNotBlank()) put("contactLink", e.userEmail)
                    put("createdAt", iso(e.createdAt))
                    e.expiresAt?.let { put("expiresAt", iso(it)) }
                })
            }
        }
        if (metaKeys.isEmpty()) throw BackupError.EmptyKeyring

        val meta = buildJsonObject {
            put("appVersion", AppVersion.VERSION)
            put("platform", "desktop")
            put("createdAt", iso(System.currentTimeMillis()))
            put("formatVersion", FORMAT_VERSION)
            put("keys", metaKeys)
        }

        val ordered = ArrayList<UstarArchive.Entry>(entries.size + 1)
        ordered.add(UstarArchive.Entry(META_NAME, PRETTY.encodeToString(JsonObject.serializer(), meta).toByteArray(Charsets.UTF_8)))
        ordered.addAll(entries)
        // No pgpony-settings.json on desktop yet (D4) — the entry is additive-optional.

        val tar = UstarArchive.write(ordered)
        val sealed = crypto.encryptSymmetric(
            data = tar,
            passphrase = recoveryCanonical,
            filename = null,
            armor = false,
            useAead = false,
            useArgon2 = false
        )
        return armorMessage(sealed)
    }

    private fun armorMessage(binary: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).apply {
            setHeader("Version", null)
            setHeader("Comment", ARMOR_COMMENT)
            write(binary)
            close()
        }
        return out.toByteArray()
    }

    // ── Restore ──────────────────────────────────────────────────────

    suspend fun restoreBackup(fileBytes: ByteArray, enteredCode: String): MergeReport {
        val text = fileBytes.toString(Charsets.UTF_8)
        if (!text.contains("BEGIN PGP MESSAGE")) throw BackupError.NotABackup

        val canonical = CrockfordBase32.normalize(enteredCode)
        val plaintext = decryptOrThrow(fileBytes, canonical)

        val entries = try {
            UstarArchive.read(plaintext)
        } catch (e: Exception) {
            throw BackupError.Corrupt(e.message ?: tr("d_backup_detail_unreadable_archive"))
        }
        if (entries.isEmpty()) throw BackupError.Corrupt(tr("d_backup_detail_empty_archive"))

        val metaByFp = HashMap<String, JsonObject>()
        entries.firstOrNull { it.name == META_NAME }?.let { m ->
            runCatching {
                val obj = Json.parseToJsonElement(String(m.data, Charsets.UTF_8)).jsonObject
                obj["keys"]?.jsonArray?.forEach { el ->
                    val k = el.jsonObject
                    k["fingerprint"]?.jsonPrimitive?.content?.lowercase()?.let { metaByFp[it] = k }
                }
            }
        }

        val added = ArrayList<RestoredKey>(); val upgraded = ArrayList<RestoredKey>()
        val updated = ArrayList<RestoredKey>(); val unchanged = ArrayList<RestoredKey>()
        val failed = ArrayList<RestoredKey>()

        val seen = HashSet<String>()
        for (entry in entries) {
            if (!entry.name.startsWith(KEYS_DIR) || !entry.name.endsWith(".asc")) continue
            val fpFromName = entry.name.removePrefix(KEYS_DIR).removeSuffix(".asc").lowercase()
            if (!seen.add(fpFromName)) continue
            val armored = String(entry.data, Charsets.UTF_8)
            try {
                val resolution = repo.importArmoredKeyDetailed(armored)
                val row = repo.byFingerprint(fpFromName)
                val fp = (row?.fingerprint ?: fpFromName).lowercase()
                val rk = RestoredKey(fp, row?.userID?.ifBlank { fp } ?: fp)
                when (resolution) {
                    ImportResolution.INSERTED -> added.add(rk)
                    ImportResolution.UPGRADED_TO_KEY_PAIR -> upgraded.add(rk)
                    ImportResolution.MERGED_NEW_MATERIAL -> updated.add(rk)
                    ImportResolution.ALREADY_IN_KEYRING -> unchanged.add(rk)
                    ImportResolution.FAILED -> failed.add(rk)
                }
                // Reapply trust for anything actually changed — never clobber an unchanged key.
                if (resolution != ImportResolution.ALREADY_IN_KEYRING && resolution != ImportResolution.FAILED) {
                    metaByFp[fp]?.let { applyTrust(fp, it) }
                }
            } catch (e: Exception) {
                val label = metaByFp[fpFromName]?.get("userID")?.jsonPrimitive?.content
                    ?.ifBlank { null } ?: fpFromName
                failed.add(RestoredKey(fpFromName, label))
            }
        }

        // Settings entry ignored on desktop until D4 (spec: additive-optional).
        return MergeReport(added, upgraded, updated, unchanged, failed, settingsApplied = false)
    }

    // ── OpenKeychain migration (the Succession) ──────────────────────

    fun detectKind(fileBytes: ByteArray): BackupKind {
        val head = String(fileBytes.copyOf(minOf(400, fileBytes.size)), Charsets.UTF_8)
        return when {
            head.contains("PGPony Backup", ignoreCase = true) -> BackupKind.PGPONY
            head.contains("Passphrase-Format", ignoreCase = true) ||
                head.contains("numeric", ignoreCase = true) -> BackupKind.OPENKEYCHAIN
            else -> BackupKind.UNKNOWN
        }
    }

    /** numeric9x4: the S2K passphrase is the code WITH its hyphens (opposite of PGPony's). */
    fun normalizeOpenKeychainCode(input: String): String =
        input.filter { it.isDigit() }.chunked(4).joinToString("-")

    suspend fun restoreOpenKeychainBackup(fileBytes: ByteArray, enteredCode: String): MergeReport {
        val passphrase = normalizeOpenKeychainCode(enteredCode)
        if (passphrase.isBlank()) throw BackupError.WrongCode
        val plaintext = decryptOrThrow(fileBytes, passphrase)

        val text = String(plaintext, Charsets.UTF_8)
        val blocks = if (text.contains("BEGIN PGP"))
            DesktopKeyRepository.splitArmoredBlocks(text)
                .flatMap { block ->
                    // A block may hold several rings — explode, fall back to the block itself.
                    runCatching { crypto.explodeToArmoredKeys(block.toByteArray(Charsets.UTF_8)) }
                        .getOrNull()?.takeIf { it.isNotEmpty() } ?: listOf(block)
                }
        else runCatching { crypto.explodeToArmoredKeys(plaintext) }.getOrDefault(emptyList())
        if (blocks.isEmpty()) throw BackupError.Corrupt(tr("d_backup_detail_no_keys"))

        val added = ArrayList<RestoredKey>(); val upgraded = ArrayList<RestoredKey>()
        val updated = ArrayList<RestoredKey>(); val unchanged = ArrayList<RestoredKey>()
        val failed = ArrayList<RestoredKey>()
        val seen = HashSet<String>()
        for (block in blocks) {
            try {
                val resolution = repo.importArmoredKeyDetailed(block)
                val fp = runCatching { crypto.importArmoredKey(block).fingerprint.lowercase() }
                    .getOrDefault("?")
                if (!seen.add(fp)) continue
                val row = repo.byFingerprint(fp)
                val rk = RestoredKey(fp, row?.userID?.ifBlank { fp } ?: fp)
                when (resolution) {
                    ImportResolution.INSERTED -> added.add(rk)
                    ImportResolution.UPGRADED_TO_KEY_PAIR -> upgraded.add(rk)
                    ImportResolution.MERGED_NEW_MATERIAL -> updated.add(rk)
                    ImportResolution.ALREADY_IN_KEYRING -> unchanged.add(rk)
                    ImportResolution.FAILED -> failed.add(rk)
                }
            } catch (_: Exception) {
                failed.add(RestoredKey("?", tr("d_restore_unreadable_block")))
            }
        }
        if (added.isEmpty() && upgraded.isEmpty() && updated.isEmpty() && unchanged.isEmpty()) {
            throw BackupError.Corrupt(tr("d_backup_detail_no_keys"))
        }
        return MergeReport(added, upgraded, updated, unchanged, failed, settingsApplied = false)
    }

    // ── Helpers ──────────────────────────────────────────────────────

    private fun decryptOrThrow(fileBytes: ByteArray, passphrase: String): ByteArray = try {
        crypto.decrypt(
            encryptedData = fileBytes,
            secretKeyRings = emptyList(),
            passphrase = passphrase,
            verificationKeys = null
        ).data
    } catch (e: PGPCryptoError.InvalidPassphrase) {
        throw BackupError.WrongCode
    } catch (e: PGPCryptoError.IntegrityCheckFailed) {
        throw BackupError.Corrupt(e.message ?: tr("d_backup_detail_integrity"))
    } catch (e: BackupError) {
        throw e
    } catch (e: Exception) {
        // Wrong SKESK passphrase usually surfaces as a generic decrypt failure.
        throw BackupError.WrongCode
    }

    private suspend fun applyTrust(fingerprint: String, meta: JsonObject) {
        val display = meta["trustLevel"]?.jsonPrimitive?.content?.ifBlank { null } ?: return
        val level = TrustLevel.entries.firstOrNull { it.displayName.equals(display, true) } ?: return
        runCatching { repo.updateTrustLevel(fingerprint, level) }
    }

    private val ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC)
    private fun iso(epochMs: Long): String = ISO.format(Instant.ofEpochMilli(epochMs))

    private val PRETTY = Json { prettyPrint = true; prettyPrintIndent = "  " }
}
