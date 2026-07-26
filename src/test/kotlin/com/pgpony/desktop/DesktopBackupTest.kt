// DesktopBackupTest.kt
// D6 validation: format-exact export (armor comment marker, gpg-compat SKESK posture proven by
// our own decrypt with the STRING code), merge-restore semantics (added / upgraded / unchanged /
// secret-never-overwritten), typo-tolerant code normalization, card keys public-only, and the
// OpenKeychain numeric9x4 code rebuild.

package com.pgpony.desktop

import com.pgpony.android.backup.CrockfordBase32
import com.pgpony.android.crypto.KeyAlgorithm
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopBackupTest {

    private fun repo(): Pair<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository> {
        val dir = Files.createTempDirectory("pgpony-backup-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    private suspend fun DesktopKeyRepository.gen(name: String, email: String) =
        generateKey(name, email, KeyAlgorithm.ED25519_CV25519, "test-passphrase")

    @Test
    fun exportRestoreRoundTripWithTrustAndTypos() = runBlocking {
        val (dbA, repoA) = repo()
        val pair = repoA.gen("Backup Pair", "pair@pgpony.app")
        repoA.updateTrustLevel(pair.fingerprint, com.pgpony.android.data.TrustLevel.VERIFIED)
        // A public-only key alongside the pair.
        val (dbT, repoT) = repo()
        val stranger = repoT.gen("Stranger", "stranger@pgpony.app")
        repoA.importArmoredText(repoT.exportArmoredPublicKey(stranger.fingerprint)!!)

        val backupA = DesktopBackupService(repoA)
        val recovery = CrockfordBase32.generate()
        val bytes = backupA.exportBackup(recovery.canonical)
        val armorText = bytes.toString(Charsets.UTF_8)
        assertTrue(armorText.contains("Comment: ${DesktopBackupService.ARMOR_COMMENT}"), "format marker")
        assertFalse(armorText.contains("Version:"), "no Version header")

        // Restore into a fresh keyring, typing the code sloppily: lowercase, hyphens,
        // and Crockford typo glyphs (o→0, l→1).
        val sloppy = recovery.grouped.lowercase().replace('0', 'o').replace('1', 'l')
        val (dbB, repoB) = repo()
        val report = DesktopBackupService(repoB).restoreBackup(bytes, sloppy)
        assertEquals(2, report.added.size, report.summary())
        assertTrue(report.failed.isEmpty(), report.summary())

        val restoredPair = repoB.byFingerprint(pair.fingerprint)!!
        assertTrue(restoredPair.isKeyPair, "secret restored")
        assertEquals(com.pgpony.android.data.TrustLevel.VERIFIED, restoredPair.trustLevel, "trust reapplied")
        assertFalse(repoB.byFingerprint(stranger.fingerprint)!!.isKeyPair, "public-only stays public")

        // Second restore: everything already up to date; the held secret untouched.
        val again = DesktopBackupService(repoB).restoreBackup(bytes, recovery.grouped)
        assertEquals(2, again.unchanged.size, again.summary())
        assertTrue(repoB.byFingerprint(pair.fingerprint)!!.isKeyPair)
        dbA.close(); dbB.close(); dbT.close()
    }

    @Test
    fun restoreUpgradesPublicOnlyRowAndWrongCodeThrows() = runBlocking {
        val (dbA, repoA) = repo()
        val pair = repoA.gen("Upgrader", "upgrade@pgpony.app")
        val backup = DesktopBackupService(repoA)
        val recovery = CrockfordBase32.generate()
        val bytes = backup.exportBackup(recovery.canonical)

        // Target keyring already holds the PUBLIC half.
        val (dbB, repoB) = repo()
        repoB.importArmoredText(repoA.exportArmoredPublicKey(pair.fingerprint)!!)
        val report = DesktopBackupService(repoB).restoreBackup(bytes, recovery.canonical)
        assertEquals(1, report.upgraded.size, report.summary())
        assertTrue(repoB.byFingerprint(pair.fingerprint)!!.isKeyPair)

        assertFailsWith<BackupError.WrongCode> {
            DesktopBackupService(repoB).restoreBackup(bytes, "AAAAAA-AAAAAA-AAAAAA-AAAAAA")
        }
        dbA.close(); dbB.close()
    }

    @Test
    fun cardBackedKeysExportPublicOnly() = runBlocking {
        val (db, repo) = repo()
        val key = repo.gen("Cardish", "card@pgpony.app")
        // Flag the row card-backed via the DAO (the test owns the DB). The secret material
        // still sits in the material store — the exporter's rule must ignore it anyway.
        val row = repo.byFingerprint(key.fingerprint)!!
        db.keyDao().update(row.copy(isCardBacked = true))

        val recovery = CrockfordBase32.generate()
        val bytes = DesktopBackupService(repo).exportBackup(recovery.canonical)

        val (db2, repo2) = repo()
        val report = DesktopBackupService(repo2).restoreBackup(bytes, recovery.canonical)
        assertEquals(1, report.added.size, report.summary())
        assertFalse(
            repo2.byFingerprint(key.fingerprint)!!.isKeyPair,
            "card-backed key must restore public-only (its secret never leaves the card)"
        )
        db.close(); db2.close()
    }

    @Test
    fun openKeychainCodeNormalization() {
        val (db, repo) = repo()
        val backup = DesktopBackupService(repo)
        assertEquals(
            "1234-5678-9012-3456-7890-1234-5678-9012-3456",
            backup.normalizeOpenKeychainCode("1234 5678 9012 3456 7890 1234 5678 9012 3456")
        )
        assertEquals(
            "1234-5678",
            backup.normalizeOpenKeychainCode("12-34 56!78")
        )
        db.close()
    }
}
