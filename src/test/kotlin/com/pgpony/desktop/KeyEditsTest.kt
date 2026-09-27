// KeyEditsTest.kt
// PGPony Desktop 3.0.0, stage 2: the ported key-management mutations (DesktopKeyEdits) and the
// v4 ML-KEM carry across edits (Android 4.6.0 item 19).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.UserIdService
import com.pgpony.android.crypto.pqc.CompositeKeyGen
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.RemovedUserIdStore
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class KeyEditsTest {

    private val crypto = PGPCryptoService.shared
    private val pass = "test-passphrase"

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() = SettingsStores.uninstall()

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, DesktopKeyEdits> {
        val dir = Files.createTempDirectory("pgpony-edits-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        return Triple(db, repo, DesktopKeyEdits(repo))
    }

    @Test
    fun recentlyDeletedHidesRestoresAndPurges() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Bin", "bin@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        edits.softDelete(k.fingerprint)
        assertNull(repo.byFingerprint(k.fingerprint), "binned keys leave the keyring")
        assertEquals(1, edits.deletedCount())
        assertEquals(DesktopKeyEdits.RETENTION_DAYS, edits.daysLeft(edits.deletedKeys().single()) + 1)

        edits.restore(edits.deletedKeys().single().id)
        assertNotNull(repo.byFingerprint(k.fingerprint), "restored")
        assertNotNull(repo.loadSecretKeyRing(k.fingerprint), "material survived the round trip")

        edits.softDelete(k.fingerprint)
        // Fifteen days later the sweep destroys it.
        val purged = edits.purgeExpiredDeleted(nowMs = System.currentTimeMillis() + 15L * 24 * 60 * 60 * 1000)
        assertEquals(1, purged)
        assertEquals(0, edits.deletedCount())
        assertNull(repo.exportArmoredPrivateKey(k.fingerprint), "material destroyed")
        db.close()
    }

    @Test
    fun passphraseSetChangeAndRemove() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Pass", "pass@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        assertFalse(edits.isPassphraseProtected(k.fingerprint))
        edits.changePassphrase(k.fingerprint, "", "first")
        assertTrue(edits.isPassphraseProtected(k.fingerprint))
        assertFails { edits.changePassphrase(k.fingerprint, "wrong", "second") }
        edits.changePassphrase(k.fingerprint, "first", "second")
        edits.changePassphrase(k.fingerprint, "second", "")
        assertFalse(edits.isPassphraseProtected(k.fingerprint))
        assertNotNull(repo.byFingerprint(k.fingerprint)!!.lastLocalEditAt, "edit stamped")
        db.close()
    }

    @Test
    fun compositePassphraseChange() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("ML Pass", "mlpass@pgpony.app", KeyAlgorithm.MLDSA65_ED25519_V6, null)
        edits.changePassphrase(k.fingerprint, "", "ml-secret")
        assertTrue(edits.isPassphraseProtected(k.fingerprint))
        assertNotNull(repo.loadCompositeKeyInfo(k.fingerprint, "ml-secret".toCharArray())?.compositeSecret)
        db.close()
    }

    @Test
    fun userIdsAddPrimaryRevokeAndRemoveWithTombstone() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Ids", "ids@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        edits.addUserId(k.fingerprint, "Ids Work <work@pgpony.app>", makePrimary = false, passphrase = pass)
        var rows = edits.userIdRows(repo.byFingerprint(k.fingerprint)!!)
        assertEquals(2, rows.size)
        assertEquals(k.userID, rows.single { it.isPrimary }.raw, "adding a non-primary UID keeps the original primary")

        edits.setPrimaryUserId(k.fingerprint, "Ids Work <work@pgpony.app>", pass)
        rows = edits.userIdRows(repo.byFingerprint(k.fingerprint)!!)
        assertEquals("Ids Work <work@pgpony.app>", rows.single { it.isPrimary }.raw)
        assertEquals("work@pgpony.app", repo.byFingerprint(k.fingerprint)!!.userEmail)

        edits.revokeUserId(k.fingerprint, k.userID, RevocationReason.NO_REASON, null, pass)
        assertTrue(edits.userIdRows(repo.byFingerprint(k.fingerprint)!!).single { it.raw == k.userID }.isRevoked)

        edits.removeUserId(k.fingerprint, k.userID)
        assertEquals(1, edits.userIdRows(repo.byFingerprint(k.fingerprint)!!).size)
        assertTrue(k.userID in RemovedUserIdStore.removed(k.fingerprint), "tombstoned against refresh")
        db.close()
    }

    @Test
    fun notationsRoundTrip() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Note", "note@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        edits.setNotations(k.fingerprint, listOf(UserIdService.Notation("proof@pgpony.app", "https://example.org")), pass)
        assertEquals("https://example.org", edits.readNotations(k.fingerprint).single().value)
        db.close()
    }

    @Test
    fun lastEncryptionSubkeyIsGuarded() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Sub", "sub@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        val enc = edits.subkeyRows(repo.byFingerprint(k.fingerprint)!!).single()
        assertFailsWith<LastEncryptionSubkeyException> { edits.removeSubkey(k.fingerprint, enc.fingerprint) }
        edits.revokeSubkey(k.fingerprint, enc.fingerprint, RevocationReason.SUPERSEDED, null, pass, allowLastEncryptionSubkey = true)
        assertTrue(edits.subkeyRows(repo.byFingerprint(k.fingerprint)!!).single().isRevoked)
        db.close()
    }

    @Test
    fun v4MlKemSubkeySurvivesEdits() = runBlocking {
        val (db, repo, edits) = temp()
        val base = crypto.importKeyData(
            crypto.generateKeyPair("V4 Edit", "v4edit@pgpony.app", KeyAlgorithm.ED25519_CV25519, null).privateKeyData
        ).secretKeyRing!!
        val rings = CompositeKeyGen.addV4Algo35SubkeyRings(base)
        repo.importArmoredKeyDetailed(
            CompositeSigPacket.armor("-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", rings.secretRaw)
        )
        val fp = rings.primaryFingerprintHex.uppercase()
        assertTrue(edits.subkeyRows(repo.byFingerprint(fp)!!).any { it.algorithmLabel.startsWith("ML-KEM") }, "listed")

        edits.addUserId(fp, "V4 Other <v4other@pgpony.app>", makePrimary = false, passphrase = null)
        repo.setKeyExpirationSoftware(fp, System.currentTimeMillis() / 1000 + 365L * 24 * 3600, null)
        edits.changePassphrase(fp, "", "now-protected")

        assertNotNull(repo.loadV4Algo35Recipient(fp), "the ML-KEM subkey survived User ID, expiry and passphrase edits")
        db.close()
    }

    private suspend fun assertFails(block: suspend () -> Unit) {
        val failed = try { block(); false } catch (_: Exception) { true }
        assertTrue(failed, "expected a failure")
    }
}
