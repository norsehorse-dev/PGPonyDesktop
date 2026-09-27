// KeyEditsTest.kt
// PGPony Desktop 3.0.0, stage 2: the ported key-management mutations (DesktopKeyEdits) and the
// v4 ML-KEM carry across edits (Android 4.6.0 item 19).

package com.pgpony.desktop

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.UserIdService
import com.pgpony.android.crypto.pqc.CompositeKeyGen
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSuite
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.RemovedUserIdStore
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.util.prefs.AbstractPreferences
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

        // UserIdService.isRevoked needs the revocation strictly newer than the newest
        // certification, and setPrimaryUserId just re-signed this User ID. Signature times have
        // one-second resolution, so a revocation in the same second reads as not revoked.
        Thread.sleep(1100)
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

    // ── 2b: add subkey (Android 4.2.0 H, 4.5.0 item 7, 4.6.0 items 16 and 21) ──

    @Test
    fun addClassicalSubkeyUsesALifetimeAndStampsTheEdit() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Add", "add@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        val year = 365L * 24 * 3600
        edits.addSubkey(k.fingerprint, AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH), year, pass)
        val entity = repo.byFingerprint(k.fingerprint)!!
        val rows = edits.subkeyRows(entity)
        assertEquals(2, rows.size)
        val auth = rows.single { (it.capabilities and 0x08) != 0 }
        assertEquals(year * 1000, auth.expiresAt!! - auth.createdAt, "the generators take seconds after creation, not an epoch time")
        assertNotNull(entity.lastLocalEditAt, "an added subkey marks the published copy out of date")
        db.close()
    }

    @Test
    fun v6KeysRefuseRsaAndV4KeysRefuseMlDsa() = runBlocking {
        val (db, repo, edits) = temp()
        val v6 = repo.generateKey("Six", "six@pgpony.app", KeyAlgorithm.V6_ED25519, pass)
        assertFailsWith<KeyEditException> {
            edits.addSubkey(v6.fingerprint, AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.RSA_2048_ENCRYPT), null, pass)
        }
        val before = edits.subkeyRows(repo.byFingerprint(v6.fingerprint)!!).size
        edits.addSubkey(v6.fingerprint, AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN), null, pass)
        assertEquals(before + 1, edits.subkeyRows(repo.byFingerprint(v6.fingerprint)!!).size)

        val v4 = repo.generateKey("Four", "four@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        assertFailsWith<KeyEditException> {
            edits.addSubkey(v4.fingerprint, AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA65_ED25519), null, pass)
        }
        assertFailsWith<KeyEditException> {
            edits.addSubkey(v4.fingerprint, AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024), null, pass)
        }
        db.close()
    }

    @Test
    fun mlKemOnAV4KeyConvertsItAndSurvivesTheNextAdd() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Kem", "kem@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        edits.addSubkey(k.fingerprint, AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768), null, pass)
        assertEquals(KeyAlgorithm.MLKEM768_X25519_V4, repo.byFingerprint(k.fingerprint)!!.algorithm)
        assertNotNull(repo.loadV4Algo35Recipient(k.fingerprint), "the v4 ML-KEM subkey is usable")

        edits.addSubkey(k.fingerprint, AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN), null, pass)
        assertNotNull(repo.loadV4Algo35Recipient(k.fingerprint), "a later classical add carries the ML-KEM subkey")
        assertEquals(3, edits.subkeyRows(repo.byFingerprint(k.fingerprint)!!).size)
        db.close()
    }

    @Test
    fun compositePrimaryTakesAClassicalSubkeyAndKeepsItsPassphrase() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("ML Add", "mladd@pgpony.app", KeyAlgorithm.MLDSA65_ED25519_V6, pass)
        val before = edits.subkeyRows(repo.byFingerprint(k.fingerprint)!!).size
        edits.addSubkey(k.fingerprint, AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT), null, pass)
        assertEquals(before + 1, edits.subkeyRows(repo.byFingerprint(k.fingerprint)!!).size)
        assertNotNull(repo.loadCompositeKeyInfo(k.fingerprint, pass.toCharArray())?.compositeSecret, "still opens with the passphrase")
        db.close()
    }

    @Test
    fun v6KeyTakesAnMlDsaSigningSubkey() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("PQ Sign", "pqsign@pgpony.app", KeyAlgorithm.V6_ED25519, pass)
        edits.addSubkey(k.fingerprint, AddSubkeyChoice.PqSigning(CompositeSignSuite.MLDSA65_ED25519), null, pass)
        assertTrue(edits.subkeyRows(repo.byFingerprint(k.fingerprint)!!).any { it.algorithmLabel.contains("ML-DSA") })
        db.close()
    }

    // ── 2b: fallback ordering (Android KeyDetailViewModel) ──

    @Test
    fun fallbackRowsToggleAndMove() = runBlocking {
        val (db, repo, _) = temp()
        val a = repo.generateKey("A", "a@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val b = repo.generateKey("B", "b@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val c = repo.generateKey("C", "c@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val pool = listOf(a, b, c)
        var rows = fallbackRows(pool, listOf(c.fingerprint, "GONE"))
        assertEquals(listOf(c.fingerprint, a.fingerprint, b.fingerprint), rows.map { it.key.fingerprint })
        assertEquals(listOf(true, false, false), rows.map { it.enabled })

        rows = toggleFallback(rows, b.fingerprint)
        assertEquals(listOf(c.fingerprint, b.fingerprint, a.fingerprint), rows.map { it.key.fingerprint })
        rows = moveFallback(rows, b.fingerprint, -1)
        assertEquals(listOf(b.fingerprint, c.fingerprint), rows.filter { it.enabled }.map { it.key.fingerprint })
        assertEquals(rows, moveFallback(rows, c.fingerprint, 1), "cannot move past the enabled block")
        rows = toggleFallback(rows, b.fingerprint)
        assertEquals(listOf(c.fingerprint), rows.filter { it.enabled }.map { it.key.fingerprint })
        assertEquals(b.fingerprint, rows[1].key.fingerprint, "switched off lands at the head of the disabled block")
        db.close()
    }

    // ── 2b: Clear All Data (plan 3.2) ──

    @Test
    fun clearAllDataResetsToFirstRun() = runBlocking {
        val dir = Files.createTempDirectory("pgpony-clear-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        val edits = DesktopKeyEdits(repo)
        val a = repo.generateKey("Keep", "keep@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        val b = repo.generateKey("Binned", "binned@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        edits.setFallbacks(a.fingerprint, listOf(b.fingerprint))
        edits.softDelete(b.fingerprint)
        Files.writeString(dir.resolve("watch-rules.json"), "[]")
        val root = TreePreferences(null, "")
        root.node(ClearAllData.PREFS_NODE).putBoolean("anything", true)
        ClearAllData.dataDirOverride = dir
        ClearAllData.prefsRootOverride = root
        try {
            ClearAllData.run(edits)
        } finally {
            ClearAllData.dataDirOverride = null
            ClearAllData.prefsRootOverride = null
        }
        assertTrue(repo.allKeys().isEmpty(), "live keys gone")
        assertEquals(0, edits.deletedCount(), "Recently Deleted emptied too")
        assertTrue(edits.fallbacksFor(a.fingerprint).isEmpty())
        assertFalse(Files.exists(dir.resolve("watch-rules.json")))
        assertFalse(Files.exists(dir.resolve("keys")), "no key material left on disk")
        assertFalse(root.nodeExists(ClearAllData.PREFS_NODE), "every desktop setting removed")
        db.close()
    }

    private suspend fun assertFails(block: suspend () -> Unit) {
        val failed = try { block(); false } catch (_: Exception) { true }
        assertTrue(failed, "expected a failure")
    }
}

/** A preferences tree in memory (MemoryPreferences is flat), for the Clear All Data test. */
private class TreePreferences(parent: TreePreferences?, name: String) : AbstractPreferences(parent, name) {
    private val values = mutableMapOf<String, String>()
    override fun putSpi(key: String, value: String) { values[key] = value }
    override fun getSpi(key: String): String? = values[key]
    override fun removeSpi(key: String) { values.remove(key) }
    override fun removeNodeSpi() { values.clear() }
    override fun keysSpi(): Array<String> = values.keys.toTypedArray()
    override fun childrenNamesSpi(): Array<String> = emptyArray()
    override fun childSpi(name: String): AbstractPreferences = TreePreferences(this, name)
    override fun syncSpi() {}
    override fun flushSpi() {}
}
