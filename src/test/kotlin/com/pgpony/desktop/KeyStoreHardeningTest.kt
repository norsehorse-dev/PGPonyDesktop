// KeyStoreHardeningTest.kt
// PGPony Desktop 3.0.0: key storage and lifecycle hardening (package C): backup restore trust,
// re-import of a binned key, owner-only data files, proof before a contact becomes a key pair,
// one key per stored block, atomic key writes, verified upstream revocations, the D1 keyring
// leftover, the pairing transfer of partly protected keys and the key refresh default.

package com.pgpony.desktop

import com.pgpony.android.backup.CrockfordBase32
import com.pgpony.android.backup.UstarArchive
import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.RevocationService
import com.pgpony.android.crypto.S2kPolicy
import com.pgpony.android.crypto.SecretKeyCheck
import com.pgpony.android.crypto.SecretKeyUnlock
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.TrustLevel
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.UUID
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

class KeyStoreHardeningTest {

    private val crypto = PGPCryptoService.shared
    private val pass = "test-passphrase"

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() = SettingsStores.uninstall()

    private class Env(val dir: Path, val db: PGPDatabase, val repo: DesktopKeyRepository) {
        val edits = DesktopKeyEdits(repo)
    }

    private fun env(): Env {
        val dir = Files.createTempDirectory("pgpony-c-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Env(dir, db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))))
    }

    private fun gen(name: String, passphrase: String? = pass) =
        crypto.generateKeyPair(name, "${name.lowercase()}@pgpony.app", KeyAlgorithm.ED25519_CV25519, passphrase)

    private fun armorPrivate(raw: ByteArray) =
        CompositeSigPacket.armor("-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", raw)

    private fun posix() = OwnerOnlyPaths.posix()
    private fun perms(p: Path) = PosixFilePermissions.toString(Files.getPosixFilePermissions(p))

    // ── KEYSTORE-1 / PAIRING-IMPL-1: backup restore and trust ──

    private fun craftBackup(code: String, meta: String, entries: List<Pair<String, String>>): ByteArray {
        val tar = UstarArchive.write(
            listOf(UstarArchive.Entry("pgpony-meta.json", meta.toByteArray())) +
                entries.map { (name, text) -> UstarArchive.Entry(name, text.toByteArray()) }
        )
        val sealed = crypto.encryptSymmetric(tar, code, null, armor = false, useAead = false, useArgon2 = false)
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).apply {
            setHeader("Comment", DesktopBackupService.ARMOR_COMMENT)
            write(sealed)
            close()
        }
        return out.toByteArray()
    }

    private fun meta(vararg rows: Pair<String, String>): String =
        """{"formatVersion":1,"keys":[""" +
            rows.joinToString(",") { (fp, trust) -> """{"fingerprint":"${fp.lowercase()}","trustLevel":"$trust"}""" } +
            "]}"

    @Test
    fun keystore1_entryWhoseKeyIsNotItsNameIsRefusedAndTrustNeverMovesToAnotherKey() = runBlocking {
        val e = env()
        val victim = gen("Victim")
        e.repo.importArmoredKeyDetailed(victim.armoredPublicKey)
        e.repo.updateTrustLevel(victim.fingerprint, TrustLevel.VERIFIED)
        val throwaway = gen("Throwaway")
        val code = CrockfordBase32.generate().canonical
        val bytes = craftBackup(
            code,
            meta(victim.fingerprint to "Unknown"),
            listOf("keys/${victim.fingerprint.lowercase()}.asc" to throwaway.armoredPublicKey)
        )
        val report = DesktopBackupService(e.repo).restoreBackup(bytes, code)
        assertEquals(1, report.failed.size, report.summary())
        assertTrue(report.added.isEmpty())
        assertNull(e.repo.byFingerprint(throwaway.fingerprint), "the mislabelled key is not imported")
        assertEquals(TrustLevel.VERIFIED, e.repo.byFingerprint(victim.fingerprint)!!.trustLevel, "victim trust untouched")
        e.db.close()
    }

    @Test
    fun keystore1_trustOnlyForNewKeysAndUltimateOnlyWithTheSecret() = runBlocking {
        val e = env()
        val stranger = gen("Stranger")          // public only in the backup, claims Ultimate
        val own = gen("Own", null)               // own key pair, Ultimate
        val held = gen("Held")                   // already held (in Recently Deleted), claims Verified
        e.repo.importArmoredKeyDetailed(held.armoredPublicKey)
        e.edits.softDelete(held.fingerprint)
        val code = CrockfordBase32.generate().canonical
        val bytes = craftBackup(
            code,
            meta(stranger.fingerprint to "Ultimate", own.fingerprint to "Ultimate", held.fingerprint to "Verified"),
            listOf(
                "keys/${stranger.fingerprint.lowercase()}.asc" to stranger.armoredPublicKey,
                "keys/${own.fingerprint.lowercase()}.asc" to own.armoredPrivateKey,
                "keys/${held.fingerprint.lowercase()}.asc" to held.armoredPublicKey
            )
        )
        DesktopBackupService(e.repo).restoreBackup(bytes, code)
        assertEquals(TrustLevel.VERIFIED, e.repo.byFingerprint(stranger.fingerprint)!!.trustLevel, "Ultimate needs the secret")
        assertEquals(TrustLevel.ULTIMATE, e.repo.byFingerprint(own.fingerprint)!!.trustLevel)
        val heldRow = e.repo.byFingerprint(held.fingerprint)!!
        assertEquals(TrustLevel.UNKNOWN, heldRow.trustLevel, "a key held before keeps its trust")
        assertEquals(0, e.edits.deletedCount(), "the binned key came back, no second row")

        // Pairing: no trust at all.
        val e2 = env()
        DesktopBackupService(e2.repo).restoreBackup(bytes, code, applyTrust = false)
        assertEquals(TrustLevel.UNKNOWN, e2.repo.byFingerprint(stranger.fingerprint)!!.trustLevel)
        assertEquals(TrustLevel.UNKNOWN, e2.repo.byFingerprint(own.fingerprint)!!.trustLevel)
        e.db.close(); e2.db.close()
    }

    @Test
    fun pairingImpl1_aMessageThatIsNotPasswordEncryptedIsNotABackup() = runBlocking {
        val e = env()
        val k = gen("Literal")
        val tar = UstarArchive.write(
            listOf(UstarArchive.Entry("keys/${k.fingerprint.lowercase()}.asc", k.armoredPublicKey.toByteArray()))
        )
        val lit = ByteArrayOutputStream()
        val gen = org.bouncycastle.openpgp.PGPLiteralDataGenerator()
        gen.open(lit, org.bouncycastle.openpgp.PGPLiteralData.BINARY, "", tar.size.toLong(), java.util.Date()).use { it.write(tar) }
        gen.close()
        val armored = ByteArrayOutputStream()
        ArmoredOutputStream(armored).apply { write(lit.toByteArray()); close() }
        assertFailsWith<BackupError.NotABackup> {
            DesktopBackupService(e.repo).restoreBackup(armored.toByteArray(), "ANYTHING")
        }
        assertNull(e.repo.byFingerprint(k.fingerprint))
        e.db.close()
    }

    // ── KEYSTORE-2: a key in Recently Deleted imported again ──

    @Test
    fun keystore2_reimportRestoresTheBinnedRowAndPurgeNeverTakesSharedMaterial() = runBlocking {
        val e = env()
        val k = e.repo.generateKey("Binned Pair", "bp@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        val publicArmor = e.repo.exportArmoredPublicKey(k.fingerprint)!!
        e.edits.softDelete(k.fingerprint)

        assertEquals(ImportResolution.INSERTED, e.repo.importArmoredKeyDetailed(publicArmor))
        assertEquals(0, e.edits.deletedCount(), "no second row")
        val row = e.repo.byFingerprint(k.fingerprint)!!
        assertEquals(k.id, row.id, "the binned row itself came back")
        assertTrue(row.isKeyPair)

        // A duplicate row left by an older version, in the bin and past retention.
        val dup = row.copy(id = UUID.randomUUID().toString(), deletedAt = 1L, isDefault = false)
        e.db.keyDao().insert(dup)
        assertEquals(1, e.edits.purgeExpiredDeleted())
        assertNotNull(e.repo.exportArmoredPrivateKey(k.fingerprint), "the live key keeps its secret")
        assertNotNull(e.repo.loadSecretKeyRing(k.fingerprint))

        // Restoring such a duplicate while the key is live drops the duplicate.
        val dup2 = row.copy(id = UUID.randomUUID().toString(), deletedAt = System.currentTimeMillis(), isDefault = false)
        e.db.keyDao().insert(dup2)
        e.edits.restore(dup2.id)
        assertEquals(0, e.edits.deletedCount())
        assertEquals(1, e.repo.allKeys().count { it.fingerprint == k.fingerprint })
        assertNotNull(e.repo.exportArmoredPrivateKey(k.fingerprint))

        // Purging the only row still removes the material.
        e.edits.softDelete(k.fingerprint)
        e.edits.emptyBin()
        assertNull(e.repo.exportArmoredPrivateKey(k.fingerprint))
        e.db.close()
    }

    // ── KEYSTORE-3 / KEYSTORE-6: owner-only and atomic files ──

    @Test
    fun keystore3_dataFilesAreOwnerOnly() = runBlocking {
        if (!posix()) return@runBlocking
        val dir = Files.createTempDirectory("pgpony-perm-test")
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwxr-xr-x"))
        OwnerOnlyPaths.createPrivateDirectories(dir)
        assertEquals("rwx------", perms(dir))

        val keys = dir.resolve("keys")
        Files.createDirectories(keys)
        val old = keys.resolve("old.pub.asc")
        Files.writeString(old, "x")
        Files.setPosixFilePermissions(old, PosixFilePermissions.fromString("rw-r--r--"))
        val store = KeyMaterialStore(keys)
        assertEquals("rw-------", perms(old), "files from older versions are fixed")
        assertEquals("rwx------", perms(keys))

        val dbFile = dir.resolve("pgpony.db")
        val db = Db.open(dbFile)
        val repo = DesktopKeyRepository(db, store)
        repo.generateKey("Perm", "perm@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        for (name in listOf("pgpony.db", "pgpony.db-wal", "pgpony.db-shm")) {
            val f = dir.resolve(name)
            if (Files.exists(f)) assertEquals("rw-------", perms(f), name)
        }
        db.close()

        // An existing database made with the default umask is fixed when it is opened.
        Files.setPosixFilePermissions(dbFile, PosixFilePermissions.fromString("rw-r--r--"))
        Db.open(dbFile).close()
        assertEquals("rw-------", perms(dbFile))
    }

    @Test
    fun keystore3_purgedRowsDoNotLingerInTheDatabaseFile() = runBlocking {
        val e = env()
        val k = e.repo.generateKey("Linger", "linger@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        val marker = "NOTE-MARKER-" + UUID.randomUUID()
        e.repo.updateNotes(k.fingerprint, marker)
        e.edits.softDelete(k.fingerprint)
        e.edits.emptyBin()
        e.db.close()
        val bytes = Files.list(e.dir).use { list ->
            list.filter { it.fileName.toString().startsWith("pgpony.db") }.toList()
        }.fold(ByteArray(0)) { acc, f -> acc + Files.readAllBytes(f) }
        assertFalse(String(bytes, Charsets.ISO_8859_1).contains(marker), "purged notes are gone from the file")
    }

    @Test
    fun keystore6_keyFilesAreReplacedWhole() {
        val dir = Files.createTempDirectory("pgpony-atomic-test")
        val store = KeyMaterialStore(dir)
        store.storeSecret("ABCD", "first")
        store.storeSecret("ABCD", "second")
        assertEquals("second", store.loadSecret("ABCD"))
        if (posix()) assertEquals("rw-------", perms(dir.resolve("abcd.sec.asc")))
        Files.list(dir).use { list -> assertTrue(list.noneMatch { it.fileName.toString().endsWith(".tmp") }, "no temp files left") }

        // A write that cannot complete leaves the old file and no temporary file.
        val target = dir.resolve("blocked")
        Files.createDirectories(target.resolve("inside"))
        assertFails { OwnerOnlyPaths.writeAtomically(target, "new".toByteArray()) }
        assertTrue(Files.isDirectory(target))
        Files.list(dir).use { list -> assertTrue(list.noneMatch { it.fileName.toString().endsWith(".tmp") }) }
    }

    // ── KEYSTORE-4: a contact becomes a key pair only with proof ──

    /** [g]'s certificate with its primary rewritten as a secret key packet holding junk. */
    private fun junkSecret(g: com.pgpony.android.crypto.GeneratedKeyResult, protected: Boolean): String {
        val packets = CertificateBindings.packets(g.publicKeyData)
        val out = ByteArrayOutputStream()
        val rnd = SecureRandom()
        for (p in packets) {
            if (p.tag == 14) break
            if (p.tag == 6) {
                val tail = if (protected) {
                    // S2K usage 254, AES-256, iterated and salted SHA-256, IV, junk "ciphertext".
                    byteArrayOf(254.toByte(), 9, 3, 8) + ByteArray(8).also { rnd.nextBytes(it) } +
                        byteArrayOf(0x60) + ByteArray(16 + 80).also { rnd.nextBytes(it) }
                } else {
                    val mpi = ByteArray(32).also { rnd.nextBytes(it); it[0] = (it[0].toInt() or 0x80).toByte() }
                    val sum = (byteArrayOf(0x01, 0x00) + mpi).sumOf { it.toInt() and 0xFF } and 0xFFFF
                    byteArrayOf(0, 0x01, 0x00) + mpi + byteArrayOf((sum shr 8).toByte(), sum.toByte())
                }
                out.write(CertificateBindings.frame(5, p.body + tail))
            } else {
                out.write(CertificateBindings.frame(p.tag, p.body))
            }
        }
        return armorPrivate(out.toByteArray())
    }

    @Test
    fun keystore4_junkSecretsNeverTurnAContactIntoAKeyPair() = runBlocking {
        val e = env()
        val alice = gen("Alice")
        e.repo.importArmoredKeyDetailed(alice.armoredPublicKey)

        // Junk "encrypted" secret: waits for a passphrase, and no passphrase opens it.
        assertEquals(ImportResolution.NEEDS_PASSPHRASE, e.repo.importArmoredKeyDetailed(junkSecret(alice, protected = true)))
        assertFalse(e.repo.byFingerprint(alice.fingerprint)!!.isKeyPair)
        val waiting = e.repo.pendingSecrets.value.single()
        assertEquals(SecretKeyCheck.SecretMatch.WRONG_PASSPHRASE, e.repo.completeSecretUpgrade(waiting, "guess".toCharArray()))
        assertFalse(e.repo.byFingerprint(alice.fingerprint)!!.isKeyPair)
        e.repo.dismissPendingSecret(alice.fingerprint)

        // Junk unprotected secret: refused at once and named in the report.
        val report = e.repo.importArmoredText(junkSecret(alice, protected = false))
        assertEquals(1, report.failed, report.summary())
        assertEquals(1, report.refused.size)
        val row = e.repo.byFingerprint(alice.fingerprint)!!
        assertFalse(row.isKeyPair)
        assertNull(e.repo.exportArmoredPrivateKey(alice.fingerprint), "nothing stored")

        // The genuine secret with its passphrase upgrades.
        e.repo.importArmoredKeyDetailed(alice.armoredPrivateKey)
        val real = e.repo.pendingSecrets.value.single()
        assertEquals(SecretKeyCheck.SecretMatch.OK, e.repo.completeSecretUpgrade(real, pass.toCharArray()))
        assertTrue(e.repo.byFingerprint(alice.fingerprint)!!.isKeyPair)

        // An unprotected genuine secret upgrades directly.
        val bob = gen("Bob", null)
        e.repo.importArmoredKeyDetailed(bob.armoredPublicKey)
        assertEquals(ImportResolution.UPGRADED_TO_KEY_PAIR, e.repo.importArmoredKeyDetailed(bob.armoredPrivateKey))
        e.db.close()
    }

    // ── KEYSTORE-5: several secret keys in one armor block ──

    @Test
    fun keystore5_eachKeyOfAMultiKeyBlockIsStoredOnItsOwn() = runBlocking {
        val e = env()
        val one = gen("One")
        val two = gen("Two")
        val block = armorPrivate(one.privateKeyData + two.privateKeyData)
        assertEquals(2, e.repo.previewArmoredText(block).size)
        val report = e.repo.importArmoredText(block)
        assertEquals(2, report.inserted, report.summary())
        for (k in listOf(one, two)) {
            assertTrue(e.repo.byFingerprint(k.fingerprint)!!.isKeyPair)
            val raw = CompositeSigPacket.dearmor(e.repo.exportArmoredPrivateKey(k.fingerprint)!!)
            val primaries = CertificateBindings.packets(raw).filter { it.tag == 5 }
            assertEquals(1, primaries.size, "one key per stored secret")
            assertNotNull(e.repo.loadSecretKeyRing(k.fingerprint))
        }
        // A direct call with the whole block stores only its first key.
        val e2 = env()
        e2.repo.importArmoredKeyDetailed(block)
        val raw = CompositeSigPacket.dearmor(e2.repo.exportArmoredPrivateKey(one.fingerprint)!!)
        assertEquals(1, CertificateBindings.packets(raw).count { it.tag == 5 })
        e.db.close(); e2.db.close()
    }

    // ── KEYSTORE-8: refresh stamps only a verified revocation ──

    private fun signatureOf(armored: String): org.bouncycastle.openpgp.PGPSignature {
        val raw = CompositeSigPacket.dearmor(armored)
        val list = BcPGPObjectFactory(raw).nextObject() as PGPSignatureList
        return list[0]
    }

    @Test
    fun keystore8_aRevocationMadeByAnotherKeyIsNotApplied() = runBlocking {
        val e = env()
        val alice = gen("Alice")
        val mallory = gen("Mallory")
        e.repo.importArmoredKeyDetailed(alice.armoredPublicKey)
        val malloryRing = PGPSecretKeyRing(mallory.privateKeyData, BcKeyFingerprintCalculator())
        val foreign = signatureOf(
            RevocationService.shared.generateRevocationCertificate(malloryRing, RevocationReason.COMPROMISED, null, pass)
        )
        val aliceRing = PGPPublicKeyRing(alice.publicKeyData, BcKeyFingerprintCalculator())
        val forged = PGPPublicKeyRing.insertPublicKey(aliceRing, PGPPublicKey.addCertification(aliceRing.publicKey, foreign))
        val refresh = DesktopKeyRefresh(e.repo)
        val r = refresh.processFetchedArmored(e.repo.byFingerprint(alice.fingerprint)!!, crypto.exportArmoredPublicKey(forged))
        assertFalse(r is KeyRefreshResult.RevokedUpstream, r.toString())
        assertFalse(e.repo.byFingerprint(alice.fingerprint)!!.isRevoked)

        // Alice's own revocation is applied, with its time and reason.
        val aliceSecret = PGPSecretKeyRing(alice.privateKeyData, BcKeyFingerprintCalculator())
        val own = signatureOf(
            RevocationService.shared.generateRevocationCertificate(aliceSecret, RevocationReason.COMPROMISED, null, pass)
        )
        val revoked = PGPPublicKeyRing.insertPublicKey(aliceRing, PGPPublicKey.addCertification(aliceRing.publicKey, own))
        val r2 = refresh.processFetchedArmored(e.repo.byFingerprint(alice.fingerprint)!!, crypto.exportArmoredPublicKey(revoked))
        assertTrue(r2 is KeyRefreshResult.RevokedUpstream, r2.toString())
        val row = e.repo.byFingerprint(alice.fingerprint)!!
        assertTrue(row.isRevoked)
        assertEquals(RevocationReason.COMPROMISED, row.revocationReason)
        assertEquals(own.creationTime.time, row.revokedAt)
        e.db.close()
    }

    // ── KEYSTORE-9: the D1 keyring file ──

    @Test
    fun keystore9_clearAllDataRemovesTheMigratedKeyringFile() = runBlocking {
        val e = env()
        e.repo.generateKey("Gone", "gone@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        val leftover = e.dir.resolve("keyring.json.migrated")
        Files.writeString(leftover, "[{\"armored\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\"}]")
        ClearAllData.dataDirOverride = e.dir
        ClearAllData.prefsRootOverride = TreePrefs(null, "")
        try {
            ClearAllData.run(e.edits)
        } finally {
            ClearAllData.dataDirOverride = null
            ClearAllData.prefsRootOverride = null
        }
        assertFalse(Files.exists(leftover))
        assertFalse(Files.exists(e.dir.resolve("keys")))
        e.db.close()

        // The migration also removes a leftover from an older version.
        val e2 = env()
        val old = e2.dir.resolve("keyring.json.migrated")
        Files.writeString(old, "[]")
        assertNull(e2.repo.migrateLegacyJson(e2.dir.resolve("keyring.json")))
        assertFalse(Files.exists(old))
        e2.db.close()
    }

    // ── PAIRING-IMPL-6: a partly protected key goes under the transfer passphrase ──

    private fun protectPrimaryOnly(raw: ByteArray, primaryPass: String): ByteArray {
        val ring = PGPSecretKeyRing(raw, BcKeyFingerprintCalculator())
        val sha1 = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1)
        val primary = PGPSecretKey.copyWithNewPassword(
            ring.secretKey, null, S2kPolicy.v4EncryptorBuilder().build(primaryPass.toCharArray()), sha1
        )
        return PGPSecretKeyRing.insertSecretKey(ring, primary).encoded
    }

    @Test
    fun pairingImpl6_aKeyWithAnUnprotectedSubkeyIsNotSentAsStored() = runBlocking {
        val e = env()
        val mixed = gen("Mixed", null)
        val mixedRaw = protectPrimaryOnly(mixed.privateKeyData, "own")
        assertEquals(ImportResolution.INSERTED, e.repo.importArmoredKeyDetailed(armorPrivate(mixedRaw)))
        val fp = mixed.fingerprint
        assertFalse(e.edits.isPassphraseProtected(fp), "an unprotected subkey makes the key unprotected")
        assertTrue(e.edits.needsPassphrase(fp))
        assertNull(e.edits.transferArmor(fp, null), "no transfer passphrase, nothing to send")

        val sent = e.edits.transferArmor(fp, "transfer")!!
        assertTrue(SecretKeyCheck.isFullyPassphraseProtected(sent.toByteArray()))
        val ring = PGPSecretKeyRing(CompositeSigPacket.dearmor(sent), BcKeyFingerprintCalculator())
        assertNotNull(SecretKeyUnlock.extract(ring.secretKey, "own".toCharArray()))
        val sub = ring.secretKeys.asSequence().first { !it.isMasterKey }
        assertNotNull(SecretKeyUnlock.extract(sub, "transfer".toCharArray()))
        assertFalse(e.edits.isPassphraseProtected(fp), "the stored key is unchanged")

        // Changing the passphrase protects every part.
        e.edits.changePassphrase(fp, "own", "new-pass")
        assertTrue(e.edits.isPassphraseProtected(fp))
        assertEquals(e.repo.exportArmoredPrivateKey(fp), e.edits.transferArmor(fp, null))

        // A key with no passphrase at all goes wholly under the transfer passphrase.
        val bare = gen("Bare", null)
        e.repo.importArmoredKeyDetailed(bare.armoredPrivateKey)
        val bareSent = e.edits.transferArmor(bare.fingerprint, "t")!!
        assertTrue(SecretKeyCheck.isFullyPassphraseProtected(bareSent.toByteArray()))
        e.db.close()
    }

    // ── SUPPLY-4: automatic key refresh default ──

    @Test
    fun supply4_refreshIsOffForNewInstallsAndKeptForExistingOnes() {
        try {
            DesktopNetworkPrefs.prefsOverride = MemoryPreferences()
            DesktopNetworkPrefs.settleDefault(existingInstall = false)
            assertFalse(DesktopNetworkPrefs.autoRefresh(), "new install: off")
            DesktopNetworkPrefs.settleDefault(existingInstall = true)
            assertFalse(DesktopNetworkPrefs.autoRefresh(), "decided once")

            DesktopNetworkPrefs.prefsOverride = MemoryPreferences()
            DesktopNetworkPrefs.settleDefault(existingInstall = true)
            assertTrue(DesktopNetworkPrefs.autoRefresh(), "existing install keeps the old default")

            DesktopNetworkPrefs.prefsOverride = MemoryPreferences()
            DesktopNetworkPrefs.setAutoRefresh(true)
            DesktopNetworkPrefs.settleDefault(existingInstall = false)
            assertTrue(DesktopNetworkPrefs.autoRefresh(), "the user's own choice stays")
        } finally {
            DesktopNetworkPrefs.prefsOverride = null
        }
    }

    private fun assertFails(block: () -> Unit) {
        val failed = try { block(); false } catch (_: Exception) { true }
        assertTrue(failed, "expected a failure")
    }
}

/** A preferences tree in memory, for the Clear All Data test. */
private class TreePrefs(parent: TreePrefs?, name: String) : AbstractPreferences(parent, name) {
    private val values = mutableMapOf<String, String>()
    override fun putSpi(key: String, value: String) { values[key] = value }
    override fun getSpi(key: String): String? = values[key]
    override fun removeSpi(key: String) { values.remove(key) }
    override fun removeNodeSpi() { values.clear() }
    override fun keysSpi(): Array<String> = values.keys.toTypedArray()
    override fun childrenNamesSpi(): Array<String> = emptyArray()
    override fun childSpi(name: String): AbstractPreferences = TreePrefs(this, name)
    override fun syncSpi() {}
    override fun flushSpi() {}
}
