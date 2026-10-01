// KeyStoreReviewTest.kt
// PGPony Desktop 3.0.0: key storage follow-ups. An import made of several calls (gpg's public
// export, then each secret) and an OpenKeychain backup (public ring before secret ring) take the
// secrets of keys they inserted themselves without a passphrase prompt; a secret file an older
// version stored with several keys hands out only its own key, and an old backup of it still
// restores; the D1 keyring file keeps the entries that did not import.

package com.pgpony.desktop

import com.pgpony.android.backup.CrockfordBase32
import com.pgpony.android.backup.UstarArchive
import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.bouncycastle.bcpg.ArmoredOutputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class KeyStoreReviewTest {

    private val crypto = PGPCryptoService.shared
    private val pass = "test-passphrase"

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() = SettingsStores.uninstall()

    private class Env(val dir: Path, val db: PGPDatabase, val repo: DesktopKeyRepository)

    private fun env(): Env {
        val dir = Files.createTempDirectory("pgpony-c-review")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Env(dir, db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))))
    }

    private fun gen(name: String, passphrase: String? = pass) =
        crypto.generateKeyPair(name, "${name.lowercase()}@pgpony.app", KeyAlgorithm.ED25519_CV25519, passphrase)

    private fun armorPrivate(raw: ByteArray) =
        CompositeSigPacket.armor("-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", raw)

    private fun armorMessage(sealed: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).apply { write(sealed); close() }
        return out.toByteArray()
    }

    @Test
    fun anImportOfSeveralCallsTakesTheSecretOfAKeyItInserted() = runBlocking {
        val e = env()
        val own = gen("Own")
        val session = HashSet<String>()
        assertEquals(1, e.repo.importBytes(own.armoredPublicKey.toByteArray(), session).inserted)
        val r = e.repo.importBytes(own.armoredPrivateKey.toByteArray(), session)
        assertEquals(1, r.upgraded, r.summary())
        assertTrue(r.pending.isEmpty())
        assertTrue(e.repo.byFingerprint(own.fingerprint)!!.isKeyPair)

        // Without the session the contact was already held: the protected secret waits.
        val e2 = env()
        e2.repo.importBytes(own.armoredPublicKey.toByteArray())
        val r2 = e2.repo.importBytes(own.armoredPrivateKey.toByteArray())
        assertEquals(1, r2.pending.size, r2.summary())
        assertFalse(e2.repo.byFingerprint(own.fingerprint)!!.isKeyPair)
        e.db.close(); e2.db.close()
    }

    @Test
    fun anOpenKeychainBackupRestoresOwnKeysWithoutAPrompt() = runBlocking {
        val e = env()
        val own = gen("Own")
        val contact = gen("Contact")
        val plain = (own.armoredPublicKey + "\n" + own.armoredPrivateKey + "\n" + contact.armoredPublicKey)
            .toByteArray()
        val code = "1234-5678-9012-3456-7890-1234-5678-9012-3456"
        val sealed = crypto.encryptSymmetric(plain, code, null, armor = false, useAead = false, useArgon2 = false)
        val report = DesktopBackupService(e.repo).restoreOpenKeychainBackup(armorMessage(sealed), code)
        assertTrue(report.pending.isEmpty(), report.summary())
        assertTrue(e.repo.byFingerprint(own.fingerprint)!!.isKeyPair)
        assertFalse(e.repo.byFingerprint(contact.fingerprint)!!.isKeyPair)
        assertTrue(e.repo.pendingSecrets.value.isEmpty())
        e.db.close()
    }

    @Test
    fun anOldSecretFileWithSeveralKeysHandsOutOnlyItsOwnKey() = runBlocking {
        val e = env()
        val first = gen("First")
        val hidden = gen("Hidden")
        e.repo.importArmoredKeyDetailed(first.armoredPrivateKey)
        // What an older version stored for a pasted gpg export of two keys.
        val oldFile = armorPrivate(first.privateKeyData + hidden.privateKeyData)
        e.repo.materials.storeSecret(first.fingerprint, oldFile)

        val exported = e.repo.exportArmoredPrivateKey(first.fingerprint)!!
        val primaries = CertificateBindings.packets(CompositeSigPacket.dearmor(exported)).filter { it.tag == 5 }
        assertEquals(1, primaries.size, "only the key itself leaves")
        assertNotNull(e.repo.loadSecretKeyRing(first.fingerprint))

        // A backup an older version made of that file restores the named key only.
        val code = CrockfordBase32.generate().canonical
        val tar = UstarArchive.write(
            listOf(
                UstarArchive.Entry("pgpony-meta.json", """{"formatVersion":1,"keys":[]}""".toByteArray()),
                UstarArchive.Entry("keys/${first.fingerprint.lowercase()}.asc", oldFile.toByteArray())
            )
        )
        val sealed = crypto.encryptSymmetric(tar, code, null, armor = false, useAead = false, useArgon2 = false)
        val e2 = env()
        val report = DesktopBackupService(e2.repo).restoreBackup(armorMessage(sealed), code)
        assertEquals(1, report.added.size, report.summary())
        assertTrue(report.failed.isEmpty())
        assertTrue(e2.repo.byFingerprint(first.fingerprint)!!.isKeyPair)
        assertEquals(null, e2.repo.byFingerprint(hidden.fingerprint), "the hidden key is not imported")
        val restored = CompositeSigPacket.dearmor(e2.repo.exportArmoredPrivateKey(first.fingerprint)!!)
        assertEquals(1, CertificateBindings.packets(restored).count { it.tag == 5 })
        e.db.close(); e2.db.close()
    }

    private fun legacyJson(vararg entries: Pair<String, String>): String =
        Json.encodeToString(
            JsonArray.serializer(),
            JsonArray(entries.map { (fp, armored) ->
                JsonObject(mapOf("fingerprint" to JsonPrimitive(fp), "armored" to JsonPrimitive(armored)))
            })
        )

    @Test
    fun theLegacyKeyringKeepsOnlyEntriesThatDidNotImport() = runBlocking {
        val e = env()
        val good = gen("Good")
        val junk = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
        val file = e.dir.resolve("keyring.json")
        Files.writeString(file, legacyJson(good.fingerprint to good.armoredPrivateKey, "00" to junk))
        val report = e.repo.migrateLegacyJson(file)!!
        assertEquals(1, report.inserted, report.summary())
        assertEquals(1, report.failed)
        assertTrue(e.repo.byFingerprint(good.fingerprint)!!.isKeyPair)
        assertTrue(Files.exists(file), "the entry that failed is kept")
        val kept = Files.readString(file)
        assertTrue(kept.contains("\"00\""))
        assertFalse(kept.contains(good.fingerprint), "the imported key is not kept")

        // Once everything has imported, the file goes.
        Files.writeString(file, legacyJson(good.fingerprint to good.armoredPrivateKey))
        e.repo.migrateLegacyJson(file)
        assertFalse(Files.exists(file))
        e.db.close()
    }
}
