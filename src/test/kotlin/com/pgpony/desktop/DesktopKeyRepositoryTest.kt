// DesktopKeyRepositoryTest.kt
// D2a validation: the vendored Room schema + DAO run on the JVM (bundled SQLite), the repository
// preserves the Android import semantics (insert / upgrade / never-downgrade), and the D1 JSON
// store migrates in cleanly.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.PGPDatabase
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopKeyRepositoryTest {

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, Path> {
        val dir = Files.createTempDirectory("pgpony-repo-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Triple(db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))), dir)
    }

    private fun generate(name: String = "Repo Test", email: String = "repo@pgpony.app") =
        PGPCryptoService.shared.generateKeyPair(
            name = name, email = email,
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "test-passphrase"
        )

    @Test
    fun insertUpgradeNeverDowngradeAndReopen() = runBlocking {
        val (db, repo, dir) = temp()
        val gen = generate()

        assertEquals(ImportResolution.INSERTED, repo.importArmoredKeyDetailed(gen.armoredPublicKey))
        assertEquals(ImportResolution.ALREADY_IN_KEYRING, repo.importArmoredKeyDetailed(gen.armoredPublicKey))
        assertEquals(ImportResolution.UPGRADED_TO_KEY_PAIR, repo.importArmoredKeyDetailed(gen.armoredPrivateKey))
        // A held secret is never overwritten by a public re-import (restore rule).
        assertEquals(ImportResolution.ALREADY_IN_KEYRING, repo.importArmoredKeyDetailed(gen.armoredPublicKey))

        val row = repo.byFingerprint(gen.fingerprint)
        assertNotNull(row)
        assertTrue(row.isKeyPair, "row should hold the pair after upgrade")
        assertEquals("Repo Test", row.userName)
        assertEquals("repo@pgpony.app", row.userEmail)
        assertNotNull(repo.exportArmoredPublicKey(gen.fingerprint), "public armor stored")
        assertNotNull(repo.exportArmoredPrivateKey(gen.fingerprint), "secret armor stored")
        db.close()

        // Reopen: metadata + material survive.
        val db2 = Db.open(dir.resolve("pgpony.db"))
        val repo2 = DesktopKeyRepository(db2, KeyMaterialStore(dir.resolve("keys")))
        assertEquals(1, repo2.count())
        assertTrue(repo2.allKeys().single().isKeyPair)
        db2.close()
    }

    @Test
    fun deleteRemovesRowAndMaterial() = runBlocking {
        val (db, repo, _) = temp()
        val gen = generate(name = "Delete Me", email = "del@pgpony.app")
        repo.importArmoredKeyDetailed(gen.armoredPrivateKey)
        assertEquals(1, repo.count())

        repo.deleteByFingerprint(gen.fingerprint)
        assertEquals(0, repo.count())
        assertNull(repo.exportArmoredPublicKey(gen.fingerprint))
        assertNull(repo.exportArmoredPrivateKey(gen.fingerprint))
        db.close()
    }

    @Test
    fun legacyJsonStoreMigratesOnce() = runBlocking {
        val (db, repo, dir) = temp()
        val gen = generate(name = "Legacy", email = "legacy@pgpony.app")
        val legacy = dir.resolve("keyring.json")
        // Minimal D1-store shape: the migrator reads only fingerprint + armored.
        val armoredJson = gen.armoredPublicKey
            .replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "")
        Files.writeString(
            legacy,
            """[{"fingerprint":"${gen.fingerprint}","armored":"$armoredJson"}]"""
        )

        val report = repo.migrateLegacyJson(legacy)
        assertNotNull(report)
        assertEquals(1, report.inserted)
        assertTrue(Files.exists(dir.resolve("keyring.json.migrated")), "legacy file renamed")
        assertEquals(1, repo.count())

        // Second call: nothing to do.
        assertNull(repo.migrateLegacyJson(legacy))
        db.close()
    }

    @Test
    fun multiBlockTextImportsBoth() = runBlocking {
        val (db, repo, _) = temp()
        val a = generate(name = "A", email = "a@pgpony.app")
        val b = generate(name = "B", email = "b@pgpony.app")
        val blob = a.armoredPublicKey + "\nprose between blocks\n" + b.armoredPublicKey
        assertEquals(2, DesktopKeyRepository.splitArmoredBlocks(blob).size)
        val report = repo.importArmoredText(blob)
        assertEquals(2, report.inserted)
        db.close()
    }
}
