// KeygenTest.kt
// PGPony Desktop 3.0.0, stage 3 checkpoint 3a (plan 4.1): the Android 4.6.1 key generation
// roster and options. Name-only keys, the v4 ML-KEM-768 interop shape, the brainpool LibrePGP
// form, granular composition, the SSH subkey at generation, the pre-cached revocation
// certificate and expiry.

package com.pgpony.desktop

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.GranularSubkeySpec
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.pqc.CompositeSuite
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class KeygenTest {

    private val pass = "keygen-passphrase"

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() = SettingsStores.uninstall()

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, DesktopKeyEdits> {
        val dir = Files.createTempDirectory("pgpony-keygen-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        return Triple(db, repo, DesktopKeyEdits(repo))
    }

    private fun isAuth(row: DesktopKeyEdits.SubkeyRow) = (row.capabilities and 0x08) != 0

    @Test
    fun nameOnlyKeyHasNoEmptyAngleBrackets() = runBlocking {
        val (db, repo, _) = temp()
        val k = repo.generateKey("Solo", "", KeyAlgorithm.ED25519_CV25519, null)
        assertEquals("Solo", k.userID)
        assertEquals("", k.userEmail)
        val c = repo.generateKey("Solo PQ", "", KeyAlgorithm.MLDSA65_ED25519_V6, null)
        assertEquals("Solo PQ", c.userID)
        db.close()
    }

    @Test
    fun classicalKeyGetsExpiryAndARevocationCertificate() = runBlocking {
        val (db, repo, _) = temp()
        val twoYears = KeygenExpiry.TWO_YEARS.seconds!!
        val k = repo.generateKey("Exp", "exp@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass, twoYears)
        val expires = assertNotNull(k.expiresAt)
        assertTrue(kotlin.math.abs(expires - (System.currentTimeMillis() + twoYears * 1000)) < 60_000)
        assertNotNull(k.revocationCertificate, "pre-cached from the binary secret ring")
        db.close()
    }

    @Test
    fun v4InteropKeyCarriesItsMlKemSubkey() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("V4 PQ", "v4pq@pgpony.app", KeyAlgorithm.MLKEM768_X25519_V4, pass)
        assertEquals(KeyAlgorithm.MLKEM768_X25519_V4, k.algorithm)
        assertNotNull(repo.loadV4Algo35Recipient(k.fingerprint), "the algo-35 subkey is there and bound")
        assertNotNull(repo.loadSecretKeyRing(k.fingerprint), "the v4 base ring still loads for signing")
        assertTrue(edits.subkeyRows(k).any { it.algorithmLabel.startsWith("ML-KEM") })
        db.close()
    }

    @Test
    fun brainpoolLibrePgpKeyGenerates() = runBlocking {
        val (db, repo, _) = temp()
        val k = repo.generateKey("BP", "bp@pgpony.app", KeyAlgorithm.MLKEM768_BP256_LIBREPGP, null)
        assertEquals(KeyAlgorithm.MLKEM768_BP256_LIBREPGP, k.algorithm)
        assertNotNull(repo.loadPublicKeyRing(k.fingerprint))
        db.close()
    }

    @Test
    fun granularKeyHasExactlyTheChosenSubkeys() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateGranularKey(
            "Granular", "granular@pgpony.app",
            includeDefaultEncryptionSubkey = false,
            subkeys = listOf(
                GranularSubkeySpec(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_768), null),
                GranularSubkeySpec(AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH), null)
            ),
            passphrase = pass
        )
        assertEquals(KeyAlgorithm.V6_ED25519, k.algorithm)
        val rows = edits.subkeyRows(repo.byFingerprint(k.fingerprint)!!)
        assertTrue(rows.any { it.algorithmLabel.contains("ML-KEM") }, "ML-KEM subkey: ${rows.map { it.algorithmLabel }}")
        assertTrue(rows.any { isAuth(it) }, "authentication subkey")
        assertFalse(rows.any { it.algorithmLabel == "X25519" }, "the default X25519 subkey was left out")
        db.close()
    }

    @Test
    fun sshSubkeyAtGenerationDoesNotMarkTheKeyEdited() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("SSH", "ssh@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        edits.addSshAuthSubkeyAtGeneration(k.fingerprint, k.algorithm, null, pass)
        val after = repo.byFingerprint(k.fingerprint)!!
        assertTrue(edits.subkeyRows(after).any { isAuth(it) })
        assertNull(after.lastLocalEditAt, "a brand-new key has nothing published to fall behind")
        db.close()
    }

    @Test
    fun cliNamesTheNewShapes() {
        assertEquals(KeyAlgorithm.MLKEM768_X25519_V4, Cli.parseAlgorithm("mlkem-v4"))
        assertEquals(KeyAlgorithm.MLKEM768_BP256_LIBREPGP, Cli.parseAlgorithm("mlkem-brainpool"))
        assertEquals(KeyAlgorithm.MLDSA87_ED448_V6, Cli.parseAlgorithm("mldsa-87"))
        assertEquals(
            AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH),
            Cli.parseSubkey("ed25519-auth")
        )
        assertEquals(AddSubkeyChoice.PqEncryption(CompositeSuite.IETF_1024), Cli.parseSubkey("mlkem-1024"))
    }
}
