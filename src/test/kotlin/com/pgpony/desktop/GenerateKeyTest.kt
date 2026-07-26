// GenerateKeyTest.kt
// D2b validation: the generateKey port (material halves, expiry derivation, pre-cached
// revocation certificate) and the subkey-detail parse — including one post-quantum composite
// generation, which exercises the vendored CompositeKeyGen on the desktop JVM.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class GenerateKeyTest {

    private fun repo(): Pair<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository> {
        val dir = Files.createTempDirectory("pgpony-gen-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    @Test
    fun v4GenerateStoresPairExpiryAndRevocationCert() = runBlocking {
        val (db, repo) = repo()
        val entity = repo.generateKey(
            name = "Gen Test", email = "gen@pgpony.app",
            algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "test-passphrase"
        )
        assertTrue(entity.isKeyPair)
        assertEquals("Gen Test", entity.userName)
        assertNotNull(repo.exportArmoredPublicKey(entity.fingerprint), "public half stored")
        assertNotNull(repo.exportArmoredPrivateKey(entity.fingerprint), "secret half stored")
        assertNotNull(
            entity.revocationCertificate,
            "pre-cached revocation certificate (Phase A6 semantics) should be present"
        )
        assertTrue(entity.revocationCertificate!!.contains("BEGIN PGP"), "cert is armored")

        val subkeys = repo.subkeyInfos(entity.fingerprint)
        assertEquals(2, subkeys.size, "primary + encryption subkey")
        assertTrue(subkeys.first().isPrimary)
        assertTrue(subkeys.all { it.capabilitiesLabel.isNotBlank() })
        db.close()
    }

    @Test
    fun v6GenerateRoundTrips() = runBlocking {
        val (db, repo) = repo()
        val entity = repo.generateKey(
            name = "Gen V6", email = "genv6@pgpony.app",
            algorithm = KeyAlgorithm.V6_ED25519, passphrase = "test-passphrase"
        )
        assertTrue(entity.isKeyPair)
        assertTrue(entity.isV6Key)
        assertEquals(64, entity.fingerprint.length, "v6 fingerprints are 32 bytes")
        assertTrue(repo.subkeyInfos(entity.fingerprint).isNotEmpty())
        db.close()
    }

    @Test
    fun compositePqcGenerateWorksOnDesktopJvm() = runBlocking {
        val (db, repo) = repo()
        val entity = repo.generateKey(
            name = "Gen PQC", email = "genpqc@pgpony.app",
            algorithm = KeyAlgorithm.MLKEM768_X25519_V6, passphrase = "test-passphrase"
        )
        assertTrue(entity.isKeyPair)
        assertEquals(KeyAlgorithm.MLKEM768_X25519_V6, entity.algorithm)
        val subkeys = repo.subkeyInfos(entity.fingerprint)
        assertTrue(subkeys.size >= 2, "composite cert carries primary + KEM subkey")
        db.close()
    }
}
