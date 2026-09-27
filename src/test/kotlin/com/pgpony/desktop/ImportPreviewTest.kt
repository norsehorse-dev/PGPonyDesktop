// ImportPreviewTest.kt
// PGPony Desktop 3.0.0, stage 3 checkpoint 3d (plan 6.5, 6.6): the import preview reads keys
// out of noisy text without writing anything, and the link importer only takes https (or http
// to a .onion address).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.settings.SettingsStores
import com.pgpony.android.network.UrlKeyFetcher
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

class ImportPreviewTest {

    private val crypto = PGPCryptoService.shared

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() = SettingsStores.uninstall()

    private fun temp(): Pair<PGPDatabase, DesktopKeyRepository> {
        val dir = Files.createTempDirectory("pgpony-preview-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    private fun publicArmor(name: String, email: String) =
        crypto.generateKeyPair(name, email, KeyAlgorithm.ED25519_CV25519, null).armoredPublicKey

    @Test
    fun previewIgnoresSurroundingTextAndWritesNothing() = runBlocking {
        val (db, repo) = temp()
        val armor = publicArmor("Page Key", "page@pgpony.app")
        val noisy = "Here is my key, copied from my site:\n\n$armor\n\nThanks! Posted 2026-09-27."
        val items = repo.previewArmoredText(noisy)
        assertEquals(1, items.size)
        assertEquals(listOf("Page Key <page@pgpony.app>"), items.single().userIds)
        assertFalse(items.single().hasPrivateKey)
        assertFalse(items.single().inKeyring)
        assertTrue(repo.allKeys().isEmpty(), "a preview stores nothing")

        repo.importArmoredText(noisy)
        assertTrue(repo.previewArmoredText(noisy).single().inKeyring)
        db.close()
    }

    @Test
    fun previewListsEveryKeyAndSkipsASignature() = runBlocking {
        val (db, repo) = temp()
        val signature = "-----BEGIN PGP SIGNATURE-----\n\nabcd\n-----END PGP SIGNATURE-----"
        val text = publicArmor("One", "one@pgpony.app") + "\n" + signature + "\n" + publicArmor("Two", "two@pgpony.app")
        assertEquals(2, repo.previewArmoredText(text).size)
        assertTrue(repo.previewArmoredText("no key here").isEmpty())
        db.close()
    }

    @Test
    fun linksMustBeHttpsOrOnion() {
        assertNotNull(UrlKeyFetcher.allowedUri("https://example.org/key.asc"))
        assertNull(UrlKeyFetcher.allowedUri("http://example.org/key.asc"))
        assertNull(UrlKeyFetcher.allowedUri("file:///etc/passwd"))
        assertNotNull(UrlKeyFetcher.allowedUri("http://exampleonionaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/key.asc"))
    }
}
