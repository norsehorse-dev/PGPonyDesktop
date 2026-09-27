// PublishStatusTest.kt
// PGPony Desktop 3.0.0, stage 3 checkpoint 3c (plan 6.1, 6.2): the per-server upload record,
// the out-of-date marker, the addresses the confirmation lines check, and the ambiguous-primary
// refusal (Android 4.6.0 items 9 and 11).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.KeyPublicationStore
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PublishStatusTest {

    private val pass = "publish-passphrase"

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() = SettingsStores.uninstall()

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, DesktopKeyEdits> {
        val dir = Files.createTempDirectory("pgpony-publish-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        return Triple(db, repo, DesktopKeyEdits(repo))
    }

    @Test
    fun uploadIsRecordedPerServerAndAnEditMarksItOutOfDate() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Pub", "pub@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        repo.markKeyServerUploaded(k.fingerprint, "keys.pgpony.app")
        assertTrue("keys.pgpony.app" in KeyPublicationStore.servers(k.fingerprint))
        val uploaded = repo.byFingerprint(k.fingerprint)!!
        assertTrue(uploaded.keyServerUploaded)
        assertFalse(uploaded.hasUnpublishedChanges)

        Thread.sleep(5)
        edits.addUserId(k.fingerprint, "Pub Work <work@pgpony.app>", makePrimary = false, passphrase = pass)
        assertTrue(repo.byFingerprint(k.fingerprint)!!.hasUnpublishedChanges, "edited since the upload")
        assertEquals(setOf("pub@pgpony.app", "work@pgpony.app"), repo.publishedAddresses(k.fingerprint).toSet())
        db.close()
    }

    @Test
    fun anAmbiguousPrimaryIsNotPublished() = runBlocking {
        val (db, repo, edits) = temp()
        val k = repo.generateKey("Prim", "prim@pgpony.app", KeyAlgorithm.ED25519_CV25519, pass)
        // A non-primary add pins the original User ID with an explicit primary flag.
        edits.addUserId(k.fingerprint, "Other <other@pgpony.app>", makePrimary = false, passphrase = pass)
        assertTrue(repo.publishPayload(k.fingerprint, k.userID) is DesktopKeyRepository.PublishPayload.Ready)
        val refused = assertIs<DesktopKeyRepository.PublishPayload.NeedsRepair>(
            repo.publishPayload(k.fingerprint, "Other <other@pgpony.app>"),
            "the shown User ID is not the flagged primary"
        )
        assertEquals(listOf(k.userID), refused.flagged)
        db.close()
    }
}
