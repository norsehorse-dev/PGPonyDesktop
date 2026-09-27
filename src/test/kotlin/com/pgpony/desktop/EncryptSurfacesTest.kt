// EncryptSurfacesTest.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4a (plan section 7): the per-recipient encryption
// subkey choice reaches the message, the post-quantum weak-link rule, and the armor Comment
// setting (validator and the cache every process loads at startup).

package com.pgpony.desktop

import com.pgpony.android.crypto.AddSubkeyChoice
import com.pgpony.android.crypto.ClassicalSubkeyGen
import com.pgpony.android.crypto.EncryptionKeyOption
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.ArmorCommentDefaults
import com.pgpony.android.data.ArmorCommentHeader
import com.pgpony.android.data.ArmorCommentPrefs
import com.pgpony.android.data.ArmorCommentValidator
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EncryptSurfacesTest {

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
    }

    @AfterTest
    fun unhook() {
        SettingsStores.uninstall()
        ArmorCommentPrefs.prefsOverride = null
        ArmorCommentHeader.current = ArmorCommentDefaults.DEFAULT_COMMENT
        ArmorCommentHeader.pubkeyCurrent = ArmorCommentDefaults.DEFAULT_COMMENT
    }

    @Test
    fun chosenEncryptionSubkeyIsTheOneUsed() = runBlocking {
        val dir = Files.createTempDirectory("pgpony-subkey-choice")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        val k = repo.generateKey("Two Enc", "twoenc@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        DesktopKeyEdits(repo).addSubkey(
            k.fingerprint, AddSubkeyChoice.Classical(ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT), null, null
        )
        val entity = repo.byFingerprint(k.fingerprint)!!
        val t = EncryptOps.recipientTargets(repo, listOf(entity)).single()
        assertEquals(2, t.options.size, "two encryption subkeys to choose from")
        for (opt in t.options) {
            val ops = EncryptOps(repo)
            val plan = ops.plan(listOf(k.fingerprint), null, null, null, mapOf(t.fingerprint to opt.keyId))
            val armored = String(ops.encryptBytes(plan, "hi".toByteArray(), null, armor = true))
            assertEquals(listOf(opt.keyId), PGPCryptoService.shared.recipientKeyIDs(armored))
        }
        db.close()
    }

    private fun opt(id: Long, pq: Boolean) = EncryptionKeyOption(id, String.format("%016X", id), false, pq, if (pq) "ML-KEM" else "X25519")

    @Test
    fun weakLinksNameTheClassicalRecipientsOfAMixedSet() {
        val pq = EncryptOps.RecipientTargets("A", "Alice", listOf(opt(1, true), opt(2, false)), false)
        val classic = EncryptOps.RecipientTargets("B", "Bob", listOf(opt(3, false)), false)
        val v4 = EncryptOps.RecipientTargets("C", "Carol", listOf(opt(4, false)), true)
        assertEquals(listOf("Bob"), EncryptOps.pqWeakLinks(listOf(pq, classic), emptyMap()))
        assertTrue(EncryptOps.pqWeakLinks(listOf(pq, v4), emptyMap()).isEmpty(), "a v4 interop key receives on ML-KEM")
        assertEquals(listOf("Alice", "Bob"), EncryptOps.pqWeakLinks(listOf(pq, classic, v4), mapOf("A" to 2L)),
            "choosing Alice's classical subkey makes her a weak link too")
        assertTrue(EncryptOps.pqWeakLinks(listOf(classic), emptyMap()).isEmpty(), "one recipient is never mixed")
    }

    @Test
    fun armorCommentValidatesAndLoadsIntoTheCache() {
        assertEquals("hello world", ArmorCommentValidator.sanitize("  :: hello\r\n world "))
        assertNull(ArmorCommentValidator.validate(true, " : "))
        assertEquals(80, ArmorCommentValidator.sanitize("x".repeat(200)).length)

        ArmorCommentPrefs.prefsOverride = MemoryPreferences()
        ArmorCommentPrefs.load()
        assertEquals(ArmorCommentDefaults.DEFAULT_COMMENT, ArmorCommentHeader.current, "default on")
        ArmorCommentPrefs.setText("My keys at example.org")
        assertEquals("My keys at example.org", ArmorCommentHeader.current)
        ArmorCommentPrefs.setInclude(false)
        assertNull(ArmorCommentHeader.current)
        assertEquals("My keys at example.org", ArmorCommentHeader.pubkeyCurrent, "the public-key toggle is separate")
    }
}
