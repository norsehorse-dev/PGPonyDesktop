// ExpirationNotifierTest.kt
// D9 validation — the key-expiration reminder scan buckets keys into the Android/iOS windows
// (30 / 7 / 1 / 0 days + already-expired), only for renewable (secret, non-revoked) keys.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.PGPKeyEntity
import java.util.concurrent.TimeUnit
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ExpirationNotifierTest {

    // The headline is localized (D11b) and I18n.language follows the OS locale by default, so
    // the assertions below would fail on a German machine. pinEnglish() writes nothing —
    // unlike selectLanguage(), which would touch the real Preferences node from a test.
    @BeforeTest
    fun englishForAssertions() {
        I18n.pinEnglish()
    }

    private val now = 1_700_000_000_000L
    private fun days(n: Long) = TimeUnit.DAYS.toMillis(n)

    private fun key(
        fp: String,
        expiresInDays: Long?,
        isKeyPair: Boolean = true,
        revoked: Boolean = false
    ) = PGPKeyEntity(
        id = fp, fingerprint = fp, userID = "K $fp", userName = "K", userEmail = "k@x.test",
        algorithm = KeyAlgorithm.ED25519_CV25519, isKeyPair = isKeyPair,
        createdAt = now - days(365),
        expiresAt = expiresInDays?.let { now + days(it) },
        isRevoked = revoked
    )

    @Test
    fun bucketsByTightestWindow() {
        val keys = listOf(
            key("A", 40),   // > 30d → silent
            key("B", 20),   // 30d window
            key("C", 5),    // 7d window
            key("D", 1),    // tomorrow (urgent)
            key("E", 0),    // today (urgent)
            key("F", -3)    // already expired (urgent)
        )
        val due = ExpirationNotifier.due(keys, now)
        val fps = due.map { it.entity.fingerprint }.toSet()

        assertTrue("A" !in fps, "40 days out is silent")
        assertEquals(setOf("B", "C", "D", "E", "F"), fps)
        assertTrue(due.first { it.entity.fingerprint == "D" }.urgent)
        assertTrue(due.first { it.entity.fingerprint == "E" }.urgent)
        assertTrue(due.first { it.entity.fingerprint == "F" }.urgent)
        assertTrue(!due.first { it.entity.fingerprint == "C" }.urgent)
        assertTrue(due.first { it.entity.fingerprint == "F" }.daysLeft < 0, "F is already expired")
        assertTrue(due.first { it.entity.fingerprint == "F" }.headline.contains("EXPIRED"))
    }

    @Test
    fun onlyRenewableKeysReport() {
        val keys = listOf(
            key("pub", 5, isKeyPair = false),   // public-only: can't renew → skip
            key("rev", 5, revoked = true),      // revoked → skip
            key("noexp", null),                 // no expiry → skip
            key("ok", 5)                        // secret, expiring → report
        )
        val due = ExpirationNotifier.due(keys, now)
        assertEquals(listOf("ok"), due.map { it.entity.fingerprint })
    }

    @Test
    fun dedupeKeyDistinguishesWindows() {
        val a = ExpirationNotifier.due(listOf(key("X", 5)), now).single()
        val b = ExpirationNotifier.due(listOf(key("X", 20)), now).single()
        assertTrue(a.dedupeKey != b.dedupeKey, "the 7-day and 30-day windows must not collapse")
    }
}
