// SessionPolicyTest.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4b: one session duration for key passphrases, the card
// PIN, SSH agent signing and git signing (plan section 7; Android 4.3.0 #15 and 4.6.1 #15), the
// passphrase cache the decrypt paths use, and the screen-lock probes.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.card.CardPinCache
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionPolicyTest {

    private val cardPrefs = MemoryPreferences()

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
        CardPinCache.prefsOverride = cardPrefs
        SessionPolicy.clearAll()
    }

    @AfterTest
    fun unhook() {
        ScreenLockWatch.assumeRunning = false
        ScreenLockWatch.reset()
        SessionPolicy.clearAll()
        SettingsStores.uninstall()
        CardPinCache.prefsOverride = null
    }

    /** A running watch that has just seen the screen lock and unlock (confirmed on Linux too). */
    private fun trustTheWatch() {
        ScreenLockWatch.assumeRunning = true
        val now = System.currentTimeMillis()
        ScreenLockWatch.step(true, now, ScreenLockWatch.POLL_MS)
        ScreenLockWatch.step(false, System.currentTimeMillis(), ScreenLockWatch.POLL_MS)
        assertTrue(ScreenLockWatch.isTrusted())
    }

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, DesktopKeyEdits> {
        val dir = Files.createTempDirectory("pgpony-session-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        return Triple(db, repo, DesktopKeyEdits(repo))
    }

    // ── The one duration ──

    @Test
    fun oneDurationWithTwoLifecycleChoices() {
        assertEquals(SessionPolicy.DEFAULT_DURATION_SEC, SessionPolicy.durationSec())
        SessionPolicy.setDurationSec(3600)
        assertEquals(3600, SessionPolicy.durationSec())
        assertEquals(3600, CardPinCache.durationSec(), "the card PIN follows the session")

        SessionPolicy.setDurationSec(SessionPolicy.DURATION_UNTIL_LOCKED)
        assertTrue(SessionPolicy.isUntilLocked())
        // GAP-2: no watch that can vouch for a lock, so the shortest timed choice applies.
        assertFalse(SessionPolicy.isLifecycleHeld())
        assertEquals(SessionPolicy.UNCONFIRMED_LOCK_FALLBACK_SEC, SessionPolicy.effectiveDurationSec())
        trustTheWatch()
        assertTrue(SessionPolicy.isLifecycleHeld())
        assertFalse(SessionPolicy.isUntilCleared())

        CardPinCache.setDurationSec(SessionPolicy.DURATION_UNTIL_CLEARED)
        assertTrue(SessionPolicy.isUntilCleared(), "the card setter writes the one setting")

        SessionPolicy.setDurationSec(0)
        assertEquals(SessionPolicy.DEFAULT_DURATION_SEC, SessionPolicy.durationSec(), "an unknown value reads as the default")
        assertEquals(SessionPolicy.DEFAULT_DURATION_SEC, SessionPolicy.sanitize(-7))
        assertEquals(SessionPolicy.DEFAULT_DURATION_SEC, SessionPolicy.sanitize(999_999))
    }

    @Test
    fun aCardOnlyDurationCarriesOverOnce() {
        cardPrefs.putInt(CardPinCache.KEY_DURATION_SEC, 900)
        assertEquals(900, SessionPolicy.durationSec())
        cardPrefs.putInt(CardPinCache.KEY_DURATION_SEC, 60)
        assertEquals(900, SessionPolicy.durationSec(), "after the carry-over the session setting rules")
    }

    @Test
    fun timeLeftFollowsTheCurrentDuration() {
        val t0 = 5_000_000_000_000L
        val second = 1_000_000_000L
        SessionPolicy.setDurationSec(60)
        assertEquals(60_000L, SessionPolicy.remainingMs(t0, t0))
        assertEquals(15_000L, SessionPolicy.remainingMs(t0, t0 + 45 * second))
        assertEquals(0L, SessionPolicy.remainingMs(t0, t0 + 61 * second))
        SessionPolicy.setDurationSec(3600)
        assertEquals(3_540_000L, SessionPolicy.remainingMs(t0, t0 + 60 * second), "a longer setting extends what is held")
        SessionPolicy.setDurationSec(SessionPolicy.DURATION_UNTIL_CLEARED)
        assertEquals(Long.MAX_VALUE, SessionPolicy.remainingMs(t0, t0 + 86_400 * second))
    }

    // ── What is held ──

    @Test
    fun passphrasesAreHeldPerKeyAndExpire() {
        PassphraseCache.put("ABCDEF", "one")
        assertEquals("one", PassphraseCache.get("abcdef"), "fingerprints match in any case")
        assertTrue(PassphraseCache.remainingMs() in 1..300_000L)
        PassphraseCache.put("123456", "")
        assertNull(PassphraseCache.get("123456"), "an empty passphrase is not held")
        PassphraseCache.clear("abcdef")
        assertNull(PassphraseCache.get("abcdef"))

        SessionPolicy.setDurationSec(1)
        PassphraseCache.put("fedcba", "two")
        Thread.sleep(1_200)
        assertNull(PassphraseCache.get("fedcba"), "expired")
        assertEquals(0L, PassphraseCache.remainingMs())
    }

    @Test
    fun clearNowDropsPassphrasesAndTheCardPin() {
        SessionPolicy.setDurationSec(SessionPolicy.DURATION_UNTIL_LOCKED)
        trustTheWatch()
        PassphraseCache.put("abcdef", "held")
        CardPinCache.setEnabled(true)
        CardPinCache.remember("123456")
        assertEquals(Long.MAX_VALUE, CardPinCache.remainingMs(), "no timer until the screen locks")
        assertEquals(Long.MAX_VALUE, PassphraseCache.remainingMs())
        SessionPolicy.clearAll()
        assertNull(PassphraseCache.get("abcdef"))
        assertNull(CardPinCache.retrieve())
    }

    @Test
    fun screenLockProbesParse() {
        assertEquals(true, ScreenLock.parseMacIoreg("""  | "IOConsoleUsers" = ({"kCGSSessionOnConsoleKey"=Yes,"CGSSessionScreenIsLocked"=Yes})"""))
        assertEquals(false, ScreenLock.parseMacIoreg("""  | "IOConsoleUsers" = ({"kCGSSessionOnConsoleKey"=Yes})"""))
        assertEquals(true, ScreenLock.parseMacIoreg("""  | "IOConsoleLocked" = Yes"""))
        assertEquals(false, ScreenLock.parseMacIoreg("""  | "IOConsoleLocked" = No"""))
        assertNull(ScreenLock.parseMacIoreg("no console here"))
        assertEquals(true, ScreenLock.parseLockedHint("yes\n"))
        assertEquals(false, ScreenLock.parseLockedHint("no"))
        assertNull(ScreenLock.parseLockedHint(""))
        assertTrue(ScreenLock.parseTasklist("LogonUI.exe                  1234 Console    1     12,345 K"))
        assertFalse(ScreenLock.parseTasklist("INFO: No tasks are running which match the specified criteria."))
        assertTrue(ScreenLockWatch.isLockEvent(wasLocked = false, locked = true))
        assertFalse(ScreenLockWatch.isLockEvent(wasLocked = true, locked = true))
        assertFalse(ScreenLockWatch.isLockEvent(wasLocked = true, locked = false))
    }

    // ── Decrypt with a remembered passphrase ──

    @Test
    fun aBlankPassphraseUsesEachKeysRememberedOne() = runBlocking {
        val (db, repo, edits) = temp()
        val a = repo.generateKey("A", "a@pgpony.app", KeyAlgorithm.ED25519_CV25519, "pass-a")
        val b = repo.generateKey("B", "b@pgpony.app", KeyAlgorithm.ED25519_CV25519, "pass-b")
        val toA = repo.encryptText("for A", listOf(repo.loadPublicKeyRing(a.fingerprint)!!), null, null)
        val toB = repo.encryptText("for B", listOf(repo.loadPublicKeyRing(b.fingerprint)!!), null, null)

        assertTrue(runCatching { repo.decryptText(toA, null) }.isFailure, "nothing remembered yet")
        assertEquals("for A", repo.decryptText(toA, "pass-a").plaintext)
        assertEquals("pass-a", PassphraseCache.get(a.fingerprint), "remembered for the key that opened it")
        assertNull(PassphraseCache.get(b.fingerprint))
        assertEquals("for B", repo.decryptText(toB, "pass-b").plaintext)

        assertEquals("for A", repo.decryptText(toA, null).plaintext, "a blank field uses A's passphrase")
        assertEquals("for B", repo.decryptText(toB, null).plaintext, "and B's, each for its own key")
        assertTrue(runCatching { repo.decryptText(toA, "wrong") }.isFailure, "a typed passphrase is used as typed")

        edits.changePassphrase(a.fingerprint, "pass-a", "pass-a2")
        assertNull(PassphraseCache.get(a.fingerprint), "a passphrase change forgets the old one")
        assertTrue(runCatching { repo.decryptText(toA, null) }.isFailure)
        db.close()
    }

    @Test
    fun aStreamedFileUsesTheRecipientsRememberedPassphrase() = runBlocking {
        val (db, repo, _) = temp()
        val dir = Files.createTempDirectory("pgpony-session-files")
        val other = repo.generateKey("Other", "other@pgpony.app", KeyAlgorithm.ED25519_CV25519, "pass-other")
        val key = repo.generateKey("Files", "files@pgpony.app", KeyAlgorithm.ED25519_CV25519, "pass-files")
        val ops = FileCryptoOps(repo)
        val payload = Random(7).nextBytes(50_000)
        val original = dir.resolve("data.bin")
        Files.write(original, payload)
        val enc = ops.encryptFile(original, listOf(key.fingerprint), null, null, armor = false)
        assertTrue(enc.ok, enc.detail)
        Files.delete(original)

        PassphraseCache.put(other.fingerprint, "pass-other")
        assertFalse(ops.decryptFile(enc.output!!, null).ok, "another key's passphrase is not tried on it")
        PassphraseCache.put(key.fingerprint, "pass-files")
        val dec = ops.decryptFile(enc.output!!, null)
        assertTrue(dec.ok, dec.detail)
        assertContentEquals(payload, Files.readAllBytes(dec.output!!))
        db.close()
    }

    // ── GAP-2: "until the screen locks" fails closed ──

    @Test
    fun gap2UntilLockedWithoutATrustedWatchFollowsTheShortestTimer() {
        SessionPolicy.setDurationSec(SessionPolicy.DURATION_UNTIL_LOCKED)
        PassphraseCache.put("abcdef", "held")
        val left = PassphraseCache.remainingMs()
        assertTrue(left in 1..SessionPolicy.UNCONFIRMED_LOCK_FALLBACK_SEC * 1000L, "held for the fallback only: $left")
        CardPinCache.setEnabled(true)
        CardPinCache.remember("123456")
        assertTrue(CardPinCache.remainingMs() < Long.MAX_VALUE, "the card PIN is not held without a timer either")
    }

    @Test
    fun gap2ALinuxDesktopMustReportALockOnceBeforeItIsBelieved() {
        val os = System.getProperty("os.name").lowercase()
        if (os.contains("mac") || os.contains("win")) return
        SessionPolicy.setDurationSec(SessionPolicy.DURATION_UNTIL_LOCKED)
        ScreenLockWatch.assumeRunning = true
        ScreenLockWatch.step(false, System.currentTimeMillis(), ScreenLockWatch.POLL_MS)
        assertFalse(ScreenLock.isConfirmed(), "LockedHint=no proves nothing yet")
        assertFalse(ScreenLockWatch.isTrusted())
        assertFalse(SessionPolicy.isLifecycleHeld())
        ScreenLockWatch.step(true, System.currentTimeMillis(), ScreenLockWatch.POLL_MS)
        assertTrue(ScreenLock.isConfirmed(), "a reported lock confirms this desktop")
        ScreenLockWatch.step(false, System.currentTimeMillis(), ScreenLockWatch.POLL_MS)
        assertTrue(SessionPolicy.isLifecycleHeld())
    }

    @Test
    fun gap2AProbeThatStopsAnsweringDropsWhatIsHeld() {
        SessionPolicy.setDurationSec(SessionPolicy.DURATION_UNTIL_LOCKED)
        trustTheWatch()
        PassphraseCache.put("abcdef", "held")
        assertEquals(Long.MAX_VALUE, PassphraseCache.remainingMs())
        ScreenLockWatch.step(null, System.currentTimeMillis(), ScreenLockWatch.POLL_MS)
        assertNull(PassphraseCache.get("abcdef"), "cleared when the lock state can no longer be read")
        assertFalse(ScreenLockWatch.isTrusted())
        PassphraseCache.put("abcdef", "again")
        assertTrue(PassphraseCache.remainingMs() <= SessionPolicy.UNCONFIRMED_LOCK_FALLBACK_SEC * 1000L, "then the fallback applies")
    }

    @Test
    fun gap2AStaleAnswerIsNotTrusted() {
        SessionPolicy.setDurationSec(SessionPolicy.DURATION_UNTIL_LOCKED)
        trustTheWatch()
        assertFalse(ScreenLockWatch.isTrusted(System.currentTimeMillis() + 60_000), "no fresh answer for a minute")
    }

    @Test
    fun gap2ALongGapBetweenPollsCountsAsALock() {
        SessionPolicy.setDurationSec(SessionPolicy.DURATION_UNTIL_LOCKED)
        trustTheWatch()
        PassphraseCache.put("abcdef", "held")
        ScreenLockWatch.step(false, System.currentTimeMillis(), ScreenLockWatch.POLL_MS + 120_000)
        assertNull(PassphraseCache.get("abcdef"), "the machine slept")
    }

    // ── LOCAL-IPC-3: a passphrase entered to decrypt does not let git sign silently ──

    @Test
    fun localIpc3OnlyAPassphraseEnteredToSignIsOfferedForSigning() {
        PassphraseCache.put("abcdef", "decrypt-pass")
        assertEquals("decrypt-pass", PassphraseCache.get("abcdef"))
        assertNull(PassphraseCache.getForSigning("abcdef"), "a decrypt unlock is not a signing unlock")
        PassphraseCache.put("abcdef", "decrypt-pass", forSigning = true)
        assertEquals("decrypt-pass", PassphraseCache.getForSigning("abcdef"))
        PassphraseCache.put("abcdef", "decrypt-pass")
        assertEquals("decrypt-pass", PassphraseCache.getForSigning("abcdef"), "the same passphrase again keeps the mark")
        PassphraseCache.put("abcdef", "other")
        assertNull(PassphraseCache.getForSigning("abcdef"), "a different passphrase drops it")
    }
}
