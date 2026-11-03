// AppLockCoreTest.kt
// PGPony Android 4.7.0 (item 32): the app lock PIN core. A fast counting hasher
// stands in for Argon2id so each test can see exactly which hashes ran.

package com.pgpony.android.lock

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class AppLockCoreTest {

    /** SHA-256 over version, salt and PIN, and a log of every call. */
    private class CountingHasher : PinHasher {
        // The two hashes of a check run on two threads, so record under a lock.
        val salts: MutableList<ByteArray> = java.util.Collections.synchronizedList(mutableListOf())
        val calls: Int get() = salts.size
        override fun hash(pin: ByteArray, salt: ByteArray, params: PinHashParams): ByteArray {
            salts.add(salt.copyOf())
            val md = MessageDigest.getInstance("SHA-256")
            md.update(params.version.toByte())
            md.update(salt)
            md.update(pin)
            return md.digest()
        }
    }

    private var counter = 0

    /** Distinct, repeatable salts. */
    private val fakeRandom: (Int) -> ByteArray = { n -> ByteArray(n) { i -> (counter * 31 + i).toByte() }.also { counter++ } }

    private fun core(h: PinHasher) = AppLockCore(h, fakeRandom)

    /** Time since boot [ms] on boot [boot]. */
    private fun at(ms: Long, boot: String? = "boot-1") = LockClock(ms, boot)

    private fun done(s: PinSetup): AppLockConfig {
        assertTrue("expected Done, got $s", s is PinSetup.Done)
        return (s as PinSetup.Done).config
    }

    private fun withDuress(c: AppLockCore, pin: String = "123456", duress: String = "654321"): AppLockConfig =
        done(c.setDuress(done(c.create(pin, fingerprintAllowed = false)), duress))

    @Test
    fun pinFormatValidation() {
        assertEquals(PinFormat.TOO_SHORT, PinRules.check(""))
        assertEquals(PinFormat.TOO_SHORT, PinRules.check("12345"))
        assertEquals(PinFormat.OK, PinRules.check("123456"))
        assertEquals(PinFormat.OK, PinRules.check("1234567890123456"))
        assertEquals(PinFormat.TOO_LONG, PinRules.check("12345678901234567"))
        assertEquals(PinFormat.NOT_DIGITS, PinRules.check("12345a"))
        assertEquals(PinFormat.NOT_DIGITS, PinRules.check("123 456"))
        // Digits from other scripts are not ASCII digits.
        assertEquals(PinFormat.NOT_DIGITS, PinRules.check("\uFF11\uFF12\uFF13\uFF14\uFF15\uFF16"))
        val c = core(CountingHasher())
        assertEquals(PinSetup.Invalid(PinFormat.TOO_SHORT), c.create("1234", fingerprintAllowed = false))
        val cfg = done(c.create("123456", fingerprintAllowed = false))
        assertEquals(PinSetup.Invalid(PinFormat.NOT_DIGITS), c.setDuress(cfg, "abcdef"))
        assertEquals(PinSetup.Invalid(PinFormat.TOO_LONG), c.changePin(cfg, "12345678901234567"))
    }

    @Test
    fun hashRoundTripAndRealPinAccepted() {
        val h = CountingHasher()
        val c = core(h)
        val cfg = done(c.create("246810", fingerprintAllowed = true))
        assertEquals(PinHashParams.CURRENT.version, cfg.version)
        assertEquals(PinRules.SALT_LENGTH, cfg.salt.size)
        assertFalse(cfg.salt.contentEquals(cfg.duressSalt))
        assertFalse(cfg.hasDuress)
        // The stored hash is the hasher's output, never the PIN.
        assertFalse(String(cfg.hash, Charsets.ISO_8859_1).contains("246810"))
        val r = c.check(cfg, "246810", at(1_000L))
        assertEquals(PinCheck.Unlocked, r.outcome)
        assertNull(r.updated)
    }

    @Test
    fun wrongPinRejectedAndCounted() {
        val c = core(CountingHasher())
        val cfg = done(c.create("246810", fingerprintAllowed = false))
        val r = c.check(cfg, "246811", at(5_000L))
        assertEquals(PinCheck.Wrong(1, 0L), r.outcome)
        val u = r.updated
        assertNotNull(u)
        assertEquals(1, u!!.failedAttempts)
        assertEquals(5_000L, u.lastFailureElapsedMs)
        assertEquals("boot-1", u.lastFailureBootId)
        // A wrong format still counts as a wrong PIN.
        assertTrue(c.check(u, "12", at(6_000L)).outcome is PinCheck.Wrong)
    }

    @Test
    fun duressPinDetected() {
        val c = core(CountingHasher())
        val cfg = withDuress(c)
        assertTrue(cfg.hasDuress)
        val r = c.check(cfg, "654321", at(1_000L))
        assertEquals(PinCheck.Duress, r.outcome)
        assertNull(r.updated)
        assertEquals(PinCheck.Unlocked, c.check(cfg, "123456", at(1_000L)).outcome)
        assertTrue(c.check(cfg, "111111", at(1_000L)).outcome is PinCheck.Wrong)
    }

    @Test
    fun duressEqualToPinRefused() {
        val c = core(CountingHasher())
        val cfg = done(c.create("123456", fingerprintAllowed = false))
        assertEquals(PinSetup.SameAsOther, c.setDuress(cfg, "123456"))
        val d = done(c.setDuress(cfg, "999999"))
        // Changing the PIN to the duress PIN is refused the same way.
        assertEquals(PinSetup.SameAsOther, c.changePin(d, "999999"))
        val changed = done(c.changePin(d, "777777"))
        assertEquals(PinCheck.Unlocked, c.check(changed, "777777", at(0L)).outcome)
        assertEquals(PinCheck.Duress, c.check(changed, "999999", at(0L)).outcome)
        assertTrue(c.check(changed, "123456", at(0L)).outcome is PinCheck.Wrong)
    }

    @Test
    fun removedDuressPinIsJustWrong() {
        val c = core(CountingHasher())
        val cfg = withDuress(c)
        val removed = c.removeDuress(cfg)
        assertFalse(removed.hasDuress)
        assertFalse(removed.duressSalt.contentEquals(cfg.duressSalt))
        assertTrue(c.check(removed, "654321", at(0L)).outcome is PinCheck.Wrong)
    }

    @Test
    fun everyCheckComputesBothHashes() {
        val h = CountingHasher()
        val c = core(h)
        val plain = done(c.create("123456", fingerprintAllowed = false))
        val duress = done(c.setDuress(plain, "654321"))
        for ((cfg, pin) in listOf(
            plain to "123456", plain to "000000", plain to "654321",
            duress to "123456", duress to "654321", duress to "000000", duress to "1"
        )) {
            val before = h.calls
            c.check(cfg, pin, at(0L))
            assertEquals("hashes for $pin", 2, h.calls - before)
            // The two run in parallel, so either may be recorded first.
            val pair = listOf(h.salts[before], h.salts[before + 1])
            assertTrue(pair.any { it.contentEquals(cfg.salt) })
            assertTrue(pair.any { it.contentEquals(cfg.duressSalt) })
        }
    }

    @Test
    fun attemptCounterAndWipeThreshold() {
        val c = core(CountingHasher())
        var cfg = c.withWipeAfter(done(c.create("123456", fingerprintAllowed = false)), 5)
        for (i in 1..4) {
            val r = c.check(cfg, "000000", at(i * 1_000L))
            // No delay while the wrong-PIN wipe is on.
            assertEquals(PinCheck.Wrong(i, 0L), r.outcome)
            cfg = r.updated!!
        }
        // A correct PIN resets the count.
        val ok = c.check(cfg, "123456", at(10_000L))
        assertEquals(PinCheck.Unlocked, ok.outcome)
        cfg = ok.updated!!
        assertEquals(0, cfg.failedAttempts)
        for (i in 1..4) cfg = c.check(cfg, "000000", at(20_000L + i)).updated!!
        val fifth = c.check(cfg, "000000", at(30_000L))
        assertEquals(PinCheck.WipeLimit(5), fifth.outcome)
        assertEquals(5, fifth.updated!!.failedAttempts)
        // Changing the threshold starts a fresh count.
        assertEquals(0, c.withWipeAfter(fifth.updated!!, 10).failedAttempts)
    }

    @Test
    fun counterPersistsAcrossRestarts() {
        val dir = java.nio.file.Files.createTempDirectory("applock").toFile()
        try {
            val c = core(CountingHasher())
            val store = AppLockFileStore(dir)
            assertFalse(store.isOn())
            store.save(c.withWipeAfter(done(c.create("123456", fingerprintAllowed = true)), 10))
            for (i in 1..3) {
                // A new store instance each time, as after a process restart.
                val loaded = AppLockFileStore(dir).load()!!
                AppLockFileStore(dir).save(c.check(loaded, "999999", at(i.toLong())).updated!!)
            }
            val after = AppLockFileStore(dir).load()!!
            assertEquals(3, after.failedAttempts)
            assertEquals(10, after.wipeAfter)
            assertTrue(after.fingerprintAllowed)
            assertEquals(PinCheck.Unlocked, c.check(after, "123456", at(10L)).outcome)
            AppLockFileStore(dir).clear()
            assertFalse(AppLockFileStore(dir).isOn())
            assertNull(AppLockFileStore(dir).load())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun escalatingDelay() {
        assertEquals(0L, PinBackoff.delayMs(0))
        assertEquals(0L, PinBackoff.delayMs(4))
        assertEquals(30_000L, PinBackoff.delayMs(5))
        assertEquals(60_000L, PinBackoff.delayMs(6))
        assertEquals(120_000L, PinBackoff.delayMs(7))
        assertEquals(300_000L, PinBackoff.delayMs(8))
        assertEquals(300_000L, PinBackoff.delayMs(50))

        val h = CountingHasher()
        val c = core(h)
        var cfg = done(c.create("123456", fingerprintAllowed = false))
        for (i in 1..4) cfg = c.check(cfg, "000000", at(1_000L)).updated!!
        val fifth = c.check(cfg, "000000", at(1_000L))
        assertEquals(PinCheck.Wrong(5, 30_000L), fifth.outcome)
        cfg = fifth.updated!!
        // Inside the delay: refused without hashing, even the right PIN.
        val calls = h.calls
        val early = c.check(cfg, "123456", at(11_000L))
        assertEquals(PinCheck.Throttled(20_000L), early.outcome)
        assertEquals(calls, h.calls)
        assertNull(early.updated)
        // After it: checked normally.
        assertEquals(PinCheck.Unlocked, c.check(cfg, "123456", at(31_000L)).outcome)
        // The delay runs on time since boot: the wall clock is not consulted
        // at all, so setting it forward skips nothing.
        assertEquals(PinCheck.Throttled(1_000L), c.check(cfg, "123456", at(30_000L)).outcome)
        // No delay while the wrong-PIN wipe is on.
        assertEquals(0L, c.throttleRemainingMs(cfg.copy(wipeAfter = 20), at(1_001L)))
    }

    @Test
    fun versionTag() {
        val v1 = PinHashParams.V1
        assertEquals(1, v1.version)
        assertEquals(64 * 1024, v1.memoryKiB)
        assertEquals(3, v1.iterations)
        assertEquals(4, v1.parallelism)
        assertEquals(32, v1.outputLength)
        assertEquals(v1, PinHashParams.forVersion(1))
        val v2 = PinHashParams.V2
        assertEquals(2, v2.version)
        assertEquals(32 * 1024, v2.memoryKiB)
        assertEquals(2, v2.iterations)
        assertEquals(v2, PinHashParams.CURRENT)
        assertEquals(v2, PinHashParams.forVersion(2))
        assertNull(PinHashParams.forVersion(3))

        val c = core(CountingHasher())
        val cfg = withDuress(c)
        val text = AppLockCodec.encode(cfg)
        assertTrue(text.lines().contains("v=${PinHashParams.CURRENT.version}"))
        assertFalse(text.contains("123456"))
        assertFalse(text.contains("654321"))
        val back = AppLockCodec.decode(text)!!
        assertEquals(cfg.version, back.version)
        assertTrue(back.salt.contentEquals(cfg.salt))
        assertTrue(back.hash.contentEquals(cfg.hash))
        assertTrue(back.duressSalt.contentEquals(cfg.duressSalt))
        assertTrue(back.duressHash!!.contentEquals(cfg.duressHash!!))
        assertEquals(PinCheck.Duress, c.check(back, "654321", at(0L)).outcome)

        // A version this build does not know never unlocks and counts nothing.
        val future = AppLockCodec.decode(text.replace("v=${PinHashParams.CURRENT.version}", "v=9"))!!
        val r = c.check(future, "123456", at(0L))
        assertEquals(PinCheck.Unsupported, r.outcome)
        assertNull(r.updated)
        assertEquals(PinSetup.Unsupported, c.setDuress(future, "111111"))
    }

    @Test
    fun codecRejectsIncompleteText() {
        assertNull(AppLockCodec.decode(""))
        assertNull(AppLockCodec.decode("format=other\nv=1"))
        assertNull(AppLockCodec.decode("format=pgpony-app-lock\nv=1\nsalt=AAAA"))
        val c = core(CountingHasher())
        val plain = AppLockCodec.encode(done(c.create("123456", fingerprintAllowed = false)))
        assertFalse(plain.contains("dhash="))
        assertFalse(AppLockCodec.decode(plain)!!.hasDuress)
    }

    @Test
    fun constantTimeEqualsBasics() {
        assertTrue(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        assertFalse(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        assertFalse(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2)))
        assertTrue(constantTimeEquals(ByteArray(0), ByteArray(0)))
    }

    @Test
    fun fingerprintUnlockResetsTheCount() {
        val c = core(CountingHasher())
        val cfg = done(c.create("123456", fingerprintAllowed = true))
        assertNull(c.resetAttempts(cfg))
        val failed = c.check(cfg, "000000", at(9L)).updated!!
        assertEquals(0, c.resetAttempts(failed)!!.failedAttempts)
    }

    @Test
    fun wipeFlagMarksAndClears() {
        val dir = java.nio.file.Files.createTempDirectory("wipeflag").toFile()
        try {
            val flag = WipeFlag(dir)
            assertFalse(flag.isPending())
            flag.markPending()
            assertTrue(WipeFlag(dir).isPending())
            WipeFlag(dir).clear()
            assertFalse(flag.isPending())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun anotherBootCountsTheWholeDelayFromNow() {
        val h = CountingHasher()
        val c = core(h)
        var cfg = done(c.create("123456", fingerprintAllowed = false))
        for (i in 1..5) cfg = c.check(cfg, "000000", at(1_000L)).updated!!
        // After a restart, time since boot starts again and cannot be compared:
        // the whole delay counts from now, and that reading is persisted.
        val calls = h.calls
        val rebooted = c.check(cfg, "123456", at(400L, "boot-2"))
        assertEquals(PinCheck.Throttled(30_000L), rebooted.outcome)
        assertEquals(calls, h.calls)
        val adjusted = rebooted.updated!!
        assertEquals(400L, adjusted.lastFailureElapsedMs)
        assertEquals("boot-2", adjusted.lastFailureBootId)
        assertEquals(PinCheck.Throttled(10_000L), c.check(adjusted, "123456", at(20_400L, "boot-2")).outcome)
        assertEquals(PinCheck.Unlocked, c.check(adjusted, "123456", at(30_400L, "boot-2")).outcome)
        // A later boot with more uptime than the stored reading is still another boot.
        assertEquals(PinCheck.Throttled(30_000L), c.check(cfg, "123456", at(900_000L, "boot-3")).outcome)
    }

    @Test
    fun missingReadingsCountTheWholeDelay() {
        val c = core(CountingHasher())
        var cfg = done(c.create("123456", fingerprintAllowed = false))
        for (i in 1..5) cfg = c.check(cfg, "000000", at(1_000L, null)).updated!!
        // No boot id on this device: the time since boot is still compared.
        assertEquals(PinCheck.Throttled(20_000L), c.check(cfg, "123456", at(11_000L, null)).outcome)
        // Time since boot went backwards (a restart): the whole delay, from now.
        assertEquals(PinCheck.Throttled(30_000L), c.check(cfg, "123456", at(500L, null)).outcome)
        // No stored reading (a config from before this change): the whole delay.
        val noReading = cfg.copy(lastFailureElapsedMs = -1L, lastFailureBootId = null)
        val r = c.check(noReading, "123456", at(99_000L))
        assertEquals(PinCheck.Throttled(30_000L), r.outcome)
        assertEquals(99_000L, r.updated!!.lastFailureElapsedMs)
        // The readings survive the file.
        val back = AppLockCodec.decode(AppLockCodec.encode(r.updated!!))!!
        assertEquals(99_000L, back.lastFailureElapsedMs)
        assertEquals("boot-1", back.lastFailureBootId)
        assertNull(AppLockCodec.decode(AppLockCodec.encode(cfg))!!.lastFailureBootId)
    }

    @Test
    fun pinModeMarkerKeepsTheLockOnWithoutAConfig() {
        val dir = java.nio.file.Files.createTempDirectory("applockmarker").toFile()
        try {
            val c = core(CountingHasher())
            val store = AppLockFileStore(dir)
            assertFalse(store.isOn())
            store.markOn()
            store.save(done(c.create("123456", fingerprintAllowed = false)))
            assertTrue(store.isOn())
            // The config deleted: still on, and unreadable.
            java.io.File(dir, AppLockFileStore.FILE_NAME).delete()
            assertTrue(AppLockFileStore(dir).isOn())
            assertNull(AppLockFileStore(dir).load())
            // The config broken: the same.
            java.io.File(dir, AppLockFileStore.FILE_NAME).writeText("format=pgpony-app-lock\nv=1\nsalt=")
            assertTrue(AppLockFileStore(dir).isOn())
            assertNull(AppLockFileStore(dir).load())
            // Only clear() leaves PIN mode.
            AppLockFileStore(dir).clear()
            assertFalse(AppLockFileStore(dir).isOn())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun configWritesAreAtomic() {
        val dir = java.nio.file.Files.createTempDirectory("applockatomic").toFile()
        try {
            val target = java.io.File(dir, "f")
            writeFileAtomically(target, "one")
            writeFileAtomically(target, "two")
            assertEquals("two", target.readText())
            assertFalse(java.io.File(dir, "f.tmp").exists())
            // A rename that cannot happen throws and leaves the target as it was,
            // with no non-atomic fallback write.
            val blocked = java.io.File(dir, "blocked").apply { mkdirs() }
            java.io.File(blocked, "inside").writeText("x")
            var threw = false
            try {
                writeFileAtomically(blocked, "three")
            } catch (e: java.io.IOException) {
                threw = true
            }
            assertTrue(threw)
            assertTrue(blocked.isDirectory)
            assertEquals("x", java.io.File(blocked, "inside").readText())
            assertFalse(java.io.File(dir, "blocked.tmp").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun argon2HasherIsDeterministicAndSalted() {
        // Small cost so the test runs fast; the real PIN uses PinHashParams.CURRENT.
        val small = PinHashParams(version = 1, memoryKiB = 64, iterations = 1, parallelism = 1, outputLength = 32)
        val pin = "123456".toByteArray()
        val a = Argon2PinHasher.hash(pin, ByteArray(16) { 1 }, small)
        val b = Argon2PinHasher.hash(pin, ByteArray(16) { 1 }, small)
        val other = Argon2PinHasher.hash(pin, ByteArray(16) { 2 }, small)
        assertEquals(32, a.size)
        assertTrue(a.contentEquals(b))
        assertFalse(a.contentEquals(other))
        val c = AppLockCore(Argon2PinHasher, fakeRandom, small) { v -> if (v == 1) small else null }
        val cfg = done(c.setDuress(done(c.create("123456", fingerprintAllowed = false)), "654321"))
        assertEquals(PinCheck.Unlocked, c.check(cfg, "123456", at(0L)).outcome)
        assertEquals(PinCheck.Duress, c.check(cfg, "654321", at(0L)).outcome)
        assertTrue(c.check(cfg, "123457", at(0L)).outcome is PinCheck.Wrong)
    }
}
