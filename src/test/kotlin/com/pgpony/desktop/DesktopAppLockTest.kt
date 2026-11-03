// DesktopAppLockTest.kt
// PGPony Desktop 3.1.0 (plan section 2): the desktop side of the PGPony PIN app lock. The PIN
// hashing, duress check, counter and delay are Android's AppLockCore and carry their own tests
// (vendor/app-crypto-tests/.../lock/AppLockCoreTest.kt); this covers what the desktop adds: the
// file store in the data folder, locking and unlocking, the silent wipe and its resume flag, the
// command line gate, the agent and shim refusing while locked, idle locking and the clocks.
//
// A fast counting hasher stands in for Argon2id, and everything runs against a scratch folder
// and in-memory preferences.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.lock.AppLockCore
import com.pgpony.android.lock.LockClock
import com.pgpony.android.lock.PinCheck
import com.pgpony.android.lock.PinHasher
import com.pgpony.android.lock.PinSetup
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopAppLockTest {

    private lateinit var dir: Path
    private var clockMs = 1_000_000L

    private val fastHasher = PinHasher { pin, salt, _ ->
        MessageDigest.getInstance("SHA-256").apply { update(salt); update(pin) }.digest()
    }

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("pgpony-applock")
        DesktopAppLock.dirOverride = dir
        DesktopAppLock.coreOverride = AppLockCore(fastHasher)
        DesktopAppLock.clockOverride = { LockClock(clockMs, "boot-1") }
        DesktopAppLock.prefsOverride = MemoryPreferences()
        ClearAllData.dataDirOverride = dir
        ClearAllData.prefsRootOverride = MemoryPreferences()
        DesktopAppLock.lockAtLaunch()
    }

    @AfterTest
    fun tearDown() {
        runBlocking { if (DesktopAppLock.isSet()) DesktopAppLock.turnOff() }
        DesktopAppLock.dirOverride = null
        DesktopAppLock.coreOverride = null
        DesktopAppLock.clockOverride = null
        DesktopAppLock.prefsOverride = null
        ClearAllData.dataDirOverride = null
        ClearAllData.prefsRootOverride = null
    }

    private class Keyring(val db: com.pgpony.android.data.PGPDatabase, val repo: DesktopKeyRepository, val edits: DesktopKeyEdits)

    private fun keyring(): Keyring {
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        return Keyring(db, repo, DesktopKeyEdits(repo))
    }

    private fun setPin(pin: String = "123456") = runBlocking {
        assertTrue(DesktopAppLock.create(pin) is PinSetup.Done)
    }

    @Test
    fun aPinLocksAndTheRightPinUnlocks() = runBlocking {
        assertFalse(DesktopAppLock.isSet())
        setPin()
        assertTrue(DesktopAppLock.isSet())
        assertTrue(Files.exists(dir.resolve("app_lock")), "kept in the data folder, beside the keyring")
        assertFalse(Files.readString(dir.resolve("app_lock")).contains("123456"), "never the PIN itself")

        DesktopAppLock.lockNow()
        assertTrue(DesktopAppLock.lockedNow)
        assertTrue(DesktopAppLock.submit("654321") is PinCheck.Wrong)
        assertTrue(DesktopAppLock.lockedNow, "a wrong PIN leaves it locked")
        assertEquals(PinCheck.Unlocked, DesktopAppLock.submit("123456"))
        assertFalse(DesktopAppLock.lockedNow)
    }

    @Test
    fun aRelaunchStartsLocked() {
        setPin()
        DesktopAppLock.lockAtLaunch()
        assertTrue(DesktopAppLock.lockedNow)
        assertTrue(DesktopAppLock.pinSet)
    }

    @Test
    fun wrongPinsAreCountedAndDelayed() = runBlocking {
        setPin()
        repeat(4) { assertEquals(PinCheck.Wrong(it + 1, 0L), DesktopAppLock.submit("000000")) }
        val fifth = DesktopAppLock.submit("000000")
        assertTrue(fifth is PinCheck.Wrong && fifth.delayMs == 30_000L, fifth.toString())
        assertTrue(DesktopAppLock.submit("123456") is PinCheck.Throttled, "even the right PIN waits")
        clockMs += 30_000L
        assertEquals(PinCheck.Unlocked, DesktopAppLock.submit("123456"))
        assertEquals(0, DesktopAppLock.load()!!.failedAttempts, "the count starts over")
    }

    @Test
    fun theDuressPinMustDifferAndWipesEverything() = runBlocking {
        setPin()
        assertEquals(PinSetup.SameAsOther, DesktopAppLock.setDuress("123456"))
        assertTrue(DesktopAppLock.setDuress("999999") is PinSetup.Done)
        assertEquals(PinSetup.SameAsOther, DesktopAppLock.changePin("999999"))

        val k = keyring()
        k.repo.generateKey("Wiped", "wiped@example.invalid", KeyAlgorithm.ED25519_CV25519, "pass")
        val gone = k.repo.generateKey("Binned", "binned@example.invalid", KeyAlgorithm.ED25519_CV25519, "pass")
        k.edits.softDelete(gone.fingerprint)

        DesktopAppLock.lockNow()
        assertEquals(PinCheck.Duress, DesktopAppLock.submit("999999"))
        assertTrue(DesktopAppLock.isWipePending(), "the resume flag is written before the outcome leaves")
        DesktopAppLock.wipe(k.edits)

        assertTrue(k.repo.allKeys().isEmpty())
        assertEquals(0, k.edits.deletedCount(), "Recently Deleted too")
        assertFalse(Files.exists(dir.resolve("keys")))
        assertFalse(DesktopAppLock.isSet(), "the lock goes with it, so it opens as a fresh install")
        assertFalse(DesktopAppLock.isWipePending())
        k.db.close()
    }

    @Test
    fun theWrongPinLimitWipesTheSameWay() = runBlocking {
        setPin()
        DesktopAppLock.setWipeAfter(5)
        repeat(4) { assertTrue(DesktopAppLock.submit("000000") is PinCheck.Wrong) }
        assertTrue(DesktopAppLock.submit("000000") is PinCheck.WipeLimit)
        assertTrue(DesktopAppLock.isWipePending())
    }

    @Test
    fun aWipeCutShortFinishesAtTheNextStart() = runBlocking {
        setPin()
        val k = keyring()
        k.repo.generateKey("Left", "left@example.invalid", KeyAlgorithm.ED25519_CV25519, "pass")
        com.pgpony.android.lock.WipeFlag(dir.toFile()).markPending()
        DesktopAppLock.resumeIfPending { k.edits to {} }
        assertTrue(k.repo.allKeys().isEmpty())
        assertFalse(DesktopAppLock.isSet())
        assertFalse(DesktopAppLock.isWipePending())
        k.db.close()
    }

    @Test
    fun theCommandLineAsksForThePin() = runBlocking {
        val err = ByteArrayOutputStream()
        val out = PrintStream(err, true)
        assertTrue(DesktopAppLock.cliGate(null, out), "no PIN set: nothing to ask")
        setPin()
        DesktopAppLock.setDuress("999999")
        assertFalse(DesktopAppLock.cliGate(null, out), "no terminal: refused")
        assertTrue(err.toString().contains("run this command in a terminal"))
        assertFalse(DesktopAppLock.cliGate({ "111111" }, out))
        assertTrue(err.toString().contains("Wrong PIN."))
        assertTrue(DesktopAppLock.cliGate({ "123456" }, out))

        val k = keyring()
        k.repo.generateKey("Cli", "cli@example.invalid", KeyAlgorithm.ED25519_CV25519, "pass")
        assertTrue(DesktopAppLock.cliGate({ "999999" }, out) { k.edits to {} }, "the duress PIN goes on, on an empty keyring")
        assertTrue(k.repo.allKeys().isEmpty())
        assertFalse(DesktopAppLock.isSet())
        k.db.close()
    }

    @Test
    fun theAgentAndTheShimRefuseWhileLocked() = runBlocking {
        val k = keyring()
        val key = k.repo.generateKey("Git", "git@example.invalid", KeyAlgorithm.ED25519_CV25519, null)
        setPin()
        DesktopAppLock.lockNow()
        assertTrue(SshAgentKeys.identities(k.repo).isEmpty())
        assertEquals(null, SshAgentKeys.sign(k.repo, ByteArray(32), ByteArray(8), 0))
        val reply = ShimSigner.signForShim(k.repo, key.fingerprint, "tree 0\n".toByteArray(), notify = {}, prompt = { null })
        assertTrue(reply is ShimBridge.Reply.Refused && reply.message.contains("locked"), reply.toString())
        k.db.close()
    }

    @Test
    fun idleTimeAndItsSetting() {
        assertTrue(DesktopAppLock.idleExpired(0, 5 * 60_000L, 5))
        assertFalse(DesktopAppLock.idleExpired(0, 5 * 60_000L - 1, 5))
        assertFalse(DesktopAppLock.idleExpired(0, Long.MAX_VALUE / 2, 0), "0 is never")
        assertEquals(DesktopAppLock.DEFAULT_IDLE_MINUTES, DesktopAppLock.idleMinutes())
        DesktopAppLock.setIdleMinutes(15)
        assertEquals(15, DesktopAppLock.idleMinutes())
        DesktopAppLock.setIdleMinutes(7)
        assertEquals(DesktopAppLock.DEFAULT_IDLE_MINUTES, DesktopAppLock.idleMinutes(), "an unknown value falls back")
    }

    @Test
    fun theClocksParse() {
        val linux = DesktopAppLock.parseLinuxClock("12345.67 99999.00\n", "6f1c2b0e-aaaa-bbbb-cccc-1234567890ab\n")
        assertEquals(LockClock(12_345_670L, "6f1c2b0e-aaaa-bbbb-cccc-1234567890ab"), linux)
        val mac = DesktopAppLock.parseMacClock(
            "{ sec = 1730000000, usec = 500000 } Mon Oct 27 03:33:20 2024\n0A1B2C3D-0000-1111-2222-333344445555\n",
            1_730_000_100_000L
        )
        assertNotNull(mac)
        assertEquals(99_500L, mac.elapsedMs)
        assertEquals("0A1B2C3D-0000-1111-2222-333344445555", mac.bootId)
        assertEquals(null, DesktopAppLock.parseMacClock("garbage", 0L))
    }

    @Test
    fun theRelaunchWaitsForThisProcessToExit() {
        val unix = DesktopAppLock.relaunchCommand("/Applications/PGPony.app/Contents/MacOS/PGPony", emptyList(), "Mac OS X")
        assertEquals("/bin/sh", unix.first())
        assertTrue(unix.contains("/Applications/PGPony.app/Contents/MacOS/PGPony"))
        val win = DesktopAppLock.relaunchCommand("C:\\PGPony\\PGPony.exe", listOf("--data-dir", "E:\\PGPony-data"), "Windows 11")
        assertEquals("cmd", win.first())
        assertTrue(win.last().contains("\"C:\\PGPony\\PGPony.exe\" \"--data-dir\" \"E:\\PGPony-data\""), win.last())
    }
}
