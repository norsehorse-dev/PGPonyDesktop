// DesktopAppLock.kt
// PGPony Desktop 3.1.0 (plan section 2): the PGPony PIN app lock, its duress PIN and the
// wrong-PIN wipe.
//
// The hashing, the duress check, the attempt counter, the wipe threshold and the delay are
// PGPony Android's AppLockCore, vendored verbatim (vendor/app-lock, 4.7.0 item 32), so the two
// apps take the same PIN rules and give the same result. This object is the desktop's
// counterpart of Android's AppLock and AppWipe: the config file in the data folder (so a
// portable copy carries its lock with it), the clock the delay is measured on, one attempt at a
// time, the silent wipe and the restart into a fresh install.
//
// What the lock covers on the desktop:
//   * the window and the menu bar (Gui.kt draws AppLockScreen and nothing behind it);
//   * the ssh-agent and the git signing shim, which refuse while locked (plan Q1);
//   * the `pgpony` command line, which asks for the PIN in the terminal (plan Q3). `pgpony sop`
//     never touches the keyring and stays outside the lock.
// Watch folders keep running: they only encrypt to public keys and never use a secret.
//
// It locks at launch, after the idle time chosen in Settings, when the computer locks
// (ScreenLockWatch) and on Lock PGPony in the menu or the tray.

package com.pgpony.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.pgpony.android.lock.AppLockConfig
import com.pgpony.android.lock.AppLockCore
import com.pgpony.android.lock.AppLockFileStore
import com.pgpony.android.lock.Argon2PinHasher
import com.pgpony.android.lock.LockClock
import com.pgpony.android.lock.PinCheck
import com.pgpony.android.lock.PinSetup
import com.pgpony.android.lock.WipeFlag
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.prefs.Preferences
import kotlin.system.exitProcess

object DesktopAppLock {

    const val KEY_IDLE_MINUTES = "app_lock_idle_minutes"
    const val DEFAULT_IDLE_MINUTES = 5

    /** Lock-after choices in Settings, in minutes; 0 locks only at launch, on a computer lock or by hand. */
    val IDLE_CHOICES: List<Int> = listOf(1, 5, 15, 30, 60, 0)

    // ── Test hooks ─────────────────────────────────────────────────────
    internal var dirOverride: Path? = null
    internal var coreOverride: AppLockCore? = null
    internal var clockOverride: (() -> LockClock)? = null
    internal var prefsOverride: Preferences? = null

    private val defaultCore by lazy { AppLockCore(Argon2PinHasher) }
    private fun core(): AppLockCore = coreOverride ?: defaultCore
    private val mutex = Mutex()

    /** Survives a lock screen leaving composition, so a wipe once started always finishes. */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private fun dir(): File = (dirOverride ?: Config.dataDir).toFile()
    private fun store() = AppLockFileStore(dir())
    private fun wipeFlag() = WipeFlag(dir())
    private fun prefs(): Preferences = prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    /** A PGPony PIN is set (its marker or config exists). File stats only. */
    fun isSet(): Boolean = runCatching { store().isOn() }.getOrDefault(false)

    // ── Locked or not ──────────────────────────────────────────────────

    /** Drawn by the window: true shows AppLockScreen and nothing behind it. */
    var locked by mutableStateOf(false)
        private set

    /** Read by the agent and shim threads; the same value as [locked]. */
    @Volatile
    var lockedNow: Boolean = false
        private set

    /** Whether a PIN is set, for the menu and the tray; follows create, turn off and the wipe. */
    var pinSet by mutableStateOf(false)
        private set

    /** Counts every lock, so Settings asks for the PIN again after one. */
    var lockEpoch by mutableIntStateOf(0)
        private set

    @Volatile
    private var lastActivityMs: Long = System.currentTimeMillis()

    private fun applyLocked(value: Boolean) {
        lockedNow = value
        locked = value
    }

    /** At launch: locked whenever a PIN is set. */
    fun lockAtLaunch() {
        pinSet = isSet()
        applyLocked(pinSet)
        if (lockedNow) lockEpoch++
    }

    /** Lock now, if a PIN is set and the app is not locked already. */
    fun lockNow() {
        if (lockedNow || !isSet()) return
        applyLocked(true)
        lockEpoch++
    }

    private fun markUnlocked() {
        lastActivityMs = System.currentTimeMillis()
        applyLocked(false)
    }

    // ── Idle ───────────────────────────────────────────────────────────

    fun idleMinutes(): Int = prefs().getInt(KEY_IDLE_MINUTES, DEFAULT_IDLE_MINUTES).let { if (it in IDLE_CHOICES) it else DEFAULT_IDLE_MINUTES }

    fun setIdleMinutes(minutes: Int) {
        prefs().putInt(KEY_IDLE_MINUTES, minutes)
        runCatching { prefs().flush() }
    }

    /** A key press, click or scroll in a PGPony window. */
    fun noteActivity() {
        lastActivityMs = System.currentTimeMillis()
    }

    /** Whether [minutes] (0 is never) have passed with no activity since [lastMs]. */
    internal fun idleExpired(lastMs: Long, nowMs: Long, minutes: Int): Boolean =
        minutes > 0 && nowMs - lastMs >= minutes * 60_000L

    /** Lock if the idle time has passed. Called on a timer by the window. */
    fun lockIfIdle(nowMs: Long = System.currentTimeMillis()) {
        if (!lockedNow && idleExpired(lastActivityMs, nowMs, idleMinutes())) lockNow()
    }

    // ── The clock the wrong-PIN delay is measured on ───────────────────
    //
    // Android uses time since boot and the boot count, so setting the wall clock forward skips
    // nothing. Linux reads the same from /proc. macOS keeps kern.boottime moving with clock
    // changes, so the wall clock minus boot time is time since boot, and kern.bootsessionuuid
    // names the boot. Windows has neither without native code; there the wall clock stands in
    // (a clock set backwards restarts the delay; set forwards, it is shortened).

    internal fun clock(): LockClock = clockOverride?.invoke() ?: platformClock()

    private fun platformClock(): LockClock {
        val os = System.getProperty("os.name").orEmpty().lowercase()
        return when {
            os.contains("linux") -> runCatching {
                parseLinuxClock(
                    Files.readString(Path.of("/proc/uptime")),
                    Files.readString(Path.of("/proc/sys/kernel/random/boot_id"))
                )
            }.getOrNull()
            os.contains("mac") -> runCatching {
                val proc = ProcessBuilder("/usr/sbin/sysctl", "-n", "kern.boottime", "kern.bootsessionuuid")
                    .redirectErrorStream(true).start()
                val out = proc.inputStream.bufferedReader().readText()
                if (proc.waitFor() == 0) parseMacClock(out, System.currentTimeMillis()) else null
            }.getOrNull()
            else -> null
        } ?: LockClock(System.currentTimeMillis(), "wall")
    }

    /** /proc/uptime ("12345.67 89012.34") and the boot id. */
    internal fun parseLinuxClock(uptime: String, bootId: String): LockClock? {
        val seconds = uptime.trim().substringBefore(' ').toDoubleOrNull() ?: return null
        val id = bootId.trim().ifEmpty { return null }
        return LockClock((seconds * 1000).toLong(), id)
    }

    /** `sysctl -n kern.boottime kern.bootsessionuuid`: "{ sec = 1730000000, usec = 5 } ..." then the uuid. */
    internal fun parseMacClock(output: String, nowMs: Long): LockClock? {
        val lines = output.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.size < 2) return null
        val sec = Regex("sec\\s*=\\s*(\\d+)").find(lines[0])?.groupValues?.get(1)?.toLongOrNull() ?: return null
        val usec = Regex("usec\\s*=\\s*(\\d+)").find(lines[0])?.groupValues?.get(1)?.toLongOrNull() ?: 0L
        val bootMs = sec * 1000 + usec / 1000
        if (nowMs < bootMs) return null
        return LockClock(nowMs - bootMs, lines[1])
    }

    // ── Attempts and setup ─────────────────────────────────────────────

    suspend fun load(): AppLockConfig? = withContext(Dispatchers.IO) { store().load() }

    fun throttleRemainingMs(config: AppLockConfig): Long = core().throttleRemainingMs(config, clock())

    /**
     * One PIN attempt, persisted before the outcome is returned. For the duress PIN and the
     * wipe limit, the wipe's resume flag is written here, under the lock, before the outcome
     * leaves; a failed write does not hold the wipe back. A wrong PIN that cannot be counted
     * throws (the caller shows it as an error, never as an unlock). Never logs the PIN.
     */
    suspend fun submit(pin: String): PinCheck = mutex.withLock {
        val s = store()
        val config = withContext(Dispatchers.IO) { s.load() } ?: return@withLock PinCheck.Unsupported
        val now = clock()
        val result = withContext(Dispatchers.Default) { core().check(config, pin, now) }
        val updated = result.updated
        when (result.outcome) {
            PinCheck.Duress, is PinCheck.WipeLimit -> withContext(Dispatchers.IO) {
                runCatching { wipeFlag().markPending() }
                if (updated != null) runCatching { s.save(updated) }
            }
            PinCheck.Unlocked -> {
                // The owner is in; a counter that fails to reset must not lock them out.
                if (updated != null) withContext(Dispatchers.IO) { runCatching { s.save(updated) } }
                markUnlocked()
            }
            else -> if (updated != null) withContext(Dispatchers.IO) { s.save(updated) }
        }
        result.outcome
    }

    private suspend fun saveIfDone(setup: PinSetup): PinSetup {
        if (setup is PinSetup.Done) withContext(Dispatchers.IO) { store().save(setup.config) }
        return setup
    }

    /** A new PIN. The PIN-mode marker is written before the config. */
    suspend fun create(pin: String): PinSetup = mutex.withLock {
        val setup = withContext(Dispatchers.Default) { core().create(pin, fingerprintAllowed = false) }
        if (setup is PinSetup.Done) withContext(Dispatchers.IO) { store().markOn() }
        saveIfDone(setup).also { if (it is PinSetup.Done) { pinSet = true; markUnlocked() } }
    }

    suspend fun changePin(newPin: String): PinSetup = mutex.withLock {
        val config = withContext(Dispatchers.IO) { store().load() } ?: return@withLock PinSetup.Unsupported
        saveIfDone(withContext(Dispatchers.Default) { core().changePin(config, newPin) })
    }

    suspend fun setDuress(duressPin: String): PinSetup = mutex.withLock {
        val config = withContext(Dispatchers.IO) { store().load() } ?: return@withLock PinSetup.Unsupported
        saveIfDone(withContext(Dispatchers.Default) { core().setDuress(config, duressPin) })
    }

    private suspend fun update(transform: (AppLockConfig) -> AppLockConfig?) {
        mutex.withLock {
            withContext(Dispatchers.IO) {
                val s = store()
                val config = s.load() ?: return@withContext
                transform(config)?.let { s.save(it) }
            }
        }
    }

    suspend fun removeDuress() = update { core().removeDuress(it) }

    suspend fun setWipeAfter(wipeAfter: Int) = update { core().withWipeAfter(it, wipeAfter) }

    /** Leave PIN mode: the PIN, its duress PIN and its counters. */
    suspend fun turnOff() = mutex.withLock {
        withContext(Dispatchers.IO) { store().clear() }
        pinSet = false
        markUnlocked()
    }

    // ── The wipe ───────────────────────────────────────────────────────
    //
    // Silent by design: no prompt, no progress, no message. The lock screen keeps its ordinary
    // "checking" state while this runs, then the app comes back as a fresh install. The flag
    // goes first and comes off last, so a wipe cut short (the app killed, the power gone)
    // finishes at the next start, before any window or command runs (resumeIfPending).

    /** Everything Clear All Data removes, plus the lock itself. Not cancellable once started. */
    suspend fun wipe(edits: DesktopKeyEdits) = withContext(NonCancellable + Dispatchers.IO) {
        runCatching { wipeFlag().markPending() }
        runCatching { ClearAllData.run(edits) }
        runCatching { store().clear() }
        runCatching { wipeFlag().clear() }
        pinSet = false
    }

    fun isWipePending(): Boolean = runCatching { wipeFlag().isPending() }.getOrDefault(false)

    // ── The command line (plan Q3) ─────────────────────────────────────

    /**
     * `pgpony` with a PGPony PIN set asks for it on the terminal before any verb runs. True when
     * the command may go on. The duress PIN and the wrong-PIN limit wipe silently and the command
     * then runs on the empty keyring, the same as a fresh install. Without a terminal
     * ([readPin] null) the command is refused. `pgpony sop` and the git shim never come here.
     */
    fun cliGate(
        readPin: (() -> String?)?,
        err: java.io.PrintStream,
        openEdits: () -> Pair<DesktopKeyEdits, () -> Unit> = ::openStandaloneEdits
    ): Boolean {
        if (!isSet()) return true
        if (readPin == null) {
            err.println("pgpony: PGPony is locked with a PGPony PIN; run this command in a terminal to enter it")
            return false
        }
        val pin = readPin() ?: return false
        return when (val r = kotlinx.coroutines.runBlocking { runCatching { submit(pin) }.getOrNull() }) {
            PinCheck.Unlocked -> true
            PinCheck.Duress, is PinCheck.WipeLimit -> {
                resumeIfPending(openEdits)
                true
            }
            is PinCheck.Wrong -> { err.println("pgpony: ${tr("applock_wrong_pin")}"); false }
            is PinCheck.Throttled -> { err.println("pgpony: ${tr("applock_wait_format", ((r.remainingMs + 999) / 1000).toInt())}"); false }
            PinCheck.Unsupported -> { err.println("pgpony: ${tr("applock_unavailable")}"); false }
            null -> { err.println("pgpony: ${tr("applock_check_failed")}"); false }
        }
    }

    /** [resumeIfPending] with the keyring opened from the data folder (the GUI and the command line). */
    fun resumeIfPendingStandalone() = resumeIfPending(::openStandaloneEdits)

    private fun openStandaloneEdits(): Pair<DesktopKeyEdits, () -> Unit> {
        val db = Db.open(Config.dbFile)
        return DesktopKeyEdits(DesktopKeyRepository(db, KeyMaterialStore(Config.keysDir))) to { db.close() }
    }

    /** Finish a wipe that was cut short. Called first thing by the GUI and the command line. */
    fun resumeIfPending(openEdits: () -> Pair<DesktopKeyEdits, () -> Unit>) {
        if (!isWipePending()) return
        val (edits, close) = openEdits()
        try {
            kotlinx.coroutines.runBlocking { wipe(edits) }
        } finally {
            runCatching { close() }
        }
    }

    /**
     * End this process and start the app again, so nothing decrypted before the lock survives in
     * memory and the new process opens as a fresh install. The new process waits a moment, so
     * this one has let go of the single-instance lock first. In a development run (no packaged
     * launcher) the app only closes.
     */
    fun relaunchFresh(): Nothing {
        val launcher = System.getProperty("jpackage.app-path")
        if (!launcher.isNullOrBlank()) runCatching { relaunchCommand(launcher, relaunchArgs()) }
            .onSuccess { cmd -> ProcessBuilder(cmd).redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start() }
        exitProcess(0)
    }

    /** The --data-dir a portable copy was started with, so the new process opens the same folder. */
    private fun relaunchArgs(): List<String> {
        val r = PortableMode.resolution
        return if (r is PortableMode.Resolution.Portable && r.fromFlag) listOf(PortableMode.DATA_DIR_FLAG, r.dataDir.toString()) else emptyList()
    }

    internal fun relaunchCommand(launcher: String, args: List<String>, osName: String = System.getProperty("os.name").orEmpty()): List<String> =
        if (osName.lowercase().contains("win")) {
            val quoted = (listOf(launcher) + args).joinToString(" ") { "\"$it\"" }
            listOf("cmd", "/c", "ping -n 2 127.0.0.1 >nul & start \"\" $quoted")
        } else {
            listOf("/bin/sh", "-c", "sleep 1; exec \"\$0\" \"\$@\"", launcher) + args
        }
}
