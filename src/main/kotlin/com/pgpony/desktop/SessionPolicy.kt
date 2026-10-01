// SessionPolicy.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4b (plan section 7; Android 4.3.0 #15 and 4.6.1 #15).
//
// One "how long a secret stays unlocked" setting. The key passphrase cache below, the card PIN
// cache (DesktopCardPinCache.kt reads its duration here), SSH agent signing and git signing
// through the running app (ShimBridge.kt) all follow it, so a user who picks 1 hour gets 1 hour
// everywhere and the caches cannot disagree. Two lifecycle choices sit beside the timed ones, as
// on Android: until cleared (no timer; Clear now, a wrong secret or quitting drops it) and until
// the screen locks (the same, plus a lock event, where ScreenLock can see one).
//
// Android's 4.6.1 #15 bug was a second process reading a stale copy of this setting. Here the
// setting is read through java.util.prefs on every call, and only the app process holds secrets:
// pgpony-gpg never holds a passphrase and never reads this setting. For a protected key it asks
// the running app (ShimBridge), and the app applies the policy.
//
// Memory only. Nothing here is written to disk, and quitting the app clears everything.
//
// Screen lock. The JVM has no lock event, so ScreenLock asks the system: ioreg on macOS (the
// console session's lock flag), loginctl's LockedHint on Linux (systemd sessions; GNOME and KDE
// set it), and on Windows whether LogonUI.exe is running (it runs while the lock screen shows).
// Where none answers, Settings does not offer the choice. ScreenLockWatch polls only while the
// choice is selected.
//
// The choice fails closed. Many Linux lockers never set LockedHint, so there a "not locked"
// answer proves nothing until the desktop has once reported a lock. Until then, and whenever
// the watch has no fresh answer (the probe stopped answering, the watch is not running), held
// secrets follow the shortest timed choice instead of staying held, and Settings says so. A
// probe that stops answering also drops what is held, and so does a long gap between polls
// (the machine slept).

package com.pgpony.desktop

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.pgpony.android.crypto.card.CardPinCache
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

object SessionPolicy {

    const val KEY_DURATION_SEC = "session_cache_duration_sec"
    const val DEFAULT_DURATION_SEC = 300

    /** Held with no timer; cleared by Clear now, a wrong secret or quitting. */
    const val DURATION_UNTIL_CLEARED = -1

    /** As [DURATION_UNTIL_CLEARED], and also cleared when the screen locks. */
    const val DURATION_UNTIL_LOCKED = -2

    /** The timed choices, 1 minute to 1 hour, as on Android. */
    val TIMED_CHOICES = listOf(60, 300, 900, 3600)

    private const val MISSING = Long.MIN_VALUE
    private const val LONGEST_SEC = 86_400L

    fun durationSec(): Int {
        val store = SettingsStores.open() ?: return DEFAULT_DURATION_SEC
        val held = store.getLong(KEY_DURATION_SEC, MISSING)
        if (held != MISSING) return sanitize(held)
        // Before 3.0.0 the card PIN cache had its own duration. A user who chose one keeps it
        // as the session length.
        val legacy = CardPinCache.legacyDurationSec() ?: return DEFAULT_DURATION_SEC
        val migrated = sanitize(legacy.toLong())
        store.putLong(KEY_DURATION_SEC, migrated.toLong())
        return migrated
    }

    fun setDurationSec(seconds: Int) {
        SettingsStores.open()?.putLong(KEY_DURATION_SEC, sanitize(seconds.toLong()).toLong())
    }

    /** A stored value outside the known shapes reads as the default. */
    internal fun sanitize(value: Long): Int = when {
        value == DURATION_UNTIL_CLEARED.toLong() || value == DURATION_UNTIL_LOCKED.toLong() -> value.toInt()
        value in 1..LONGEST_SEC -> value.toInt()
        else -> DEFAULT_DURATION_SEC
    }

    fun isUntilCleared(): Boolean = durationSec() == DURATION_UNTIL_CLEARED
    fun isUntilLocked(): Boolean = durationSec() == DURATION_UNTIL_LOCKED

    /** What "until the screen locks" means while a lock cannot be confirmed: the shortest timed choice. */
    val UNCONFIRMED_LOCK_FALLBACK_SEC: Int get() = TIMED_CHOICES.first()

    /**
     * The duration secrets actually follow: the stored choice, except that "until the screen
     * locks" reads as [UNCONFIRMED_LOCK_FALLBACK_SEC] while ScreenLockWatch cannot vouch for
     * seeing a lock.
     */
    fun effectiveDurationSec(): Int {
        val d = durationSec()
        return if (d == DURATION_UNTIL_LOCKED && !ScreenLockWatch.isTrusted()) UNCONFIRMED_LOCK_FALLBACK_SEC else d
    }

    /** True under either lifecycle choice while it is in force: a held secret has no timer. */
    fun isLifecycleHeld(): Boolean = effectiveDurationSec() < 0

    /**
     * Milliseconds left for a secret stored at [storedAtNanos] (System.nanoTime, which does
     * not jump with the wall clock), under the CURRENT duration, so a change applies to secrets
     * already held. Long.MAX_VALUE under a lifecycle choice in force.
     */
    fun remainingMs(storedAtNanos: Long, nowNanos: Long = System.nanoTime()): Long {
        val d = effectiveDurationSec()
        if (d < 0) return Long.MAX_VALUE
        val elapsedMs = TimeUnit.NANOSECONDS.toMillis(nowNanos - storedAtNanos)
        return (d * 1000L - elapsedMs).coerceAtLeast(0L)
    }

    /** Drop every held secret: key passphrases and the card PIN. */
    fun clearAll() {
        PassphraseCache.clearAll()
        CardPinCache.clear()
    }

    /** The Settings label for a duration. */
    fun label(seconds: Int): String = when (seconds) {
        60 -> tr("settings_card_pin_cache_1min")
        300 -> tr("settings_card_pin_cache_5min")
        900 -> tr("settings_card_pin_cache_15min")
        3600 -> tr("settings_card_pin_cache_1hr")
        DURATION_UNTIL_CLEARED -> tr("settings_card_pin_cache_until_cleared")
        DURATION_UNTIL_LOCKED -> tr("d_session_until_screen_locks")
        else -> tr("d_cards_pin_cache_custom_seconds", seconds)
    }
}

/**
 * Key passphrases entered in the app, keyed by primary fingerprint (Android InAppPassphraseCache
 * and ProviderPassphraseCache in one). Filled only after the passphrase worked: a decrypt, a
 * signature, an SSH agent or git signing prompt. A wrong cached passphrase is dropped by the
 * caller that found it wrong, and a passphrase change drops the key's entry.
 *
 * An entry also records whether the passphrase was entered to sign (a signing screen or the git
 * signing prompt). Git signing through the running app uses only those ([getForSigning]), so
 * unlocking a key to decrypt or for ssh never lets another program get a signature silently.
 */
object PassphraseCache {

    private class Entry(val passphrase: String, val storedAtNanos: Long, val forSigning: Boolean)

    private val entries = ConcurrentHashMap<String, Entry>()

    private fun key(fingerprint: String) = fingerprint.lowercase()

    /**
     * Remember [passphrase] for [fingerprint]. [forSigning] marks one entered to sign; a later
     * put of the same passphrase for another purpose keeps that mark.
     */
    fun put(fingerprint: String, passphrase: String, forSigning: Boolean = false) {
        if (passphrase.isEmpty()) return
        val k = key(fingerprint)
        val keepMark = entries[k]?.let { it.forSigning && it.passphrase == passphrase } == true
        entries[k] = Entry(passphrase, System.nanoTime(), forSigning || keepMark)
    }

    private fun live(fingerprint: String): Entry? {
        val k = key(fingerprint)
        val entry = entries[k] ?: return null
        if (SessionPolicy.remainingMs(entry.storedAtNanos) <= 0L) {
            entries.remove(k, entry)
            return null
        }
        return entry
    }

    fun get(fingerprint: String): String? = live(fingerprint)?.passphrase

    /** The held passphrase only when it was entered to sign; null otherwise. */
    fun getForSigning(fingerprint: String): String? = live(fingerprint)?.takeIf { it.forSigning }?.passphrase

    fun clear(fingerprint: String) {
        entries.remove(key(fingerprint))
    }

    fun clearAll() = entries.clear()

    /** The longest time left over the held passphrases; 0 when none is held. */
    fun remainingMs(): Long {
        var longest = 0L
        for ((k, entry) in entries) {
            val left = SessionPolicy.remainingMs(entry.storedAtNanos)
            if (left <= 0L) entries.remove(k, entry) else if (left > longest) longest = left
        }
        return longest
    }
}

object ScreenLock {

    /** True when locked, false when not, null when this system gives no answer. */
    fun probe(): Boolean? {
        val os = System.getProperty("os.name").orEmpty().lowercase()
        return when {
            os.contains("mac") -> exec(listOf("/usr/sbin/ioreg", "-n", "Root", "-d1"))?.let(::parseMacIoreg)
            os.contains("win") -> exec(listOf("tasklist", "/FI", "IMAGENAME eq LogonUI.exe", "/NH"))?.let(::parseTasklist)
            else -> {
                val session = System.getenv("XDG_SESSION_ID")?.takeIf { it.isNotBlank() } ?: "self"
                exec(listOf("loginctl", "show-session", session, "-p", "LockedHint", "--value"))?.let(::parseLockedHint)
            }
        }
    }

    @Volatile private var supported: Boolean? = null

    /** Whether [probe] answers here; asked once per run. */
    fun isSupported(): Boolean = supported ?: (probe() != null).also { supported = it }

    private fun isLinux(): Boolean {
        val os = System.getProperty("os.name").orEmpty().lowercase()
        return !os.contains("mac") && !os.contains("win")
    }

    /** The settings key that records a lock seen on this kind of Linux desktop. */
    internal fun seenKey(): String =
        "session_lock_seen:" + (System.getenv("XDG_CURRENT_DESKTOP")?.takeIf { it.isNotBlank() } ?: "unknown").take(64)

    /**
     * Whether an answer of "not locked" can be believed: always on macOS and Windows, whose
     * probes read the lock itself; on Linux only once this desktop has reported a lock.
     */
    fun isConfirmed(): Boolean {
        if (!isLinux()) return true
        return runCatching { SettingsStores.open()?.getLong(seenKey(), 0L) == 1L }.getOrDefault(false)
    }

    /** Record that this desktop reported a lock (Linux). */
    fun markLockSeen() {
        if (!isLinux() || isConfirmed()) return
        runCatching { SettingsStores.open()?.putLong(seenKey(), 1L) }
    }

    private val MAC_LOCKED = Regex("\"(CGSSessionScreenIsLocked|IOConsoleLocked)\"\\s*=\\s*Yes")

    internal fun parseMacIoreg(text: String): Boolean? = when {
        MAC_LOCKED.containsMatchIn(text) -> true
        text.contains("IOConsoleUsers") || text.contains("IOConsoleLocked") -> false
        else -> null
    }

    internal fun parseLockedHint(text: String): Boolean? = when (text.trim().lowercase()) {
        "yes" -> true
        "no" -> false
        else -> null
    }

    internal fun parseTasklist(text: String): Boolean = text.lowercase().contains("logonui.exe")

    private fun exec(command: List<String>): String? = try {
        val p = ProcessBuilder(command).redirectErrorStream(true).start()
        p.outputStream.close()
        if (!p.waitFor(3, TimeUnit.SECONDS)) {
            p.destroyForcibly()
            null
        } else if (p.exitValue() != 0) {
            null
        } else {
            p.inputStream.readBytes().toString(Charsets.UTF_8)
        }
    } catch (_: Exception) {
        null
    }
}

/**
 * Clears every held secret on a lock event while "Until the screen locks" is chosen, and keeps
 * the freshness that SessionPolicy.effectiveDurationSec relies on.
 */
object ScreenLockWatch {

    internal const val POLL_MS = 2_000L

    // An answer older than this is not fresh: the probe can take up to 3 seconds itself.
    private const val FRESH_MS = 10_000L

    // A gap between polls this much longer than POLL_MS means the machine slept.
    private const val SLEEP_GAP_MS = 30_000L

    @Volatile private var thread: Thread? = null

    @Volatile private var lastAnswerMs = 0L
    @Volatile private var wasLocked = false
    @Volatile private var wasTrusted = false

    /** Test hook: treat the watch as running. */
    @Volatile internal var assumeRunning = false

    fun start() {
        synchronized(this) {
            if (thread != null) return
            thread = Thread(::loop, "pgpony-screen-lock").apply {
                isDaemon = true
                start()
            }
        }
    }

    /** True when a probe of [locked] after [wasLocked] is a lock event. */
    internal fun isLockEvent(wasLocked: Boolean, locked: Boolean): Boolean = locked && !wasLocked

    /**
     * Whether "until the screen locks" can be honoured right now: the watch runs, the platform
     * can confirm a lock, and the last probe answered recently.
     */
    fun isTrusted(nowMs: Long = System.currentTimeMillis()): Boolean =
        (thread != null || assumeRunning) && ScreenLock.isConfirmed() && nowMs - lastAnswerMs <= FRESH_MS

    private fun loop() {
        var lastTick = System.currentTimeMillis()
        while (true) {
            try {
                Thread.sleep(POLL_MS)
            } catch (_: InterruptedException) {
                return
            }
            val now = System.currentTimeMillis()
            val gap = now - lastTick
            lastTick = now
            if (!SessionPolicy.isUntilLocked()) {
                reset()
                continue
            }
            step(ScreenLock.probe(), now, gap)
        }
    }

    internal fun reset() {
        wasLocked = false
        wasTrusted = false
        lastAnswerMs = 0L
    }

    /**
     * One poll under "until the screen locks": [locked] is the probe's answer (null for none),
     * [gapMs] the time since the previous poll. Internal for tests.
     */
    internal fun step(locked: Boolean?, nowMs: Long, gapMs: Long) {
        if (gapMs > POLL_MS + SLEEP_GAP_MS) SessionPolicy.clearAll()
        if (locked == null) {
            // No answer: what was held under a trusted watch goes now; from here on the
            // fallback duration applies until answers come back.
            if (wasTrusted) SessionPolicy.clearAll()
            wasTrusted = false
            lastAnswerMs = 0L
            return
        }
        lastAnswerMs = nowMs
        if (locked) ScreenLock.markLockSeen()
        if (isLockEvent(wasLocked, locked)) SessionPolicy.clearAll()
        wasLocked = locked
        wasTrusted = isTrusted(nowMs)
    }
}

internal fun formatSessionCountdown(ms: Long): String {
    val totalSec = ms / 1000
    return "%d:%02d".format(totalSec / 60, totalSec % 60)
}

/** The Settings section: the one duration, what is held now, and Clear now. */
@Composable
fun SessionPolicySection() {
    var version by remember { mutableStateOf(0) }
    val duration = remember(version) { SessionPolicy.durationSec() }
    var lockSupported by remember { mutableStateOf<Boolean?>(null) }
    var remaining by remember { mutableStateOf(PassphraseCache.remainingMs()) }
    var pinHeld by remember { mutableStateOf(CardPinCache.isHolding()) }
    var lockTrusted by remember { mutableStateOf(ScreenLockWatch.isTrusted()) }
    var menuOpen by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        lockSupported = withContext(Dispatchers.IO) { ScreenLock.isSupported() }
    }
    LaunchedEffect(version) {
        while (true) {
            remaining = PassphraseCache.remainingMs()
            pinHeld = CardPinCache.isHolding()
            lockTrusted = ScreenLockWatch.isTrusted()
            delay(1000)
        }
    }
    val lockInForce = duration == SessionPolicy.DURATION_UNTIL_LOCKED && lockTrusted

    val choices = SessionPolicy.TIMED_CHOICES + SessionPolicy.DURATION_UNTIL_CLEARED +
        if (lockSupported == true || duration == SessionPolicy.DURATION_UNTIL_LOCKED) {
            listOf(SessionPolicy.DURATION_UNTIL_LOCKED)
        } else {
            emptyList()
        }

    WrapRow(verticalSpacing = Spacing.Medium) {
        Text(tr("settings_card_pin_cache_duration_label"), style = MaterialTheme.typography.bodyMedium)
        Box {
            OutlinedButton(onClick = { menuOpen = true }, shape = RoundedCornerShape(Radius.Small)) {
                Text(SessionPolicy.label(duration))
            }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                choices.forEach { sec ->
                    DropdownMenuItem(
                        text = { Text(SessionPolicy.label(sec)) },
                        onClick = { SessionPolicy.setDurationSec(sec); menuOpen = false; version++ }
                    )
                }
            }
        }
    }
    Spacer(Modifier.height(Spacing.Small))
    WrapRow(verticalSpacing = Spacing.Medium) {
        Text(
            when {
                remaining <= 0L -> tr("settings_passphrase_cache_none_held")
                lockInForce -> tr("d_session_held_until_locked")
                duration == SessionPolicy.DURATION_UNTIL_CLEARED -> tr("settings_passphrase_cache_held_until_cleared")
                else -> tr("settings_passphrase_cache_countdown_format", formatSessionCountdown(remaining))
            },
            style = MaterialTheme.typography.bodySmall
        )
        if (pinHeld) {
            Text(tr("d_session_pin_held"), style = MaterialTheme.typography.bodySmall)
        }
        if (remaining > 0L || pinHeld) {
            TextButton(onClick = { SessionPolicy.clearAll(); version++ }) { Text(tr("d_common_clear_now")) }
        }
    }
    if (duration == SessionPolicy.DURATION_UNTIL_LOCKED && !lockTrusted) {
        Spacer(Modifier.height(Spacing.Small))
        Text(
            tr("d_session_lock_unconfirmed", SessionPolicy.label(SessionPolicy.UNCONFIRMED_LOCK_FALLBACK_SEC)),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error
        )
    }
}
