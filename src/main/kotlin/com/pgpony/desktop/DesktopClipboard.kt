// DesktopClipboard.kt
// PGPony Desktop — D8: an auto-clearing clipboard. The Android app clears a copied secret after
// a timeout (ClipboardService, settings keys `clipboard_auto_clear` / `clipboard_clear_seconds`,
// default 60s); the desktop copied passwords for the first time in D8, so it needs the same
// discipline. Same setting KEYS and same default as Android, over java.util.prefs.
//
// One deliberate improvement on the Android behavior: the timer only clears the clipboard if it
// STILL HOLDS THE TEXT WE PUT THERE. If the user copied something else in the meantime, their
// clipboard is theirs — wiping it would be a data-loss bug wearing a security hat.
//
// The clipboard is a shared OS resource: on a machine with a clipboard manager or a sync service
// (KDE Klipper, Windows cloud clipboard, macOS Universal Clipboard) the copy may already have
// been recorded elsewhere, and clearing here cannot reach into that history. The UI says so.

package com.pgpony.desktop

import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.prefs.Preferences

object DesktopClipboard {

    const val KEY_AUTO_CLEAR = "clipboard_auto_clear"
    const val KEY_CLEAR_SECONDS = "clipboard_clear_seconds"
    const val DEFAULT_CLEAR_SECONDS = 60

    /** Test hook — a scratch node instead of the real one. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun autoClear(): Boolean = prefs().getBoolean(KEY_AUTO_CLEAR, true)
    fun setAutoClear(enabled: Boolean) = prefs().putBoolean(KEY_AUTO_CLEAR, enabled)

    /** Clamped to 5…600s — a 1s timer clears before the user can paste. */
    fun clearSeconds(): Int =
        prefs().getInt(KEY_CLEAR_SECONDS, DEFAULT_CLEAR_SECONDS).coerceIn(5, 600)

    fun setClearSeconds(seconds: Int) =
        prefs().putInt(KEY_CLEAR_SECONDS, seconds.coerceIn(5, 600))

    private val timer = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "pgpony-clipboard-clear").apply { isDaemon = true }
    }
    private var pending: ScheduledFuture<*>? = null

    /** Seconds left on the current auto-clear, or null when nothing is armed. Polled by the UI. */
    @Volatile
    var secondsRemaining: Int? = null
        private set

    /**
     * Copy [text] to the system clipboard. When [secret] (the default for D8's password and
     * field copies) and auto-clear is on, arms the countdown. Plain copies — a public key, a
     * recipient list — pass secret = false and cancel any armed timer, since the user is now
     * clearly using the clipboard for something else.
     */
    fun copy(text: String, secret: Boolean = true) {
        pending?.cancel(false)
        pending = null
        secondsRemaining = null

        runCatching {
            Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
        }.onFailure { return }

        if (!secret || !autoClear()) return

        val total = clearSeconds()
        secondsRemaining = total
        pending = timer.scheduleAtFixedRate({
            val left = (secondsRemaining ?: 0) - 1
            if (left > 0) {
                secondsRemaining = left
            } else {
                clearIfHolds(text)
                secondsRemaining = null
                pending?.cancel(false)
                pending = null
            }
        }, 1, 1, TimeUnit.SECONDS)
    }

    /** Clear now (the "Clear clipboard" button), regardless of what it currently holds. */
    fun clearNow() {
        pending?.cancel(false)
        pending = null
        secondsRemaining = null
        runCatching {
            Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(""), null)
        }
    }

    /**
     * Clear only if the clipboard still holds [expected] — see the header note. A clipboard we
     * can't read (another app owns it, or it holds a non-text flavor) is left alone: not ours to
     * wipe.
     */
    internal fun clearIfHolds(expected: String) {
        runCatching {
            val cb = Toolkit.getDefaultToolkit().systemClipboard
            val current = if (cb.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                cb.getData(DataFlavor.stringFlavor) as? String
            } else null
            if (current == expected) cb.setContents(StringSelection(""), null)
        }
    }
}
