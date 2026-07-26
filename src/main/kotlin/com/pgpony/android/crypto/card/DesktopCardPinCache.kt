// DesktopCardPinCache.kt — DESKTOP TWIN of the Android CardPinCache (vendored copy excluded in
// build.gradle.kts). Same package, same public API, same semantics; the only change is the
// preference backing: java.util.prefs.Preferences instead of SharedPreferences-via-PGPonyApp.
//
// The FILE is named DesktopCardPinCache.kt (declaring the same `object CardPinCache`) because
// Kotlin source-set excludes are set-wide: an exclude matching "**/card/CardPinCache.kt" would
// remove this file too, not just the vendored copy (D1 Fix1).
//
// Contract preserved from the Android original (3.1.0 Phase 7 B1/B2 + 4.0.0 Phase 9):
//   • Memory only — the PIN never touches disk or logs; process death clears it.
//   • Expiry = capturedAt + CURRENT duration preference, recomputed on every read, so duration
//     changes apply to an already-held PIN immediately.
//   • DURATION_UNTIL_CLEARED sentinel: held with no timer; clears only on wrong PIN, manual
//     Clear, toggle-off, or process death.
//   • Only PW1 is ever cached; PW3 never. Wrong PIN clears (wired at OpenPgpCardSession.verify —
//     the vendored session calls CardPinCache.clear()/remember() exactly as on Android).
//   • Enable flag default OFF.
//
// UPSTREAM SEAM CANDIDATE: a KeyValueSettings interface injected in the Android file would let
// one source file serve both platforms; first in line for the core-extraction pass (D0-1).

package com.pgpony.android.crypto.card

import java.util.prefs.Preferences

object CardPinCache {

    const val KEY_ENABLED = "card_pin_cache_enabled"
    const val KEY_DURATION_SEC = "card_pin_cache_duration_sec"
    const val DEFAULT_DURATION_SEC = 300 // 5 minutes

    /** Sentinel duration for "Until I clear it". */
    const val DURATION_UNTIL_CLEARED = -1

    @Volatile private var pin: String? = null
    @Volatile private var capturedAt: Long = 0L

    /** Test hook — the DesktopProxyPrefs/DesktopKeyServerDirectory pattern; lets the suite run
     *  on a scratch node instead of the user's real prefs tree. */
    internal var prefsOverride: Preferences? = null

    private val prefs: Preferences
        get() = prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun durationSec(): Int = prefs.getInt(KEY_DURATION_SEC, DEFAULT_DURATION_SEC)

    /** True when the duration preference is the "Until I clear it" sentinel. */
    fun isUntilCleared(): Boolean = durationSec() == DURATION_UNTIL_CLEARED

    /** Remember a successfully-verified PW1. No-op when disabled. */
    fun remember(pinValue: String) {
        if (!isEnabled()) return
        pin = pinValue
        capturedAt = System.currentTimeMillis()
    }

    /** The cached PIN, or null when disabled, empty, or expired (recompute-on-read). */
    fun retrieve(): String? {
        if (!isEnabled()) return null
        val held = pin ?: return null
        if (remainingMs() <= 0) {
            clear()
            return null
        }
        return held
    }

    /** Milliseconds until expiry; 0 when none held; Long.MAX_VALUE under the sentinel. */
    fun remainingMs(): Long {
        if (pin == null) return 0L
        if (isUntilCleared()) return Long.MAX_VALUE
        val expiresAt = capturedAt + durationSec() * 1000L
        return (expiresAt - System.currentTimeMillis()).coerceAtLeast(0L)
    }

    fun isHolding(): Boolean = pin != null && remainingMs() > 0

    /** Drop the held PIN (wrong PIN, user request, toggle off). */
    fun clear() {
        pin = null
        capturedAt = 0L
    }

    fun setEnabled(enabled: Boolean) {
        prefs.putBoolean(KEY_ENABLED, enabled)
        if (!enabled) clear()
    }

    fun setDurationSec(seconds: Int) {
        // Live-read semantics: retrieve()/remainingMs() consult the preference on every call,
        // so the new duration (or the sentinel) takes effect on a held PIN instantly.
        prefs.putInt(KEY_DURATION_SEC, seconds)
    }
}
