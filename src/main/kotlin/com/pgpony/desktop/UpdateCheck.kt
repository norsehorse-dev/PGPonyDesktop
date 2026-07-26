// UpdateCheck.kt
// PGPony Desktop — D13. "Is there a newer version" against pgpony.app.
//
// This is the only outbound request the app makes that the user did not ask for, so the posture
// is worth stating rather than inferring:
//
//  - It is a plain GET of a static JSON file. No query string, no custom headers, no identifier,
//    no version of the running install — nothing goes out that could distinguish one user from
//    another. The server learns an IP fetched a public file, which is what serving a file means.
//  - It goes through HttpClientFactory, so a configured Tor/SOCKS proxy carries it exactly like
//    every keyserver request. A user routing PGPony over Tor is not silently exempted here.
//  - It is throttled to once a day and the timestamp is PERSISTED, so relaunching the app in a
//    loop cannot turn the check into a heartbeat.
//  - It is OPT-IN. It does nothing until the user turns it on, which is what keeps pgpony.app's
//    privacy policy true as written: nothing leaves the device by default, and the features that
//    transmit are off until switched on.
//  - It never downloads or installs anything. 1.0 surfaces that a newer version exists and points
//    at the download page; auto-update is explicitly out of scope (plan §5).
//
// The endpoint is downloads/desktop.json, deliberately NOT the APK's downloads/releases.json —
// that file is owned and rotated by the site's APK admin dashboard on every Android publish.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import com.pgpony.android.network.HttpClientFactory
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.prefs.Preferences

object UpdateCheck {

    /** Hardcoded constant, never built from remote data. */
    const val MANIFEST_URL = "https://pgpony.app/downloads/desktop.json"

    private const val KEY_ENABLED = "update_check_enabled"
    private const val KEY_LAST_MS = "update_check_last_ms"
    private const val KEY_LATEST  = "update_check_latest"

    /** Once a day. The manifest changes a handful of times a year; anything tighter is noise. */
    private const val INTERVAL_MS = 24L * 60L * 60L * 1000L

    /** Same preferences node ProxyPrefs uses, so all desktop settings live in one place. */
    private fun prefs(): Preferences = Preferences.userRoot().node("app/pgpony/desktop")

    enum class Status(val labelKey: String) {
        Idle("d_settings_updates_idle"),
        Checking("d_settings_updates_checking"),
        UpToDate("d_settings_updates_current"),
        Available("d_settings_updates_available"),
        Failed("d_settings_updates_failed")
    }

    /** Compose-observable so the Settings section repaints without polling. */
    var status by mutableStateOf(Status.Idle)
        private set

    var latestVersion by mutableStateOf<String?>(null)
        private set

    // OFF by default, and that default is load-bearing rather than a preference. pgpony.app's
    // privacy policy states that nothing leaves the device unless the user starts it, and that
    // the features which do transmit are off until switched on. An update check enabled out of
    // the box would make both statements false on desktop — so the app matches the promise
    // instead of the promise being amended to match the app.
    //
    // Read defensively: this initializer runs the first time ANY member is touched, including
    // from a unit test that only wants the pure comparator, and a preferences backing store that
    // is missing or locked (a sandboxed CI runner) must not take the whole object down with it.
    var autoEnabled by mutableStateOf(runCatching { prefs().getBoolean(KEY_ENABLED, false) }.getOrDefault(false))
        private set

    /** Turn the automatic check on or off. Named `setAuto` rather than exposing a setter on
     *  [autoEnabled]: a `var … by mutableStateOf` with `private set` already emits a JVM
     *  `setAutoEnabled`, and a hand-written twin beside it is a platform-declaration clash. */
    fun setAuto(enabled: Boolean) {
        prefs().putBoolean(KEY_ENABLED, enabled)
        autoEnabled = enabled
    }

    private fun lastCheckMs(): Long = prefs().getLong(KEY_LAST_MS, 0L)

    /**
     * Compare two dotted version strings. Negative if [a] is older than [b], zero if equal,
     * positive if newer.
     *
     * Segment-wise NUMERIC comparison, not string comparison: lexicographically "1.0.10" sorts
     * before "1.0.9", which would tell a user on 1.0.10 to downgrade. Missing segments count as
     * zero, so "1.1" and "1.1.0" are equal. A pre-release suffix sorts BELOW the same base
     * release ("1.1.0-rc.1" < "1.1.0"), which is what stops someone running the final 1.1.0 from
     * being offered a release candidate as an upgrade. Non-numeric junk in a segment reads as 0
     * rather than throwing — this parses a file from the network, and a malformed manifest should
     * mean "no update", never a crash.
     */
    fun compareVersions(a: String, b: String): Int {
        val (aBase, aPre) = splitVersion(a)
        val (bBase, bPre) = splitVersion(b)
        val an = aBase.split('.')
        val bn = bBase.split('.')
        for (i in 0 until maxOf(an.size, bn.size)) {
            val x = an.getOrNull(i)?.trim()?.toIntOrNull() ?: 0
            val y = bn.getOrNull(i)?.trim()?.toIntOrNull() ?: 0
            if (x != y) return x.compareTo(y)
        }
        return when {
            aPre == null && bPre == null -> 0
            aPre == null -> 1
            bPre == null -> -1
            else -> aPre.compareTo(bPre)
        }
    }

    private fun splitVersion(v: String): Pair<String, String?> {
        val t = v.trim()
        val i = t.indexOf('-')
        return if (i < 0) t to null else t.substring(0, i) to t.substring(i + 1)
    }

    /** True when [remote] is a strictly newer release than what this build reports. */
    fun isNewer(remote: String, running: String = AppVersion.VERSION): Boolean =
        remote.isNotBlank() && compareVersions(remote, running) > 0

    /**
     * Read `current.version` out of the manifest. Returns null on any failure — an unreachable
     * site, a proxy that is not running, a truncated body, a manifest whose shape changed. None
     * of those are worth surfacing as an error the user has to act on.
     */
    private suspend fun fetchLatest(): String? = withContext(Dispatchers.IO) {
        runCatching {
            val body = HttpClientFactory.client().get(MANIFEST_URL).bodyAsText()
            JSONObject(body).optJSONObject("current")?.optString("version", "")?.ifBlank { null }
        }.getOrNull()
    }

    /**
     * The automatic path: does nothing unless the check is enabled AND a day has passed. Safe to
     * call on every launch, which is exactly how it is wired.
     */
    suspend fun checkIfDue(now: Long = System.currentTimeMillis()) {
        if (!autoEnabled) return
        if (now - lastCheckMs() < INTERVAL_MS) return
        checkNow(now)
    }

    /** The explicit path: ignores both the toggle and the throttle. */
    suspend fun checkNow(now: Long = System.currentTimeMillis()) {
        status = Status.Checking
        val remote = fetchLatest()
        // Stamp the attempt either way. A site that is down should not be retried on every
        // launch for the rest of the day.
        prefs().putLong(KEY_LAST_MS, now)
        if (remote == null) {
            status = Status.Failed
            return
        }
        prefs().put(KEY_LATEST, remote)
        latestVersion = remote
        status = if (isNewer(remote)) Status.Available else Status.UpToDate
    }
}

// ── Settings UI ────────────────────────────────────────────────────────
//
// Lives here rather than in SettingsScreen.kt so the screen's edit stays a single SectionCard
// call — same-package, so no import is needed there.

@Composable
fun UpdateSection(state: DesktopState) {
    val scope = rememberCoroutineScope()
    val status = UpdateCheck.status
    val latest = UpdateCheck.latestVersion

    // Off-composition safety: tr() is a plain top-level function, not @Composable, so resolving
    // the label here is fine — but the argument only exists for the Available case.
    val line = if (status == UpdateCheck.Status.Available && latest != null) {
        tr("d_settings_updates_available", latest)
    } else {
        tr(status.labelKey)
    }

    Text(
        line,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    Spacer(Modifier.height(Spacing.Medium))

    WrapRow {
        OutlinedButton(
            enabled = status != UpdateCheck.Status.Checking,
            onClick = { scope.launch { UpdateCheck.checkNow() } }
        ) {
            Text(tr("d_settings_updates_check_now"))
        }
        if (status == UpdateCheck.Status.Available) {
            OutlinedButton(onClick = { openUri(Links.DESKTOP_DOWNLOAD, state) }) {
                Text(tr("d_settings_updates_download"))
            }
        }
    }

    Spacer(Modifier.height(Spacing.Medium))

    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(
            checked = UpdateCheck.autoEnabled,
            onCheckedChange = { UpdateCheck.setAuto(it) }
        )
        Spacer(Modifier.width(Spacing.Small))
        Text(
            tr("d_settings_updates_auto"),
            style = MaterialTheme.typography.bodyMedium
        )
    }
}
