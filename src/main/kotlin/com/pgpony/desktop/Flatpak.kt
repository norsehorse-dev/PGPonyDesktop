// Flatpak.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5c (plan 13a): what changes when PGPony runs as a
// Flatpak. Detection, and the two JVM defaults the sandbox needs before anything else runs.
//
// Preferences. java.util.prefs keeps its user tree under ~/.java. The Flatpak is granted only a
// few folders in home (Documents, Downloads, Desktop, and ~/.gnupg and ~/.password-store read
// only), so ~/.java is not writable there; and a user who widens the grant to all of home would
// otherwise share settings with an AppImage, AUR or .deb install on the same account while
// keeping a keyring of its own (XDG_DATA_HOME points into ~/.var/app). The user tree moves beside
// the rest of the Flatpak's data instead.
//
// Smart cards. javax.smartcardio looks for libpcsclite under /usr only. The Flatpak ships its own
// client library in /app/lib (the manifest builds pcsc-lite without its daemon), and
// --socket=pcsc brings the host pcscd's socket in, so the JDK is pointed at that copy.
//
// Both are system properties the JDK reads once, when the class that uses them first loads, so
// Main calls apply() before any other code runs. A property already set on the command line is
// left alone.
//
// Everything else that differs under Flatpak is decided where it happens: no update check (Flathub
// delivers updates), and GnuPG import without gpg (GnupgImport.sandboxed).

package com.pgpony.desktop

import java.nio.file.Files
import java.nio.file.Path

object Flatpak {

    const val PCSC_LIBRARY = "/app/lib/libpcsclite.so.1"

    private val env: (String) -> String? = { System.getenv(it) }
    private val exists: (String) -> Boolean = { Files.exists(Path.of(it)) }

    /** True inside a Flatpak sandbox. */
    val active: Boolean by lazy { detect(env, exists) }

    internal fun detect(env: (String) -> String?, exists: (String) -> Boolean): Boolean =
        !env("FLATPAK_ID").isNullOrBlank() || exists("/.flatpak-info")

    /** The system properties the sandbox needs, given its environment. Empty outside Flatpak. */
    internal fun defaults(env: (String) -> String?, exists: (String) -> Boolean): Map<String, String> {
        if (!detect(env, exists)) return emptyMap()
        val out = linkedMapOf<String, String>()
        // FileSystemPreferences puts its tree at <userRoot>/.java/.userPrefs.
        env("XDG_CONFIG_HOME")?.takeIf { it.isNotBlank() }?.let { out["java.util.prefs.userRoot"] = it }
        if (exists(PCSC_LIBRARY)) out["sun.security.smartcardio.library"] = PCSC_LIBRARY
        return out
    }

    /** Set the sandbox defaults. A no-op outside Flatpak. */
    fun apply() {
        for ((key, value) in defaults(env, exists)) {
            if (System.getProperty(key) == null) System.setProperty(key, value)
        }
    }
}
