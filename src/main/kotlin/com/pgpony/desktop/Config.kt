// Config.kt
// PGPony Desktop — per-OS app paths + version constants (RelayPony Config pattern).

package com.pgpony.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

object AppVersion {
    /**
     * Desktop version line — independent of the Android 4xx and iOS 8.x bands.
     *
     * Must stay in step with `packageVersion` in build.gradle.kts: that one becomes the installer's
     * version and, on macOS, CFBundleShortVersionString. They had drifted (this read "1.0.0-dev.D1"
     * while the bundle said 1.0.0) and D13 caught it by reading a built Info.plist. This string is
     * also written into every .pgpony backup as `appVersion` metadata — informational only, nothing
     * reads it back on restore.
     */
    const val VERSION = "1.0.3"
}

object Config {

    /**
     * Per-OS application data directory, created on first use:
     *   macOS   ~/Library/Application Support/PGPony
     *   Linux   $XDG_DATA_HOME/pgpony  (fallback ~/.local/share/pgpony)
     *   Windows %APPDATA%\PGPony
     */
    val dataDir: Path by lazy {
        val home = System.getProperty("user.home")
        val os = System.getProperty("os.name").lowercase()
        val dir: Path = when {
            os.contains("mac") -> Paths.get(home, "Library", "Application Support", "PGPony")
            os.contains("win") -> {
                val appData = System.getenv("APPDATA")
                if (appData.isNullOrBlank()) Paths.get(home, "AppData", "Roaming", "PGPony")
                else Paths.get(appData, "PGPony")
            }
            else -> {
                val xdg = System.getenv("XDG_DATA_HOME")
                if (xdg.isNullOrBlank()) Paths.get(home, ".local", "share", "pgpony")
                else Paths.get(xdg, "pgpony")
            }
        }
        Files.createDirectories(dir)
        dir
    }

    /** The D1 bootstrap store file — read once by DesktopKeyRepository.migrateLegacyJson. */
    val legacyKeyringFile: Path get() = dataDir.resolve("keyring.json")

    /** Room database — same filename as Android ("pgpony.db"). */
    val dbFile: Path get() = dataDir.resolve("pgpony.db")

    /** Armored key material, one file per key half (KeyMaterialStore). */
    val keysDir: Path get() = dataDir.resolve("keys")
}
