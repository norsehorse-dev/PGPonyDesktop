// Config.kt
// PGPony Desktop — per-OS app paths + version constants (RelayPony Config pattern).

package com.pgpony.desktop

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
    const val VERSION = "3.0.5"
}

object Config {

    /**
     * Per-OS application data directory, created on first use:
     *   macOS   ~/Library/Application Support/PGPony
     *   Linux   $XDG_DATA_HOME/pgpony  (fallback ~/.local/share/pgpony)
     *   Windows %APPDATA%\PGPony
     *
     * 3.0.0: the folder is owner-only (0700 on macOS and Linux), set at creation and again at
     * every start so an install made with the default umask is fixed too. It holds the database
     * (contacts, notes, trust, revocation certificates) next to the key files. Windows keeps the
     * per-user ACL of %APPDATA%.
     *
     * 3.1.0 (plan 3e): in portable mode it is the PGPony-data folder beside the app, or the
     * --data-dir folder (PortableMode). On FAT32 and exFAT the owner-only step does nothing.
     */
    val dataDir: Path by lazy {
        PortableMode.dataDir?.let { dir ->
            OwnerOnlyPaths.createPrivateDirectories(dir)
            OwnerOnlyPaths.restrictTree(dir)
            return@lazy dir
        }
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
        OwnerOnlyPaths.createPrivateDirectories(dir)
        OwnerOnlyPaths.restrictTree(dir)
        dir
    }

    /** The D1 bootstrap store file — read once by DesktopKeyRepository.migrateLegacyJson. */
    val legacyKeyringFile: Path get() = dataDir.resolve("keyring.json")

    /** Room database — same filename as Android ("pgpony.db"). */
    val dbFile: Path get() = dataDir.resolve("pgpony.db")

    /** Armored key material, one file per key half (KeyMaterialStore). */
    val keysDir: Path get() = dataDir.resolve("keys")

    /**
     * D15: the ssh-agent's Unix socket lives here, 0700 dir / 0600 socket (SshAgentService).
     * 3.1.0 (plan 3e.3): in portable mode the data folder may be on FAT32 or exFAT, which cannot
     * hold a Unix socket, so the socket goes in an owner-only folder under the host's temp
     * directory, made once per run and removed on exit.
     */
    val agentDir: Path
        get() = if (PortableMode.active) portableAgentDir else dataDir.resolve("agent")

    private val portableAgentDir: Path by lazy {
        val dir = if (OwnerOnlyPaths.posix()) {
            java.nio.file.Files.createTempDirectory(
                "pgpony-agent",
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")
                )
            )
        } else java.nio.file.Files.createTempDirectory("pgpony-agent")
        Runtime.getRuntime().addShutdownHook(Thread({
            runCatching {
                java.nio.file.Files.walk(dir).use { s -> s.sorted(Comparator.reverseOrder()).forEach { java.nio.file.Files.deleteIfExists(it) } }
            }
        }, "pgpony-agent-cleanup"))
        dir
    }
}
