// PortableMode.kt
// PGPony Desktop 3.1.0 (plan 3e): run from a USB drive with nothing installed.
//
// The switch is a folder named PGPony-data beside the app. No guessing whether a drive is
// removable: the folder decides, and deleting it makes the copy an ordinary install again.
// "Beside the app" depends on the build:
//
//   Windows app folder   the folder holding PGPony.exe            jpackage.app-path
//   Linux tarball        the folder holding the PGPony/ folder     jpackage.app-path (PGPony/bin/PGPony)
//   Linux AppImage       the folder holding the .AppImage file    APPIMAGE
//   macOS                the folder holding PGPony.app             jpackage.app-path
//
// --data-dir <path> on the command line beats the folder check, for anyone who wants the
// folder somewhere else (or a second keyring on one machine).
//
// macOS runs a downloaded (quarantined) app from a hidden read-only copy (App Translocation), so
// jpackage.app-path points into /private/var/folders/.../AppTranslocation/. The copy is a nullfs
// mount of the original, and the mount table names the original, so `mount` gives the folder to
// look in without any native code. If that lookup fails the app cannot tell whether a
// PGPony-data folder was meant, says so on stderr, and runs as an ordinary install; the docs tell
// the user to clear the quarantine.
//
// In portable mode everything that keeps state goes to the data folder: Config.dataDir (keys,
// database, signing pins) and the settings, through PortablePreferencesFactory, which replaces
// the registry / plist / ~/.java store for the whole process. The ssh-agent socket goes to the
// host's temp folder, since FAT32 and exFAT cannot hold a Unix socket.
//
// apply() runs first in main(), before the JDK's Preferences class loads: the factory property is
// read once.

package com.pgpony.desktop

import java.nio.file.Files
import java.nio.file.Path

object PortableMode {

    const val FOLDER_NAME = "PGPony-data"
    const val DATA_DIR_FLAG = "--data-dir"
    const val SETTINGS_FILE = "settings.properties"

    /** System property naming the settings file the preferences factory reads. */
    const val SETTINGS_PROPERTY = "pgpony.portable.settings"

    /** Set by [apply]; null outside portable mode. */
    @Volatile
    var dataDir: Path? = null
        private set

    val active: Boolean get() = dataDir != null

    /** What [resolve] found, and why; kept for About and the self-test. */
    sealed class Resolution {
        data class Portable(val dataDir: Path, val fromFlag: Boolean) : Resolution()
        data object Installed : Resolution()
        /** macOS ran a translocated copy and the original could not be found. */
        data class TranslocatedUnresolved(val appPath: String) : Resolution()
    }

    @Volatile
    var resolution: Resolution = Resolution.Installed
        private set

    /**
     * Decide the mode from [args], the environment and the launcher path, set the JVM properties
     * it needs, and return [args] without the --data-dir option.
     */
    fun apply(args: Array<String>): Array<String> {
        val (rest, flagDir) = takeDataDirFlag(args)
        val r = resolve(
            flagDir = flagDir,
            appPath = System.getProperty("jpackage.app-path"),
            appImage = System.getenv("APPIMAGE"),
            osName = System.getProperty("os.name").orEmpty(),
            isDirectory = { Files.isDirectory(it) },
            mountTable = { readMountTable() }
        )
        resolution = r
        when (r) {
            is Resolution.Portable -> {
                val dir = r.dataDir.toAbsolutePath().normalize()
                if (r.fromFlag) Files.createDirectories(dir)
                dataDir = dir
                if (System.getProperty("java.util.prefs.PreferencesFactory") == null) {
                    System.setProperty(SETTINGS_PROPERTY, dir.resolve(SETTINGS_FILE).toString())
                    System.setProperty("java.util.prefs.PreferencesFactory", PortablePreferencesFactory::class.java.name)
                }
            }
            is Resolution.TranslocatedUnresolved -> System.err.println(
                "PGPony: macOS is running a temporary copy of the app (${r.appPath}), so a $FOLDER_NAME " +
                    "folder beside it cannot be found. Running as an ordinary install. To run portable, " +
                    "clear the quarantine: xattr -dr com.apple.quarantine <path to PGPony.app>"
            )
            Resolution.Installed -> {}
        }
        return rest
    }

    /** [args] without `--data-dir <path>` / `--data-dir=<path>`, and the path given, if any. */
    internal fun takeDataDirFlag(args: Array<String>): Pair<Array<String>, Path?> {
        val out = ArrayList<String>(args.size)
        var dir: Path? = null
        var i = 0
        while (i < args.size) {
            val a = args[i]
            when {
                a == DATA_DIR_FLAG && i + 1 < args.size -> { dir = Path.of(args[i + 1]); i += 2; continue }
                a.startsWith("$DATA_DIR_FLAG=") -> dir = Path.of(a.substringAfter('='))
                else -> out += a
            }
            i++
        }
        return out.toTypedArray() to dir
    }

    /** The decision itself, with every outside input passed in so it can be tested. */
    internal fun resolve(
        flagDir: Path?,
        appPath: String?,
        appImage: String?,
        osName: String,
        isDirectory: (Path) -> Boolean,
        mountTable: () -> String?
    ): Resolution {
        if (flagDir != null) return Resolution.Portable(flagDir, fromFlag = true)
        val home = when {
            !appImage.isNullOrBlank() -> Path.of(appImage).toAbsolutePath().parent
            appPath.isNullOrBlank() -> null
            osName.lowercase().contains("mac") -> {
                val bundle = bundleOf(Path.of(appPath)) ?: return Resolution.Installed
                val original = if (isTranslocated(bundle)) {
                    originalOf(bundle, mountTable()) ?: return Resolution.TranslocatedUnresolved(appPath)
                } else bundle
                original.parent
            }
            osName.lowercase().contains("win") -> Path.of(appPath).toAbsolutePath().parent
            // Linux tarball / .deb: <root>/PGPony/bin/PGPony; the folder beside it holds PGPony/.
            else -> Path.of(appPath).toAbsolutePath().parent?.parent?.parent
        } ?: return Resolution.Installed
        val candidate = home.resolve(FOLDER_NAME)
        return if (isDirectory(candidate)) Resolution.Portable(candidate, fromFlag = false) else Resolution.Installed
    }

    /** The .app bundle that holds [launcher] (…/PGPony.app/Contents/MacOS/PGPony). */
    internal fun bundleOf(launcher: Path): Path? {
        var p: Path? = launcher.toAbsolutePath()
        while (p != null) {
            if (p.fileName?.toString()?.endsWith(".app") == true) return p
            p = p.parent
        }
        return null
    }

    internal fun isTranslocated(path: Path): Boolean = path.toString().contains("/AppTranslocation/")

    /**
     * The original location of a translocated [path], from `mount` output: the nullfs mount whose
     * mount point is the longest prefix of [path] names its source.
     */
    internal fun originalOf(path: Path, mountTable: String?): Path? {
        if (mountTable.isNullOrBlank()) return null
        val p = path.toString()
        val line = Regex("^(.+) on (.+) \\((.*)\\)$")
        var best: Pair<String, String>? = null
        for (raw in mountTable.lineSequence()) {
            val m = line.matchEntire(raw.trim()) ?: continue
            val (source, mountPoint, options) = m.destructured
            if (!options.contains("nullfs")) continue
            val mp = mountPoint.trimEnd('/')
            if ((p == mp || p.startsWith("$mp/")) && (best == null || mp.length > best.second.length)) best = source to mp
        }
        val (source, mp) = best ?: return null
        val src = Path.of(source)
        // The mount source is the original bundle itself (the copy then sits at <mount>/d/X.app)
        // or a folder holding it.
        if (source.trimEnd('/').endsWith(".app")) return src
        val rest = p.removePrefix(mp).trimStart('/')
        return if (rest.isEmpty()) src else src.resolve(rest)
    }

    private fun readMountTable(): String? = runCatching {
        val proc = ProcessBuilder("/sbin/mount").redirectErrorStream(true).start()
        val text = proc.inputStream.bufferedReader().readText()
        if (proc.waitFor() == 0) text else null
    }.getOrNull()
}
