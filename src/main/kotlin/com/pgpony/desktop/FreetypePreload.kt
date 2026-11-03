// FreetypePreload.kt
// PGPony Desktop 3.1.0 (plan 3a, #12): the system libfreetype preload, made independent of the launcher.
//
// On Linux the GTK file chooser opens blank ("drawing failure ... error occurred in libfreetype")
// unless the system libfreetype.so.6 is preloaded before the JVM starts (issue #1; the reasoning is
// in tools/linux-wrap-launcher.sh). The release wraps the launcher of the .deb and the tarball in a
// shell script that sets LD_PRELOAD, and the AppImage's AppRun does the same. Every launch that
// skips the wrapper got the blank picker: a menu entry or shortcut that points straight at
// PGPony.bin, the lowercase `pgpony` launcher run with no arguments, or a desktop file of the
// user's own (#12, antiX with IceWM).
//
// So a GUI launch checks for itself. On Linux, when LD_PRELOAD names no libfreetype, it finds the
// system copy the way PcscLibrary finds libpcsclite (the distribution directories, a 64-bit ELF
// file for this JVM's architecture, so a multiarch i386 copy is never picked) and starts the same
// launcher again with LD_PRELOAD set, then exits with that process's exit code. An environment
// variable marks the second process so it never loops. The wrappers stay the first line: with them
// in place none of this runs.
//
// Only GUI launches: the CLI, the git shim and SOP never open a window, and starting a second JVM
// would only slow them down. Skipped under Flatpak (the runtime is its own), outside a jpackage
// launch (a development run has no launcher to restart), and when PGPONY_NO_FT_PRELOAD is set.

package com.pgpony.desktop

import kotlin.system.exitProcess

object FreetypePreload {

    const val SONAME = "libfreetype.so.6"
    const val GUARD = "PGPONY_FT_PRELOADED"
    const val OPT_OUT = "PGPONY_NO_FT_PRELOAD"

    /** The command and environment for the second launch, or null when this launch can go on as it is. */
    internal data class Plan(val command: List<String>, val ldPreload: String)

    internal fun plan(
        osName: String,
        arch: String,
        env: (String) -> String?,
        appPath: String?,
        flatpak: Boolean,
        argv: List<String>,
        readHeader: (String) -> ByteArray?
    ): Plan? {
        if (!osName.lowercase().startsWith("linux") || flatpak) return null
        if (env(GUARD) != null || env(OPT_OUT) != null) return null
        if (appPath.isNullOrBlank()) return null
        val current = env("LD_PRELOAD").orEmpty()
        if (current.split(':', ' ').any { it.substringAfterLast('/').startsWith("libfreetype.so") }) return null
        val lib = PcscLibrary.choose(osName, arch, readHeader, SONAME) ?: return null
        val preload = if (current.isBlank()) lib else "$lib:$current"
        return Plan(listOf(appPath) + argv, preload)
    }

    /**
     * Called by Main just before a GUI launch takes the single-instance guard. Returns when no
     * second launch is needed (or it could not be started); otherwise never returns.
     */
    fun reexecIfNeeded(argv: Array<String>) {
        val plan = plan(
            osName = System.getProperty("os.name") ?: "",
            arch = System.getProperty("os.arch") ?: "",
            env = System::getenv,
            appPath = System.getProperty("jpackage.app-path"),
            flatpak = Flatpak.active,
            argv = argv.toList(),
            readHeader = PcscLibrary::header
        ) ?: return
        val process = runCatching {
            ProcessBuilder(plan.command).inheritIO().also { pb ->
                pb.environment()["LD_PRELOAD"] = plan.ldPreload
                pb.environment()[GUARD] = "1"
            }.start()
        }.getOrNull() ?: return
        exitProcess(runCatching { process.waitFor() }.getOrDefault(0))
    }
}
