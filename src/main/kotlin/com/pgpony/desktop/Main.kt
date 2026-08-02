// Main.kt
// PGPony Desktop — one binary, several faces (RelayPony pattern): a bare launch (or `gui`)
// opens the graphical app; a CLI verb runs the CLI; a FILE PATH argument (from a file
// association double-click, "Open With", or the shell) opens that file in the app, routed by
// type (D9 — DesktopFileRouter). The full CLI verb set is phase D10.

package com.pgpony.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.system.exitProcess

// D10 — the pgpony CLI verbs (Cli.run) plus the meta verbs handled here.
private val PGPONY_VERBS = setOf(
    "encrypt", "decrypt", "sign", "verify", "import", "export", "list-keys", "gen-key",
    // 1.0.1 — card-info. This set is the GATE: a verb Cli.run() dispatches but that is missing
    // here never reaches it, and falls through to the usage text below instead. Adding a verb
    // means editing BOTH places, which is exactly what was forgotten first time round.
    "card-info"
)
private val CLI_VERBS = setOf("selftest", "version", "--version", "gui", "open", "help", "--help", "-h") + PGPONY_VERBS

fun main(args: Array<String>) {
    val first = args.firstOrNull()

    // D15 (2.0.0 §1b) — the git signing shim. Reached as `pgpony-gpg` (git invokes gpg.program
    // by that name, seen here through the launcher basename) or the explicit `gpg-shim` verb.
    // It is a scriptable, machine-readable face like the CLI verbs, so it pins English and runs
    // in-process, never touching the single-instance guard or the GUI.
    if (invokedAsGpgShim() || first == "gpg-shim") {
        I18n.pinEnglish()
        val shimArgs = if (first == "gpg-shim") args.drop(1) else args.toList()
        exitProcess(GpgShim.run(shimArgs, System.`in`, System.out, System.err))
    }

    // CLI output is scriptable, so a CLI process is pinned to English before any of it runs.
    // The repository and the crypto/backup helpers are shared with the GUI and their messages
    // are localized (D11b) — without this pin, someone's `pgpony import | grep failed` would
    // start missing lines the day they switched the app to German. Nothing is persisted; only
    // this process is affected, and the GUI's stored preference is untouched.
    if (first == "selftest" || first in PGPONY_VERBS) I18n.pinEnglish()

    // CLI verbs run in-process and never touch the single-instance guard.
    when (first) {
        "selftest" -> exitProcess(SelfTest.run())
        "version", "--version" -> { println("PGPony Desktop ${AppVersion.VERSION}"); return }
        "help", "--help", "-h" -> { usage(); return }
        in PGPONY_VERBS -> exitProcess(Cli.run(args))
    }

    // D14 (2.0.0 §2a) — `open` puts files in the GUI like a bare file argument does, but can
    // FORCE the operation instead of trusting classification: `pgpony open --op encrypt <file>…`.
    // The file-manager context menus and the clipboard sentinel are built on this spelling.
    // Not one of PGPONY_VERBS on purpose: it launches (or forwards to) the GUI, so it must not
    // pin English, and it routes through the single-instance guard like any other open.
    if (first == "open") {
        val request = try {
            parseOpenArgs(args.drop(1).toList())
        } catch (e: IllegalArgumentException) {
            System.err.println("pgpony: ${e.message}")
            System.err.println(OPEN_USAGE)
            exitProcess(ExitCode.USAGE)
        }
        if (!SingleInstance.acquire(request)) return
        cmdGui()
        return
    }

    // File-open arguments: any arg that isn't a known verb and resolves to an existing file.
    val fileArgs = if (first != null && first !in CLI_VERBS) {
        args.mapNotNull { runCatching { Path.of(it) }.getOrNull() }
            .filter { Files.exists(it) && Files.isRegularFile(it) }
    } else emptyList()

    // A non-verb, non-file first argument is a usage error.
    if (first != null && first !in CLI_VERBS && fileArgs.isEmpty()) {
        usage(); return
    }

    // GUI launch (bare, `gui`, or with file arguments). The single-instance guard forwards the
    // files to an already-running window when there is one; otherwise this becomes the primary.
    if (!SingleInstance.acquire(OpenRequest(fileArgs))) {
        return // forwarded to the running instance — exit quietly
    }
    cmdGui()
}

/**
 * True when this process was launched as the git signing shim rather than `pgpony`. jpackage
 * sets `jpackage.app-path` to the launcher the user (here, git) actually invoked; its basename
 * distinguishes the `pgpony-gpg` launcher from `pgpony` within the one app image. Falls back to
 * `sun.java.command` for a `java -jar` / dev run. Never throws — an unknown launcher is `pgpony`.
 */
internal fun invokedAsGpgShim(): Boolean {
    fun basename(p: String?): String =
        p?.substringAfterLast('/')?.substringAfterLast('\\')?.lowercase() ?: ""
    val appPath = basename(System.getProperty("jpackage.app-path"))
    if (appPath.isNotEmpty()) return appPath.removeSuffix(".exe") == "pgpony-gpg"
    return basename(System.getProperty("sun.java.command")).removeSuffix(".exe") == "pgpony-gpg"
}

private const val OPEN_USAGE =
    "usage: pgpony open [--op encrypt|decrypt|verify|import|restore] <file>..."

/**
 * The `open` grammar, apart from main() so it is testable without launching a window (CliTest).
 * Reuses the D10 [Options] parser, so `--op=encrypt`, `--op encrypt` and `--` all behave like
 * every other verb. Throws [IllegalArgumentException] with a printable message on a bad op
 * name, a missing file argument, or a path that is not an existing regular file — a
 * misconfigured context-menu verb must fail loudly on stderr, not open an empty window.
 */
internal fun parseOpenArgs(rest: List<String>): OpenRequest {
    val o = Options(rest)
    val op = o.value("--op")?.let {
        ForcedOp.fromCli(it) ?: throw IllegalArgumentException(
            "unknown --op '$it' (expected ${ForcedOp.entries.joinToString(" | ") { e -> e.cliName }})"
        )
    }
    val files = o.allPositionals().map { Path.of(it) }
    if (files.isEmpty()) throw IllegalArgumentException("open needs at least one file")
    files.firstOrNull { !Files.isRegularFile(it) }?.let {
        throw IllegalArgumentException("not a file: $it")
    }
    return OpenRequest(files.map { it.toAbsolutePath() }, op)
}

private fun usage() {
    println(
        """
        pgpony — OpenPGP on the desktop

        Usage: pgpony [command | file]

          gui         Open the graphical app (also opens when run with no command)
          <file>      Open a file in the app, routed by type (key → import, message → decrypt,
                      .pgpony → restore, detached signature → verify, anything else → encrypt)
          open        Open files in the app, optionally forcing the operation instead of
                      routing by type: pgpony open [--op encrypt|decrypt|verify|import|restore] <file>...
          selftest    Verify the vendored OpenPGP engine runs on this JVM (keygen + round-trip)
          version     Print the version
          gpg-shim    Speak git's gpg.program slice (sign + verify) against the keyring; also
                      reached as the `pgpony-gpg` launcher — set git's gpg.program to it

        CLI verbs (share the app's keyring): encrypt · decrypt · sign · verify · import ·
        export · list-keys · gen-key. Run `pgpony <verb>` with no options for its usage.

          card-info   Report the PC/SC readers this build can see, and why it cannot see any
        """.trimIndent()
    )
}
