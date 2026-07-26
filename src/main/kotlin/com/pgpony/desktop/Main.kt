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
private val CLI_VERBS = setOf("selftest", "version", "--version", "gui", "help", "--help", "-h") + PGPONY_VERBS

fun main(args: Array<String>) {
    val first = args.firstOrNull()

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
    if (!SingleInstance.acquire(fileArgs)) {
        return // forwarded to the running instance — exit quietly
    }
    cmdGui()
}

private fun usage() {
    println(
        """
        pgpony — OpenPGP on the desktop

        Usage: pgpony [command | file]

          gui         Open the graphical app (also opens when run with no command)
          <file>      Open a file in the app, routed by type (key → import, message → decrypt,
                      .pgpony → restore, detached signature → verify, anything else → encrypt)
          selftest    Verify the vendored OpenPGP engine runs on this JVM (keygen + round-trip)
          version     Print the version

        CLI verbs (share the app's keyring): encrypt · decrypt · sign · verify · import ·
        export · list-keys · gen-key. Run `pgpony <verb>` with no options for its usage.

          card-info   Report the PC/SC readers this build can see, and why it cannot see any
        """.trimIndent()
    )
}
