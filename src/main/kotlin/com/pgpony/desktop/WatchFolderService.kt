// WatchFolderService.kt
// PGPony Desktop — D18 (2.0.0 §3c): the watch-folder engine.
//
// WatchRule.kt holds the model and the pure logic (glob, quiesce); this owns the one daemon
// thread that turns "anything landing in ~/Backups is encrypted to the offsite key" into a
// sentence a user can actually say. It is ENCRYPT-ONLY — see WatchRule's header for why that
// is the whole security story — so it resolves recipient PUBLIC keys and never asks for a
// secret. Off by default (WatchRulesStore.enabled()); starting and stopping is the master
// toggle's job, wired in Gui.
//
// Shape: FileFolder WatchService, poll with a timeout so every tick is also a quiesce sweep,
// encrypt a file only once its size has held steady (QuiesceTracker), skip anything that is
// already ciphertext / a temp / a hidden file so the produced .gpg never re-triggers the rule.
// Outcomes go two places: a bounded in-memory log the Settings pane renders, and a tray
// notification through TrayOutbox (the watcher thread can't compose, so it hands messages to
// the window, the TrayNav idiom).

package com.pgpony.desktop

import androidx.compose.runtime.mutableStateListOf
import kotlinx.coroutines.runBlocking
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardWatchEventKinds.ENTRY_CREATE
import java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY
import java.nio.file.WatchService
import java.util.concurrent.TimeUnit

/** One thing the watcher did, for the results pane. [ok] false with [detail] on a failure. */
data class WatchOutcome(
    val ruleId: String,
    val source: String,
    val output: String?,
    val ok: Boolean,
    val detail: String,
    val at: Long
)

/** Background → window bridge for tray notifications (the watcher thread can't compose). */
object TrayOutbox {
    data class Msg(val title: String, val body: String, val warn: Boolean)
    private val queue = java.util.concurrent.ConcurrentLinkedQueue<Msg>()
    fun post(msg: Msg) = queue.add(msg)
    /** Drained by the Gui poll loop. */
    fun drain(): List<Msg> {
        val out = ArrayList<Msg>()
        while (true) out.add(queue.poll() ?: break)
        return out
    }
}

object WatchFolderService {

    /** The results pane reads this; snapshot state, so a new outcome recomposes it. Newest first. */
    val outcomes = mutableStateListOf<WatchOutcome>()
    private const val MAX_OUTCOMES = 100

    // ~1s between quiesce sweeps: a file must be the same size across two of these to be acted
    // on, so a copy is left alone until it's been quiet for roughly two seconds.
    private const val TICK_MS = 1000L

    @Volatile private var thread: Thread? = null
    @Volatile private var stopRequested = false
    @Volatile var lastError: String? = null
        private set

    fun isRunning(): Boolean = thread != null

    @Synchronized
    fun start(repo: DesktopKeyRepository) {
        if (thread != null) return
        lastError = null
        stopRequested = false
        val t = Thread({ runLoop(repo) }, "pgpony-watch-folders").apply { isDaemon = true }
        thread = t
        t.start()
    }

    @Synchronized
    fun stop() {
        stopRequested = true
        thread?.interrupt()
        thread = null
    }

    /** Re-read rules and restart the loop — called after the Settings UI edits the rule set. */
    @Synchronized
    fun reload(repo: DesktopKeyRepository) {
        if (thread == null) return
        stop()
        start(repo)
    }

    private fun runLoop(repo: DesktopKeyRepository) {
        val rules = WatchRulesStore.load().rules.filter { it.enabled }
        if (rules.isEmpty()) return
        val fileOps = FileCryptoOps(repo)

        // folder → its rules; register each existing folder once.
        val byFolder = rules.groupBy { runCatching { it.folderPath.toRealPath() }.getOrNull() }
            .filterKeys { it != null && Files.isDirectory(it) }
            .mapKeys { it.key!! }
        if (byFolder.isEmpty()) return

        val ws: WatchService = try {
            FileSystems.getDefault().newWatchService()
        } catch (e: Exception) {
            lastError = e.message; return
        }

        val quiesce = QuiesceTracker()
        val active = HashSet<Path>()          // candidate files being watched for stability
        val processed = HashMap<Path, Long>() // path → mtime we already handled (skip re-fire)

        try {
            for (folder in byFolder.keys) {
                runCatching { folder.register(ws, ENTRY_CREATE, ENTRY_MODIFY) }
                // Seed with anything already sitting in the folder at startup.
                runCatching {
                    Files.list(folder).use { s -> s.forEach { if (Files.isRegularFile(it)) active.add(it) } }
                }
            }

            while (!stopRequested) {
                val key = try {
                    ws.poll(TICK_MS, TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    break
                }
                if (key != null) {
                    val dir = key.watchable() as? Path
                    for (event in key.pollEvents()) {
                        val name = event.context() as? Path ?: continue
                        if (dir != null) active.add(dir.resolve(name))
                    }
                    if (!key.reset()) active.removeAll { it.parent == key.watchable() }
                }

                // Quiesce sweep: stat every candidate; act on the ones that just went stable.
                for (path in active.toList()) {
                    if (stopRequested) break
                    if (!Files.isRegularFile(path)) { quiesce.forget(path); active.remove(path); continue }
                    val mtime = runCatching { Files.getLastModifiedTime(path).toMillis() }.getOrDefault(0L)
                    if (processed[path] == mtime) { active.remove(path); continue }
                    val size = runCatching { Files.size(path) }.getOrNull()
                    if (size == null) continue
                    if (quiesce.observe(path, size)) {
                        handleStable(path, byFolder, fileOps, processed)
                        quiesce.forget(path)
                        active.remove(path)
                    }
                }
            }
        } finally {
            runCatching { ws.close() }
        }
    }

    /** A file has quiesced — encrypt it for every matching rule on its folder. */
    private fun handleStable(
        path: Path,
        byFolder: Map<Path, List<WatchRule>>,
        fileOps: FileCryptoOps,
        processed: MutableMap<Path, Long>
    ) {
        val name = path.fileName.toString()
        // Never chew our own output, a temp, or a hidden file — that is the anti-loop guard.
        if (name.startsWith(".") || FileCryptoOps.looksEncrypted(path)) return
        val folder = runCatching { path.parent?.toRealPath() }.getOrNull() ?: return
        val matches = byFolder[folder].orEmpty().filter { it.matches(name) }
        if (matches.isEmpty()) return

        var anyDelete = false
        var allOk = true
        for (rule in matches) {
            val outcome = try {
                runBlocking {
                    fileOps.encryptFile(
                        file = path,
                        recipientFingerprints = rule.recipients,
                        signerFingerprint = null,      // encrypt-only: no secret, ever
                        signerPassphrase = null,
                        armor = rule.armor,
                        outputDir = rule.outputPath
                    )
                }
            } catch (t: Throwable) {
                FileCryptoOps.FileOutcome(path, null, false, t.message ?: "encrypt failed")
            }
            record(rule, outcome)
            if (outcome.ok) anyDelete = anyDelete || rule.deleteOriginal else allOk = false
        }

        // delete-original only after every matching rule succeeded (default off per rule).
        if (allOk && anyDelete) runCatching { Files.deleteIfExists(path) }
        processed[path] = runCatching { Files.getLastModifiedTime(path).toMillis() }.getOrDefault(0L)
    }

    private fun record(rule: WatchRule, outcome: FileCryptoOps.FileOutcome) {
        val entry = WatchOutcome(
            ruleId = rule.id,
            source = outcome.input.fileName?.toString() ?: outcome.input.toString(),
            output = outcome.output?.fileName?.toString(),
            ok = outcome.ok,
            detail = outcome.detail,
            at = System.currentTimeMillis()
        )
        // mutableStateListOf writes are safe off the UI thread; recomposition is scheduled.
        outcomes.add(0, entry)
        while (outcomes.size > MAX_OUTCOMES) outcomes.removeAt(outcomes.size - 1)
        TrayOutbox.post(
            TrayOutbox.Msg(
                title = if (outcome.ok) tr("d_watch_notif_encrypted") else tr("d_watch_notif_failed"),
                body = "${entry.source}${entry.output?.let { " → $it" } ?: ""}",
                warn = !outcome.ok
            )
        )
    }
}
