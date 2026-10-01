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
import com.pgpony.android.crypto.SecurityLimits
import kotlinx.coroutines.runBlocking
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardWatchEventKinds.ENTRY_CREATE
import java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY
import java.nio.file.SecureDirectoryStream
import java.nio.file.StandardOpenOption
import java.nio.file.WatchService
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
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
                    // 3.0.0 (4d): a link is never followed. An arrival that is a symlink to a file
                    // elsewhere (a synced or shared folder) would otherwise encrypt that file and
                    // write the result where the link's author can collect it.
                    val seen = identity(path)
                    if (seen == null) {
                        quiesce.forget(path); active.remove(path); continue
                    }
                    if (processed[path] == seen.mtime) { active.remove(path); continue }
                    if (quiesce.observe(path, seen.size)) {
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

        // 3.0.0 (4d): the file as it was when encrypting began. Delete-original only removes a
        // file that is still exactly that, so a writer that paused past the quiesce window and
        // then appended does not lose what it wrote after the ciphertext was made.
        val before = identity(path) ?: return
        var anyDelete = false
        var allOk = true
        // A file that changed under the open is left for its next event, not marked as done.
        var changedUnderOpen = false
        for (rule in matches) {
            // A file PGPony could not decrypt again is never encrypted by a rule that then
            // deletes the original.
            if (rule.deleteOriginal && before.size > SecurityLimits.MAX_STREAM_PLAINTEXT_BYTES) {
                record(rule, FileCryptoOps.FileOutcome(path, null, false, tr("d_watch_err_too_large", limitLabel())))
                allOk = false
                continue
            }
            val outcome = try {
                runBlocking {
                    fileOps.encryptFile(
                        file = path,
                        recipientFingerprints = rule.recipients,
                        signerFingerprint = null,      // encrypt-only: no secret, ever
                        signerPassphrase = null,
                        armor = rule.armor,
                        outputDir = rule.outputPath,
                        // Opened inside the watched folder without following links, and checked
                        // to be the file that went quiet (see WatchInput).
                        openInput = {
                            try {
                                WatchInput.open(folder, it, before)
                            } catch (e: WatchInput.Refused) {
                                if (e.changed) changedUnderOpen = true
                                throw e
                            }
                        }
                    )
                }
            } catch (t: Throwable) {
                FileCryptoOps.FileOutcome(path, null, false, t.message ?: "encrypt failed")
            }
            record(rule, outcome)
            if (outcome.ok) anyDelete = anyDelete || rule.deleteOriginal else allOk = false
        }

        // delete-original only after every matching rule succeeded (default off per rule).
        if (allOk && anyDelete && identity(path) == before) runCatching { Files.deleteIfExists(path) }
        if (changedUnderOpen) processed.remove(path) else processed[path] = identity(path)?.mtime ?: 0L
    }

    private fun limitLabel(): String = "${SecurityLimits.MAX_STREAM_PLAINTEXT_BYTES / (1024L * 1024 * 1024)} GB"

    /** Size and modification time of a regular file (not a link), or null. */
    internal fun snapshot(path: Path): Pair<Long, Long>? = identity(path)?.let { it.size to it.mtime }

    /**
     * Size, modification time and file key (where the platform has one) of a regular file,
     * read without following a link; null for anything else.
     */
    internal fun identity(path: Path): FileIdentity? = runCatching {
        val attrs = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (attrs.isRegularFile) {
            FileIdentity(attrs.size(), attrs.lastModifiedTime().toMillis(), attrs.fileKey(), WatchInput.changeTime(path))
        } else null
    }.getOrNull()

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

/**
 * What a watched file was when it went quiet. [key] is the file key and [ctime] the status
 * change time (which a rename or a new link moves on), each null where the platform has none.
 */
internal data class FileIdentity(val size: Long, val mtime: Long, val key: Any?, val ctime: Any? = null)

/**
 * Opening a watched file for a rule. The checks that matter are made on the open itself, not
 * before it: the file is opened inside the watched folder without following a link (through the
 * folder's handle where the platform has one, so no path component can be swapped), and must
 * still be the file that went quiet (same file key) and have no other hard link, so a link to a
 * file elsewhere, planted or swapped in, is refused rather than encrypted. The name is checked
 * again after the open, and the opened file's own size must be the size that went quiet; the
 * status change time catches a file renamed away and back around the open.
 */
internal object WatchInput {

    /** [changed]: the file was replaced or changed (worth another look later), not a link. */
    class Refused(message: String, val changed: Boolean = true) : java.io.IOException(message)

    fun open(folderReal: Path, file: Path, expected: FileIdentity): OpenedInput {
        val name = file.fileName ?: throw Refused(tr("d_watch_err_changed"))
        if (linkCount(file) > 1) throw Refused(tr("d_watch_err_linked"), changed = false)
        val noFollowRead = setOf(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)
        val folderStream = Files.newDirectoryStream(folderReal)
        val channel = folderStream.use { dir ->
            if (dir is SecureDirectoryStream<Path>) {
                val ch = try {
                    dir.newByteChannel(name, noFollowRead)
                } catch (e: java.io.IOException) {
                    throw Refused(tr("d_watch_err_changed"))
                }
                val now = runCatching {
                    dir.getFileAttributeView(name, BasicFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
                        .readAttributes()
                }.getOrNull()
                if (now == null || !now.isRegularFile || !matches(now, expected)) {
                    ch.close()
                    throw Refused(tr("d_watch_err_changed"))
                }
                ch
            } else {
                null
            }
        } ?: openByPath(folderReal, file, expected, noFollowRead)
        if (linkCount(file) > 1) {
            channel.close()
            throw Refused(tr("d_watch_err_linked"), changed = false)
        }
        val openedSize = runCatching { channel.size() }.getOrDefault(-1L)
        val ctimeNow = changeTime(file)
        if (openedSize != expected.size || (expected.ctime != null && ctimeNow != expected.ctime)) {
            channel.close()
            throw Refused(tr("d_watch_err_changed"))
        }
        return OpenedInput(java.nio.channels.Channels.newInputStream(channel), expected.size)
    }

    /** Where folders have no handle (Windows): open by path, then check where it was opened. */
    private fun openByPath(
        folderReal: Path,
        file: Path,
        expected: FileIdentity,
        options: Set<java.nio.file.OpenOption>
    ): java.nio.channels.SeekableByteChannel {
        if (file.parent?.toRealPath() != folderReal) throw Refused(tr("d_watch_err_changed"))
        val ch = try {
            Files.newByteChannel(file, options)
        } catch (e: java.io.IOException) {
            throw Refused(tr("d_watch_err_changed"))
        }
        val now = runCatching {
            Files.readAttributes(file, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        }.getOrNull()
        if (now == null || !now.isRegularFile || !matches(now, expected) || file.parent?.toRealPath() != folderReal) {
            ch.close()
            throw Refused(tr("d_watch_err_changed"))
        }
        return ch
    }

    private fun matches(now: BasicFileAttributes, expected: FileIdentity): Boolean {
        val key = now.fileKey()
        return if (key != null && expected.key != null) key == expected.key
        else now.size() == expected.size && now.lastModifiedTime().toMillis() == expected.mtime
    }

    /** The status change time (unix:ctime) of [file] itself, or null where there is none. */
    internal fun changeTime(file: Path): Any? =
        runCatching { Files.getAttribute(file, "unix:ctime", LinkOption.NOFOLLOW_LINKS) }.getOrNull()

    /** The file's hard link count where the platform reports one, else 1. */
    internal fun linkCount(file: Path): Int =
        runCatching { (Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toInt() }
            .getOrDefault(1)
}
