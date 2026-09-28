// GnupgImport.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5b (plan F3): import from GnuPG in one action.
//
// Reads a GnuPG home (Gpg4win's %APPDATA%\gnupg, GPG Suite's and Linux's ~/.gnupg, or
// $GNUPGHOME) and brings over its public keys, its trust, and, when gpg is installed, its
// secret keys. PGPony only reads: it never writes to the GnuPG folder or changes a key there.
//
// With gpg installed, everything goes through gpg itself: `--export` for public keys,
// `--export-ownertrust` and the validity column of `--list-keys` for trust, and
// `--export-secret-keys` one key at a time for secret keys, so gpg's own pinentry asks for
// each passphrase and the key arrives protected by it, as it was. Secret keys that live on a
// smartcard, or whose primary secret gpg holds only as a stub, are skipped with a reason.
//
// Without gpg, public keys come from pubring.kbx (the keybox; each OpenPGP blob holds one
// keyblock) or the older pubring.gpg (a plain packet stream), and trust from trustdb.gpg
// (40-byte records; a trust record carries a v4 fingerprint and the ownertrust). The screen
// says that secret keys need gpg, or an export and a file import.
//
// Trust mapping. GnuPG's ownertrust is how far you trust a key's owner to certify others;
// validity is whether the key is known to belong to its owner, which is what PGPony's trust
// levels mean. Ultimate (your own keys) stays Ultimate; a key gpg calls fully valid, or whose
// owner you trust fully, becomes Verified. Nothing is ever lowered: a key already Verified in
// PGPony stays Verified.
//
// Under Flatpak there is no gpg in the sandbox, so only public keys and trust import. The
// Flatpak's home grant (5c) makes ~/.gnupg readable, and the dialog can still pick another folder.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.awt.AwtWindow
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import javax.swing.JFileChooser
import javax.swing.SwingUtilities

object GnupgImport {

    /** An installed gpg: its path and the first line of `gpg --version`. */
    data class Gpg(val path: Path, val version: String)

    /** A secret key gpg lists. [onCard]: on a smartcard; [stub]: gpg holds no primary secret. */
    data class SecretKey(val fingerprint: String, val userId: String, val onCard: Boolean, val stub: Boolean)

    /** What a GnuPG home holds, as far as PGPony can see it. */
    data class Scan(
        val home: Path,
        val gpg: Gpg?,
        val publicKeys: Int,
        val secretKeys: List<SecretKey>,
        val sandboxed: Boolean
    )

    data class Result(
        val report: ImportReport,
        val trustSet: Int,
        val secretsImported: Int,
        val notes: List<String>
    )

    /** One key record from `gpg --with-colons` output. */
    data class ColonKey(
        val secret: Boolean,
        val fingerprint: String,
        val validity: Char?,
        val ownertrust: Char?,
        val serial: String,
        val userId: String
    )

    // 3.0.0 (4d rules): bounds on what is read from GnuPG or gpg.
    private const val MAX_READ = 256L * 1024 * 1024
    private const val TRUST_RECORD = 40
    private const val RECTYPE_TRUST = 12

    fun sandboxed(): Boolean = Flatpak.active

    private val isWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")

    /** $GNUPGHOME, else the platform's default GnuPG home. */
    fun defaultHome(): Path {
        System.getenv("GNUPGHOME")?.takeIf { it.isNotBlank() }?.let { return Path.of(it) }
        val home = System.getProperty("user.home") ?: "."
        return if (isWindows) Path.of(System.getenv("APPDATA") ?: home, "gnupg") else Path.of(home, ".gnupg")
    }

    fun looksLikeHome(dir: Path): Boolean =
        Files.isRegularFile(dir.resolve("pubring.kbx")) || Files.isRegularFile(dir.resolve("pubring.gpg"))

    /** gpg on PATH or in the usual install places; null when there is none, or in a sandbox. */
    fun findGpg(): Gpg? {
        if (sandboxed()) return null
        val names = if (isWindows) listOf("gpg.exe") else listOf("gpg", "gpg2")
        val onPath = System.getenv("PATH").orEmpty().split(File.pathSeparatorChar).filter { it.isNotBlank() }
            .flatMap { dir -> names.map { Path.of(dir, it) } }
        val known = if (isWindows) {
            listOf("C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe", "C:\\Program Files\\GnuPG\\bin\\gpg.exe")
        } else {
            listOf("/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/local/MacGPG2/bin/gpg2", "/usr/bin/gpg")
        }.map { Path.of(it) }
        for (candidate in onPath + known) {
            if (!Files.isRegularFile(candidate) || !Files.isExecutable(candidate)) continue
            val version = runCatching { exec(listOf(candidate.toString(), "--version"), 10) }.getOrNull()
                ?.toString(Charsets.UTF_8)?.lineSequence()?.firstOrNull()?.trim() ?: continue
            if (version.startsWith("gpg")) return Gpg(candidate, version)
        }
        return null
    }

    // ── Pure parsers (tests drive these) ────────────────────────────────────

    /** The OpenPGP keyblocks in a keybox file (pubring.kbx), in order. */
    fun keyboxKeyblocks(kbx: ByteArray): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        var off = 0
        while (off + 16 <= kbx.size) {
            val len = SopPackets.be32(kbx, off)
            if (len < 16 || off + len > kbx.size) break
            if (kbx[off + 4].toInt() == 2) {
                val kbOff = SopPackets.be32(kbx, off + 8)
                val kbLen = SopPackets.be32(kbx, off + 12)
                if (kbOff >= 0 && kbLen > 0 && kbOff.toLong() + kbLen <= len) {
                    out += kbx.copyOfRange(off + kbOff, off + kbOff + kbLen)
                }
            }
            off += len
        }
        return out
    }

    /** Ownertrust by uppercase v4 fingerprint, from trustdb.gpg's trust records. */
    fun trustdbOwnertrust(trustdb: ByteArray): Map<String, Int> {
        val out = mutableMapOf<String, Int>()
        var off = 0
        while (off + TRUST_RECORD <= trustdb.size) {
            if (trustdb[off].toInt() == RECTYPE_TRUST) {
                val fp = trustdb.copyOfRange(off + 2, off + 22)
                if (fp.any { it.toInt() != 0 }) {
                    out[fp.joinToString("") { "%02X".format(it) }] = trustdb[off + 22].toInt() and 0x0F
                }
            }
            off += TRUST_RECORD
        }
        return out
    }

    /** `gpg --export-ownertrust`: "FINGERPRINT:LEVEL:" lines, comments start with '#'. */
    fun parseOwnertrustExport(text: String): Map<String, Int> =
        text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { line ->
                val parts = line.split(':')
                val fp = parts.getOrNull(0)?.uppercase()?.takeIf { f -> f.all { it in "0123456789ABCDEF" } && f.length >= 40 }
                val level = parts.getOrNull(1)?.toIntOrNull()
                if (fp != null && level != null) fp to (level and 0x0F) else null
            }.toMap()

    /** The keys in `gpg --list-keys` / `--list-secret-keys` `--with-colons` output. */
    fun parseColons(listing: String): List<ColonKey> {
        val out = mutableListOf<ColonKey>()
        var current: ColonKey? = null
        var wantFpr = false
        fun flush() {
            current?.takeIf { it.fingerprint.isNotEmpty() }?.let { out += it }
            current = null
        }
        for (line in listing.lineSequence()) {
            val f = line.split(':')
            when (f.firstOrNull()) {
                "pub", "sec" -> {
                    flush()
                    current = ColonKey(
                        secret = f[0] == "sec",
                        fingerprint = "",
                        validity = f.getOrNull(1)?.firstOrNull(),
                        ownertrust = f.getOrNull(8)?.firstOrNull(),
                        serial = f.getOrNull(14).orEmpty(),
                        userId = ""
                    )
                    wantFpr = true
                }
                "fpr" -> if (wantFpr) {
                    current = current?.copy(fingerprint = f.getOrNull(9).orEmpty().uppercase())
                    wantFpr = false
                }
                "uid" -> current?.let { c ->
                    if (c.userId.isEmpty()) current = c.copy(userId = unescapeColon(f.getOrNull(9).orEmpty()))
                }
                "sub", "ssb" -> wantFpr = false
            }
        }
        flush()
        return out
    }

    private fun unescapeColon(s: String): String =
        Regex("\\\\x([0-9a-fA-F]{2})").replace(s) { it.groupValues[1].toInt(16).toChar().toString() }

    /** GnuPG trust to PGPony trust. Ownertrust: 5 full, 6 ultimate. Validity: f full, u ultimate. */
    fun trustFor(ownertrust: Int?, validity: Char?): TrustLevel? = when {
        ownertrust == 6 || validity == 'u' -> TrustLevel.ULTIMATE
        ownertrust == 5 || validity == 'f' -> TrustLevel.VERIFIED
        else -> null
    }

    // ── Reading a home ──────────────────────────────────────────────────────

    private fun readCapped(p: Path): ByteArray? {
        if (!Files.isRegularFile(p)) return null
        if (Files.size(p) > MAX_READ) throw IllegalStateException("${p.fileName} is too large")
        return Files.readAllBytes(p)
    }

    /** Public keys straight from the files, for when there is no gpg. */
    fun readPublicKeys(home: Path): ByteArray {
        readCapped(home.resolve("pubring.kbx"))?.let { kbx ->
            return keyboxKeyblocks(kbx).fold(ByteArray(0)) { acc, b -> acc + b }
        }
        return readCapped(home.resolve("pubring.gpg")) ?: ByteArray(0)
    }

    /** Runs a command and returns its stdout; a nonzero exit throws with the end of stderr. */
    private fun exec(command: List<String>, timeoutSeconds: Long): ByteArray {
        val p = ProcessBuilder(command).start()
        p.outputStream.close()
        var out = ByteArray(0)
        var err = ByteArray(0)
        val outReader = Thread { out = p.inputStream.readNBytes(MAX_READ.toInt()) }.apply { start() }
        val errReader = Thread { err = p.errorStream.readNBytes(64 * 1024) }.apply { start() }
        if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            p.destroyForcibly()
            throw IllegalStateException("gpg did not finish in $timeoutSeconds seconds")
        }
        outReader.join()
        errReader.join()
        if (p.exitValue() != 0) {
            val tail = String(err, Charsets.UTF_8).trim().lines().lastOrNull().orEmpty()
            throw IllegalStateException(tail.ifEmpty { "gpg exited with ${p.exitValue()}" })
        }
        return out
    }

    /** gpg against [home], read-only in effect: no trustdb check, no permission warning. */
    private fun gpg(g: Gpg, home: Path, timeoutSeconds: Long, vararg args: String): ByteArray =
        exec(
            listOf(g.path.toString(), "--homedir", home.toString(), "--batch", "--no-auto-check-trustdb", "--no-permission-warning") + args,
            timeoutSeconds
        )

    fun scan(home: Path, gpg: Gpg? = findGpg()): Scan {
        if (gpg != null) {
            val pub = parseColons(String(gpg(gpg, home, 60, "--with-colons", "--list-keys"), Charsets.UTF_8))
            val sec = parseColons(String(gpg(gpg, home, 60, "--with-colons", "--list-secret-keys"), Charsets.UTF_8))
            val secrets = sec.map { k ->
                SecretKey(k.fingerprint, k.userId, onCard = k.serial.isNotEmpty() && k.serial != "+" && k.serial != "#", stub = k.serial == "#")
            }
            return Scan(home, gpg, pub.size, secrets, sandboxed())
        }
        val count = SopPackets.split(readPublicKeys(home)).count { it.first == 6 }
        return Scan(home, null, count, emptyList(), sandboxed())
    }

    /** Import what [scan] found. Trust only ever goes up; secret keys need gpg. */
    suspend fun import(repo: DesktopKeyRepository, scan: Scan, withTrust: Boolean, withSecrets: Boolean): Result {
        val g = scan.gpg
        val publicBytes = if (g != null) gpg(g, scan.home, 120, "--export") else readPublicKeys(scan.home)
        var report = if (publicBytes.isEmpty()) ImportReport(0, 0, 0, 0) else repo.importBytes(publicBytes)
        val notes = mutableListOf<String>()

        var secretsImported = 0
        if (withSecrets && g != null) {
            for (s in scan.secretKeys) {
                val label = s.userId.ifBlank { s.fingerprint }
                when {
                    s.onCard -> notes += tr("d_gnupg_card_skipped", label)
                    s.stub -> notes += tr("d_gnupg_stub_skipped", label)
                    else -> try {
                        // One key per call, so gpg's pinentry names the key it is asking about.
                        val bytes = gpg(g, scan.home, 300, "--export-secret-keys", s.fingerprint)
                        val r = repo.importBytes(bytes)
                        if (r.failed == 0 && r.total > 0) secretsImported++ else notes += tr("d_gnupg_secret_not_imported", label)
                        report = report.plus(r)
                    } catch (e: Exception) {
                        notes += tr("d_gnupg_secret_failed", label, e.message.orEmpty())
                    }
                }
            }
        }

        var trustSet = 0
        if (withTrust) {
            val targets = mutableMapOf<String, TrustLevel>()
            val ownertrust = if (g != null) {
                parseOwnertrustExport(String(gpg(g, scan.home, 60, "--export-ownertrust"), Charsets.UTF_8))
            } else {
                readCapped(scan.home.resolve("trustdb.gpg"))?.let { trustdbOwnertrust(it) }.orEmpty()
            }
            val validity = if (g != null) {
                parseColons(String(gpg(g, scan.home, 60, "--with-colons", "--list-keys"), Charsets.UTF_8))
                    .associate { it.fingerprint to it.validity }
            } else {
                emptyMap()
            }
            for (fp in ownertrust.keys + validity.keys) {
                trustFor(ownertrust[fp], validity[fp])?.let { level ->
                    val prior = targets[fp]
                    if (prior == null || level.ordinal > prior.ordinal) targets[fp] = level
                }
            }
            for ((fp, level) in targets) {
                val e = repo.byFingerprint(fp) ?: continue
                if (level.ordinal > e.trustLevel.ordinal) {
                    repo.updateTrustLevel(e.fingerprint, level)
                    trustSet++
                }
            }
        }
        return Result(report, trustSet, secretsImported, notes)
    }

    private fun ImportReport.plus(o: ImportReport) = ImportReport(
        inserted + o.inserted, upgraded + o.upgraded, already + o.already, failed + o.failed, merged + o.merged
    )
}

// ── The dialog ─────────────────────────────────────────────────────────────

@Composable
fun GnupgImportDialog(state: DesktopState, onDismiss: () -> Unit) {
    val scope = rememberCoroutineScope()
    var home by remember { mutableStateOf(GnupgImport.defaultHome()) }
    var scan by remember { mutableStateOf<GnupgImport.Scan?>(null) }
    var scanError by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(true) }
    var withTrust by remember { mutableStateOf(true) }
    var withSecrets by remember { mutableStateOf(true) }
    var working by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<GnupgImport.Result?>(null) }
    var pickFolder by remember { mutableStateOf(false) }
    val sandboxed = remember { GnupgImport.sandboxed() }

    LaunchedEffect(home) {
        scanning = true
        scanError = null
        scan = null
        val (s, err) = withContext(Dispatchers.IO) {
            if (!GnupgImport.looksLikeHome(home)) null to null
            else runCatching { GnupgImport.scan(home) }.fold({ it to null }, { null to (it.message ?: it.javaClass.simpleName) })
        }
        scan = s
        scanError = err
        scanning = false
    }

    fun runImport() {
        val s = scan ?: return
        working = true
        scope.launch {
            try {
                result = withContext(Dispatchers.IO) {
                    GnupgImport.import(state.repository, s, withTrust, withSecrets && s.gpg != null)
                }
                state.reload()
            } catch (e: Exception) {
                scanError = e.message ?: e.javaClass.simpleName
            } finally {
                working = false
            }
        }
    }

    BrandDialog(
        onDismissRequest = { if (!working) onDismiss() },
        title = tr("d_gnupg_title"),
        content = {
            Column(Modifier.fillMaxWidth().heightIn(max = 520.dp).verticalScroll(rememberScrollState())) {
                val done = result
                if (done != null) {
                    Text(
                        tr("d_gnupg_done", done.report.summary(), done.trustSet, done.secretsImported),
                        style = MaterialTheme.typography.bodyMedium
                    )
                    done.notes.forEach {
                        Spacer(Modifier.height(4.dp))
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    return@Column
                }
                Text(tr("d_gnupg_home", home.toString()), style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                Spacer(Modifier.height(4.dp))
                OutlinedButton(onClick = { pickFolder = true }, enabled = !working) { Text(tr("d_gnupg_choose_folder")) }
                Spacer(Modifier.height(8.dp))
                val s = scan
                when {
                    scanning -> Text(tr("d_common_working"), style = MaterialTheme.typography.bodyMedium)
                    scanError != null -> Text(scanError!!, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                    s == null -> Text(tr("d_gnupg_no_home"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                    else -> {
                        Text(
                            if (s.gpg != null) tr("d_gnupg_counts", s.publicKeys, s.secretKeys.size) else tr("d_gnupg_counts_public", s.publicKeys),
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            when {
                                s.gpg != null -> tr("d_gnupg_gpg_found", s.gpg.version)
                                sandboxed -> tr("d_gnupg_sandboxed")
                                else -> tr("d_gnupg_gpg_missing")
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = withTrust, onCheckedChange = { withTrust = it }, enabled = !working)
                            Text(tr("d_gnupg_opt_trust"), style = MaterialTheme.typography.bodyMedium)
                        }
                        if (s.gpg != null && s.secretKeys.isNotEmpty()) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = withSecrets, onCheckedChange = { withSecrets = it }, enabled = !working)
                                Text(tr("d_gnupg_opt_secret"), style = MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text(tr("d_gnupg_readonly_note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
        confirmButton = {
            if (result == null) {
                TextButton(enabled = scan != null && !working && !scanning, onClick = { runImport() }) {
                    Text(if (working) tr("d_common_working") else tr("d_gnupg_import"))
                }
            } else {
                TextButton(onClick = onDismiss) { Text(tr("common_button_close")) }
            }
        },
        dismissButton = {
            if (result == null) TextButton(onClick = onDismiss, enabled = !working) { Text(tr("common_button_cancel")) }
        }
    )

    if (pickFolder) {
        GnupgFolderDialog(home) { picked ->
            pickFolder = false
            if (picked != null) home = picked.toPath()
        }
    }
}

/**
 * Pick the GnuPG folder. macOS: the native dialog in directory mode; elsewhere Swing's chooser
 * (the PassScreen pattern). Hidden folders show, since ~/.gnupg is one.
 */
@Composable
private fun GnupgFolderDialog(start: Path, onResult: (File?) -> Unit) {
    val mac = remember { System.getProperty("os.name").lowercase().contains("mac") }
    if (mac) {
        AwtWindow(
            create = {
                System.setProperty("apple.awt.fileDialogForDirectories", "true")
                object : FileDialog(null as Frame?, tr("d_gnupg_choose_folder"), LOAD) {
                    init {
                        directory = (start.parent ?: start).toString()
                    }

                    override fun setVisible(visible: Boolean) {
                        super.setVisible(visible)
                        if (visible) {
                            val picked = file?.let { File(directory, it) }
                            System.setProperty("apple.awt.fileDialogForDirectories", "false")
                            onResult(picked)
                        }
                    }
                }
            },
            dispose = FileDialog::dispose
        )
    } else {
        LaunchedEffect(Unit) {
            onResult(withContext(Dispatchers.IO) { chooseGnupgFolderSwing(start) })
        }
    }
}

private fun chooseGnupgFolderSwing(start: Path): File? {
    var chosen: File? = null
    val show = Runnable {
        val chooser = JFileChooser().apply {
            dialogTitle = tr("d_gnupg_choose_folder")
            fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            isFileHidingEnabled = false
            isMultiSelectionEnabled = false
            currentDirectory = (start.toFile().takeIf { it.isDirectory } ?: File(System.getProperty("user.home") ?: "."))
        }
        if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) chosen = chooser.selectedFile
    }
    if (SwingUtilities.isEventDispatchThread()) show.run() else runCatching { SwingUtilities.invokeAndWait(show) }
    return chosen
}
