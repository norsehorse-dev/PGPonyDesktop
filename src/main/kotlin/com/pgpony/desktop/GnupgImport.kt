// GnupgImport.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5b (plan F3): import from GnuPG in one action.
//
// Reads a GnuPG home (Gpg4win's %APPDATA%\gnupg, GPG Suite's and Linux's ~/.gnupg, or
// $GNUPGHOME) and brings over its public keys, its trust, and, for the user's own GnuPG home
// when gpg is installed, its secret keys. PGPony never changes a key in GnuPG.
//
// gpg runs only against the user's own GnuPG home ($GNUPGHOME, else the platform default), and
// only after the user presses Continue: opening the dialog runs nothing. Any other folder the
// user picks is read with the built-in file parsers alone, so its configuration files are never
// acted on. When gpg runs it gets --no-options (gpg.conf is not read) and --agent-program set to
// the gpg-agent installed next to it, and any gpg-agent or keyboxd that PGPony had to start is
// stopped again when it is done, so no extra agent keeps passphrases cached.
//
// With gpg: `--export` for public keys, `--export-ownertrust` and the per-user-ID validity of
// `--list-keys` for trust, and `--export-secret-keys` one key at a time for secret keys, so gpg's
// own pinentry asks for each passphrase and the key arrives protected by it, as it was. Secret
// keys that live on a smartcard, or whose primary secret gpg holds only as a stub, are skipped.
//
// From files: public keys come from pubring.kbx (the keybox; each OpenPGP blob holds one
// keyblock) or the older pubring.gpg (a plain packet stream), and ownertrust from trustdb.gpg
// (40-byte records; a trust record carries a v4 fingerprint and the ownertrust byte).
//
// Trust mapping. GnuPG's ownertrust is how far you trust a key's owner to certify others;
// validity is whether a user ID is known to belong to the key, which is what PGPony's trust
// levels mean. PGPony's trust covers the whole key, so:
//   - Ultimate ownertrust (you said the key is yours) gives Ultimate when PGPony holds the
//     key's secret after the import, and Verified otherwise.
//   - Otherwise a key becomes Verified only when gpg calls EVERY one of its user IDs fully or
//     ultimately valid, and only when gpg's trust database is current.
//   - Full ownertrust alone gives nothing: it is about certifying others, not about this key.
//   - A key disabled in GnuPG gets no trust.
// Trust applies only to keys in the keyring being imported, is shown key by key before it is
// applied (each one can be unticked), and is never lowered.
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
import androidx.compose.foundation.layout.padding
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
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.FileDialog
import java.awt.Frame
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit
import javax.swing.JFileChooser
import javax.swing.SwingUtilities

object GnupgImport {

    /** An installed gpg: its path and the first line of `gpg --version` (empty until it has run). */
    data class Gpg(val path: Path, val version: String)

    /** A secret key gpg lists. [onCard]: on a smartcard; [stub]: gpg holds no primary secret. */
    data class SecretKey(val fingerprint: String, val userId: String, val onCard: Boolean, val stub: Boolean)

    /**
     * What a GnuPG home holds, as far as the files show, without running anything. [gpg] is set
     * only for the user's own GnuPG home ([isDefault]) outside a sandbox, and has not run yet.
     */
    data class Scan(
        val home: Path,
        val gpg: Gpg?,
        val publicKeys: Int,
        val secretKeys: List<SecretKey>,
        val sandboxed: Boolean,
        val isDefault: Boolean = false
    )

    /** One trust level PGPony will set (or did set) on a key. [from] is null for a key new to PGPony. */
    data class TrustChange(val fingerprint: String, val userId: String, val from: TrustLevel?, val to: TrustLevel)

    data class Result(
        val report: ImportReport,
        val trustSet: Int,
        val secretsImported: Int,
        val notes: List<String>,
        val trustChanges: List<TrustChange> = emptyList()
    )

    /** One key record from `gpg --with-colons` output. */
    data class ColonKey(
        val secret: Boolean,
        val fingerprint: String,
        val validity: Char?,
        val ownertrust: Char?,
        val serial: String,
        val userId: String,
        val userIds: List<String> = emptyList(),
        val uidValidity: List<Char?> = emptyList(),
        val disabled: Boolean = false
    )

    /** A key in the keyring being imported. [uidValidity] is per user ID, from gpg (empty without it). */
    data class HomeKey(
        val fingerprint: String,
        val userIds: List<String>,
        val uidValidity: List<Char?> = emptyList(),
        val disabled: Boolean = false
    ) {
        val userId: String get() = userIds.firstOrNull { it.isNotBlank() }.orEmpty()
    }

    /** Why a key that GnuPG trusts in some way gets no trust in PGPony. */
    enum class TrustSkip { DISABLED, NOT_ALL_UIDS_VALID }

    data class TrustDecision(val level: TrustLevel?, val skip: TrustSkip? = null)

    /** What [prepare] read from the home: the input to the trust preview and to [apply]. */
    data class Plan(
        val scan: Scan,
        val keys: List<HomeKey>,
        val ownertrust: Map<String, Int>,
        val validityUsable: Boolean,
        val secretKeys: List<SecretKey>,
        val notes: List<String>
    )

    // 3.0.0 (4d rules): bounds on what is read from GnuPG or gpg.
    private const val MAX_READ = 256L * 1024 * 1024
    private const val MAX_KEYBLOCKS = 1_000_000
    private const val ERR_TAIL = 64 * 1024
    private const val TRUST_RECORD = 40
    private const val RECTYPE_TRUST = 12
    private const val OWNERTRUST_MASK = 0x0F
    private const val OWNERTRUST_DISABLED = 0x80
    private const val OWNERTRUST_ULTIMATE = 6

    fun sandboxed(): Boolean = Flatpak.active

    private val isWindows = System.getProperty("os.name").orEmpty().lowercase().contains("win")

    /** Lets a test stand in for $GNUPGHOME, which a running JVM cannot change. */
    @Volatile
    internal var defaultHomeOverride: Path? = null

    /** $GNUPGHOME, else the platform's default GnuPG home. */
    fun defaultHome(): Path {
        defaultHomeOverride?.let { return it }
        System.getenv("GNUPGHOME")?.takeIf { it.isNotBlank() }?.let { return Path.of(it) }
        val home = System.getProperty("user.home") ?: "."
        return if (isWindows) Path.of(System.getenv("APPDATA") ?: home, "gnupg") else Path.of(home, ".gnupg")
    }

    /** True when [dir] is the user's own GnuPG home, the only one gpg is ever run against. */
    fun isDefaultHome(dir: Path): Boolean {
        val def = defaultHome()
        return runCatching { Files.isSameFile(dir, def) }
            .getOrElse { dir.toAbsolutePath().normalize() == def.toAbsolutePath().normalize() }
    }

    fun looksLikeHome(dir: Path): Boolean =
        Files.isRegularFile(dir.resolve("pubring.kbx")) || Files.isRegularFile(dir.resolve("pubring.gpg"))

    // ── Finding gpg ─────────────────────────────────────────────────────────

    /**
     * Where to look for gpg, in order: the fixed install locations first, then the absolute
     * entries of PATH. Relative and empty PATH entries are skipped.
     */
    internal fun gpgCandidates(windows: Boolean, path: String?, env: (String) -> String?, registryDirs: List<String> = emptyList()): List<Path> {
        val fixed = if (windows) {
            val roots = listOfNotNull(env("ProgramFiles(x86)"), env("ProgramFiles"), "C:\\Program Files (x86)", "C:\\Program Files")
            roots.map { "$it\\GnuPG\\bin\\gpg.exe" } + registryDirs.map { "${it.trimEnd('\\')}\\bin\\gpg.exe" }
        } else {
            listOf(
                "/usr/bin/gpg", "/usr/bin/gpg2",
                "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg",
                "/usr/local/MacGPG2/bin/gpg", "/usr/local/MacGPG2/bin/gpg2",
                "/opt/local/bin/gpg"
            )
        }
        val names = if (windows) listOf("gpg.exe") else listOf("gpg", "gpg2")
        val sep = if (windows) ';' else ':'
        val onPath = path.orEmpty().split(sep).map { it.trim().removeSurrounding("\"") }
            .filter { it.isNotEmpty() && isAbsolute(it, windows) }
            .flatMap { dir -> names.map { "${dir.trimEnd('/', '\\')}${if (windows) "\\" else "/"}$it" } }
        return (fixed + onPath).distinct().mapNotNull { runCatching { Path.of(it) }.getOrNull() }
    }

    private fun isAbsolute(p: String, windows: Boolean): Boolean =
        if (windows) Regex("^[A-Za-z]:[\\\\/].*").matches(p) || p.startsWith("\\\\") else p.startsWith("/")

    /** Gpg4win's "Install Directory" from the registry (HKLM, both views). Windows only. */
    private fun windowsRegistryDirs(): List<String> {
        val root = System.getenv("SystemRoot") ?: "C:\\Windows"
        val reg = Path.of(root, "System32", "reg.exe")
        if (!Files.isRegularFile(reg)) return emptyList()
        return listOf("HKLM\\SOFTWARE\\GnuPG", "HKLM\\SOFTWARE\\WOW6432Node\\GnuPG").mapNotNull { key ->
            runCatching { exec(listOf(reg.toString(), "query", key, "/v", "Install Directory"), 10) }.getOrNull()
                ?.toString(Charsets.UTF_8)?.lineSequence()
                ?.firstOrNull { it.contains("Install Directory") && it.contains("REG_") }
                ?.substringAfter("REG_")?.substringAfter(' ')?.trim()?.takeIf { it.isNotEmpty() }
        }
    }

    /** The registry is asked only on Windows, and only when no fixed install location has gpg. */
    private fun candidates(): List<Path> {
        val env = { name: String -> System.getenv(name) }
        val path = System.getenv("PATH")
        if (!isWindows || gpgCandidates(true, null, env).any { Files.isRegularFile(it) }) {
            return gpgCandidates(isWindows, path, env)
        }
        return gpgCandidates(true, path, env, windowsRegistryDirs())
    }

    /** The first gpg on disk, without running it; null when there is none, or in a sandbox. */
    fun locateGpg(): Gpg? {
        if (sandboxed()) return null
        return candidates().firstOrNull { Files.isRegularFile(it) && Files.isExecutable(it) }?.let { Gpg(it, "") }
    }

    /** Runs [g] with `--version`; the same gpg with its version line, or null when it is not gpg. */
    fun probe(g: Gpg): Gpg? {
        val version = runCatching { exec(listOf(g.path.toString(), "--version"), 10) }.getOrNull()
            ?.toString(Charsets.UTF_8)?.lineSequence()?.firstOrNull()?.trim() ?: return null
        return if (version.startsWith("gpg")) Gpg(g.path, version) else null
    }

    /** The first candidate that answers like gpg. This runs candidates: call it on a user action only. */
    fun findGpg(): Gpg? {
        if (sandboxed()) return null
        for (candidate in candidates()) {
            if (!Files.isRegularFile(candidate) || !Files.isExecutable(candidate)) continue
            probe(Gpg(candidate, ""))?.let { return it }
        }
        return null
    }

    // ── Pure parsers (tests drive these) ────────────────────────────────────

    /** Calls [block] with (offset, length) of each OpenPGP keyblock in a keybox file, in order. */
    private fun forEachKeyblock(kbx: ByteArray, cancelled: () -> Boolean, block: (Int, Int) -> Unit) {
        var off = 0
        var count = 0
        while (off + 16 <= kbx.size) {
            val len = SopPackets.be32(kbx, off)
            if (len < 16 || off.toLong() + len > kbx.size) break
            if (kbx[off + 4].toInt() == 2) {
                val kbOff = SopPackets.be32(kbx, off + 8)
                val kbLen = SopPackets.be32(kbx, off + 12)
                // The keyblock follows the blob's fixed header, so it never starts inside it.
                if (kbOff >= 16 && kbLen > 0 && kbOff.toLong() + kbLen <= len) {
                    if (++count > MAX_KEYBLOCKS) throw IllegalStateException(tr("d_gnupg_too_many_keys"))
                    if (count % 1024 == 0 && cancelled()) throw CancellationException()
                    block(off + kbOff, kbLen)
                }
            }
            off += len
        }
    }

    /** The OpenPGP keyblocks in a keybox file (pubring.kbx), in order. */
    fun keyboxKeyblocks(kbx: ByteArray, cancelled: () -> Boolean = { false }): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        forEachKeyblock(kbx, cancelled) { o, n -> out += kbx.copyOfRange(o, o + n) }
        return out
    }

    /** All keyblocks of a keybox file, one after the other, as one packet stream. */
    fun keyboxPacketStream(kbx: ByteArray, cancelled: () -> Boolean = { false }): ByteArray {
        val out = ByteArrayOutputStream()
        forEachKeyblock(kbx, cancelled) { o, n -> out.write(kbx, o, n) }
        return out.toByteArray()
    }

    /**
     * Ownertrust bytes by uppercase v4 fingerprint, from trustdb.gpg's trust records. The value
     * is the whole byte: the level is its low nibble ([ownertrustLevel]), and 0x80 marks a key
     * disabled in GnuPG ([ownertrustDisabled]).
     */
    fun trustdbOwnertrust(trustdb: ByteArray): Map<String, Int> {
        val out = mutableMapOf<String, Int>()
        var off = 0
        while (off + TRUST_RECORD <= trustdb.size) {
            if (trustdb[off].toInt() == RECTYPE_TRUST) {
                val fp = trustdb.copyOfRange(off + 2, off + 22)
                if (fp.any { it.toInt() != 0 }) {
                    out[fp.joinToString("") { "%02X".format(it) }] = trustdb[off + 22].toInt() and 0xFF
                }
            }
            off += TRUST_RECORD
        }
        return out
    }

    /** `gpg --export-ownertrust`: "FINGERPRINT:VALUE:" lines, comments start with '#'. Values as [trustdbOwnertrust]. */
    fun parseOwnertrustExport(text: String): Map<String, Int> =
        text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { line ->
                val parts = line.split(':')
                val fp = parts.getOrNull(0)?.uppercase()?.takeIf { f -> f.all { it in "0123456789ABCDEF" } && f.length >= 40 }
                val value = parts.getOrNull(1)?.toIntOrNull()
                if (fp != null && value != null) fp to (value and 0xFF) else null
            }.toMap()

    fun ownertrustLevel(value: Int?): Int? = value?.and(OWNERTRUST_MASK)
    fun ownertrustDisabled(value: Int?): Boolean = value != null && value and OWNERTRUST_DISABLED != 0

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
                    val validity = f.getOrNull(1)?.firstOrNull()
                    current = ColonKey(
                        secret = f[0] == "sec",
                        fingerprint = "",
                        validity = validity,
                        ownertrust = f.getOrNull(8)?.firstOrNull(),
                        serial = f.getOrNull(14).orEmpty(),
                        userId = "",
                        disabled = validity == 'd' || f.getOrNull(11).orEmpty().contains('D')
                    )
                    wantFpr = true
                }
                "fpr" -> if (wantFpr) {
                    current = current?.copy(fingerprint = f.getOrNull(9).orEmpty().uppercase())
                    wantFpr = false
                }
                "uid" -> current?.let { c ->
                    val uid = unescapeColon(f.getOrNull(9).orEmpty())
                    current = c.copy(
                        userId = c.userId.ifEmpty { uid },
                        userIds = c.userIds + uid,
                        uidValidity = c.uidValidity + f.getOrNull(1)?.firstOrNull()
                    )
                }
                "sub", "ssb" -> wantFpr = false
            }
        }
        flush()
        return out
    }

    /**
     * True when the validity in a `--with-colons --list-keys` listing cannot be relied on: no
     * trust database record, a database gpg itself would recheck first ('o', or a next check
     * time already past), or one built for another trust model ('t').
     */
    fun trustdbStale(listing: String, nowSeconds: Long = System.currentTimeMillis() / 1000): Boolean {
        val tru = listing.lineSequence().map { it.split(':') }.firstOrNull { it.firstOrNull() == "tru" } ?: return true
        val flags = tru.getOrNull(1).orEmpty()
        if ('o' in flags || 't' in flags) return true
        val nextCheck = tru.getOrNull(4)?.toLongOrNull() ?: 0L
        return nextCheck in 1..nowSeconds
    }

    private fun unescapeColon(s: String): String =
        Regex("\\\\x([0-9a-fA-F]{2})").replace(s) { it.groupValues[1].toInt(16).toChar().toString() }

    /** The primary keys in an OpenPGP packet stream, each with its fingerprint and user IDs. */
    fun keyringKeys(raw: ByteArray): List<HomeKey> {
        val out = mutableListOf<HomeKey>()
        var fp: String? = null
        var uids = mutableListOf<String>()
        fun flush() {
            fp?.let { out += HomeKey(it, uids.toList()) }
            fp = null
            uids = mutableListOf()
        }
        for ((tag, packet) in SopPackets.split(raw)) {
            when (tag) {
                6 -> {
                    flush()
                    fp = runCatching { primaryFingerprint(CompositeSigPacket.firstPacket(packet).second) }.getOrNull()
                }
                13 -> if (fp != null) {
                    runCatching { CompositeSigPacket.firstPacket(packet).second }.getOrNull()
                        ?.let { uids += String(it, Charsets.UTF_8) }
                }
            }
        }
        flush()
        return out
    }

    /** v4: SHA-1 over 0x99, a 2-byte length and the body; v5 and v6: SHA-256 with 0x9A / 0x9B and 4 bytes. */
    private fun primaryFingerprint(body: ByteArray): String? {
        val n = body.size
        val digest = when (body.firstOrNull()?.toInt()) {
            4 -> MessageDigest.getInstance("SHA-1").apply {
                update(0x99.toByte()); update((n shr 8).toByte()); update(n.toByte())
            }
            5, 6 -> MessageDigest.getInstance("SHA-256").apply {
                update(if (body[0].toInt() == 5) 0x9A.toByte() else 0x9B.toByte())
                update((n ushr 24).toByte()); update((n ushr 16).toByte()); update((n ushr 8).toByte()); update(n.toByte())
            }
            else -> return null
        }
        digest.update(body)
        return digest.digest().joinToString("") { "%02X".format(it) }
    }

    /**
     * The trust PGPony gives one key of the imported keyring. [ownertrust] is the raw ownertrust
     * value; [validityUsable] says whether [HomeKey.uidValidity] reflects a current trust
     * database; [hasSecret] whether PGPony holds the key's secret (or will, after the import).
     */
    fun decideTrust(key: HomeKey, ownertrust: Int?, validityUsable: Boolean, hasSecret: Boolean): TrustDecision {
        val level = ownertrustLevel(ownertrust)
        val validity = if (validityUsable) key.uidValidity else emptyList()
        val allValid = validity.isNotEmpty() && validity.size == key.userIds.size && validity.all { it == 'f' || it == 'u' }
        val someValid = validity.any { it == 'f' || it == 'u' }
        val wouldTrust = level == OWNERTRUST_ULTIMATE || someValid
        if (key.disabled || ownertrustDisabled(ownertrust)) {
            return TrustDecision(null, if (wouldTrust) TrustSkip.DISABLED else null)
        }
        return when {
            level == OWNERTRUST_ULTIMATE -> TrustDecision(if (hasSecret) TrustLevel.ULTIMATE else TrustLevel.VERIFIED)
            allValid -> TrustDecision(TrustLevel.VERIFIED)
            someValid -> TrustDecision(null, TrustSkip.NOT_ALL_UIDS_VALID)
            else -> TrustDecision(null)
        }
    }

    internal fun labelOf(userId: String, fingerprint: String): String =
        if (userId.isBlank()) fingerprint else "$userId (${fingerprint.takeLast(16)})"

    // ── Reading a home ──────────────────────────────────────────────────────

    private fun readCapped(p: Path): ByteArray? {
        if (!Files.isRegularFile(p)) return null
        if (Files.size(p) > MAX_READ) throw IllegalStateException("${p.fileName} is too large")
        return Files.readAllBytes(p)
    }

    /** Public keys straight from the files, as one packet stream. */
    fun readPublicKeys(home: Path, cancelled: () -> Boolean = { false }): ByteArray {
        readCapped(home.resolve("pubring.kbx"))?.let { kbx -> return keyboxPacketStream(kbx, cancelled) }
        return readCapped(home.resolve("pubring.gpg")) ?: ByteArray(0)
    }

    /** Reads [input] to its end: the first [cap] bytes, and whether there were more. */
    private fun readUpTo(input: InputStream, cap: Int): Pair<ByteArray, Boolean> {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        var over = false
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            val room = cap - out.size()
            if (n <= room) out.write(buf, 0, n) else { if (room > 0) out.write(buf, 0, room); over = true }
        }
        return out.toByteArray() to over
    }

    /** Reads [input] to its end and keeps only its last [keep] bytes. */
    private fun readTail(input: InputStream, keep: Int): ByteArray {
        val ring = ByteArray(keep)
        var total = 0L
        val buf = ByteArray(8 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            for (i in 0 until n) ring[((total + i) % keep).toInt()] = buf[i]
            total += n
        }
        if (total <= keep) return ring.copyOf(total.toInt())
        val start = (total % keep).toInt()
        return ring.copyOfRange(start, keep) + ring.copyOfRange(0, start)
    }

    /** Runs a command and returns its stdout; a nonzero exit throws with the end of stderr. */
    internal fun exec(command: List<String>, timeoutSeconds: Long): ByteArray {
        val p = ProcessBuilder(command).start()
        p.outputStream.close()
        var out = ByteArray(0)
        var overflow = false
        var err = ByteArray(0)
        val outReader = Thread { readUpTo(p.inputStream, MAX_READ.toInt()).let { out = it.first; overflow = it.second } }.apply { start() }
        val errReader = Thread { err = readTail(p.errorStream, ERR_TAIL) }.apply { start() }
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
        if (overflow) throw IllegalStateException("gpg wrote more than ${MAX_READ / (1024 * 1024)} MB")
        return out
    }

    /** The major version in a `gpg --version` first line ("gpg (GnuPG) 2.4.4" gives 2); null when unknown. */
    internal fun gpgMajor(version: String): Int? =
        Regex("""\)\s+(\d+)\.""").find(version)?.groupValues?.get(1)?.toIntOrNull()

    private fun sibling(g: Gpg, name: String): Path? {
        val p = (g.path.parent ?: return null).resolve(if (isWindows) "$name.exe" else name)
        return p.takeIf { Files.isRegularFile(it) && Files.isExecutable(it) }
    }

    /**
     * gpg runs against the user's own GnuPG home, one session per user action. It reads no
     * gpg.conf (--no-options), starts the gpg-agent installed next to it if it needs one, and
     * never rechecks or rewrites the trust database. Daemons that were not running when the
     * session opened (gpg-agent, and keyboxd for a home that uses it) are stopped on close.
     */
    private class GpgSession(val g: Gpg, val home: Path) : AutoCloseable {
        private val connect = sibling(g, "gpg-connect-agent")
        private val usesKeyboxd = Files.isDirectory(home.resolve("public-keys.d"))
        private val agentWasRunning = running(keyboxd = false)
        private val keyboxdWasRunning = if (usesKeyboxd) running(keyboxd = true) else null

        private fun connectArgs(keyboxd: Boolean, vararg commands: String): List<String>? =
            connect?.let {
                listOf(it.toString(), "--homedir", home.toString(), "--no-autostart") +
                    (if (keyboxd) listOf("--keyboxd") else emptyList()) + commands + "/bye"
            }

        /** True or false when gpg-connect-agent could tell; null when it could not. */
        private fun running(keyboxd: Boolean): Boolean? {
            val args = connectArgs(keyboxd, "GETINFO pid") ?: return null
            val out = runCatching { exec(args, 15) }.getOrNull() ?: return null
            return out.toString(Charsets.UTF_8).lineSequence().any { it.startsWith("D ") }
        }

        fun run(timeoutSeconds: Long, vararg args: String): ByteArray {
            val base = mutableListOf(
                g.path.toString(), "--homedir", home.toString(), "--no-options",
                "--batch", "--no-auto-check-trustdb", "--no-permission-warning"
            )
            // gpg 1.x has no --agent-program and refuses to start with it.
            if ((gpgMajor(g.version) ?: 2) >= 2) sibling(g, "gpg-agent")?.let { base += listOf("--agent-program", it.toString()) }
            return exec(base + args, timeoutSeconds)
        }

        override fun close() {
            // gpgconf --kill does not stop keyboxd in some 2.4 releases; the assuan commands do.
            if (agentWasRunning == false) connectArgs(false, "KILLAGENT")?.let { runCatching { exec(it, 15) } }
            if (keyboxdWasRunning == false) connectArgs(true, "KILLKEYBOXD")?.let { runCatching { exec(it, 15) } }
        }
    }

    /**
     * What a GnuPG home holds, read from its files alone: nothing is run. gpg is offered only for
     * the user's own GnuPG home; a [gpg] passed for any other folder is ignored.
     */
    fun scan(home: Path, gpg: Gpg? = null, cancelled: () -> Boolean = { false }): Scan {
        val isDefault = isDefaultHome(home)
        val usable = if (isDefault && !sandboxed()) (gpg ?: locateGpg()) else null
        val count = SopPackets.split(readPublicKeys(home, cancelled)).count { it.first == 6 }
        return Scan(home, usable, count, emptyList(), sandboxed(), isDefault)
    }

    /**
     * Reads what the import needs: the keyring's keys, ownertrust, per-user-ID validity and the
     * secret key list. This is where gpg first runs (the user's own home only).
     */
    fun prepare(scan: Scan, cancelled: () -> Boolean = { false }): Plan {
        val notes = mutableListOf<String>()
        val located = scan.gpg?.takeIf { scan.isDefault && isDefaultHome(scan.home) && !sandboxed() }
        val g = located?.let { l -> l.takeIf { it.version.isNotEmpty() } ?: probe(l) ?: findGpg() }
        if (located != null && g == null) notes += tr("d_gnupg_gpg_not_working", located.path.toString())

        if (g == null) {
            val keys = keyringKeys(readPublicKeys(scan.home, cancelled))
            val ownertrust = readCapped(scan.home.resolve("trustdb.gpg"))?.let { trustdbOwnertrust(it) }.orEmpty()
            val plan = Plan(scan.copy(gpg = null), keys, ownertrust, validityUsable = false, secretKeys = emptyList(), notes = notes)
            return plan.copy(notes = notes + skipNotes(plan))
        }

        GpgSession(g, scan.home).use { s ->
            val listing = String(s.run(60, "--with-colons", "--with-fingerprint", "--list-keys"), Charsets.UTF_8)
            if (cancelled()) throw CancellationException()
            val pub = parseColons(listing)
            val sec = parseColons(String(s.run(60, "--with-colons", "--with-fingerprint", "--list-secret-keys"), Charsets.UTF_8))
            val ownertrust = parseOwnertrustExport(String(s.run(60, "--export-ownertrust"), Charsets.UTF_8))
            val stale = trustdbStale(listing)
            if (stale && pub.any { k -> k.uidValidity.any { it == 'f' || it == 'u' } }) notes += tr("d_gnupg_note_stale")
            val keys = pub.map { HomeKey(it.fingerprint, it.userIds, it.uidValidity, it.disabled) }
            val secrets = sec.map { k ->
                SecretKey(k.fingerprint, k.userId, onCard = k.serial.isNotEmpty() && k.serial != "+" && k.serial != "#", stub = k.serial == "#")
            }
            val plan = Plan(scan.copy(gpg = g, publicKeys = keys.size, secretKeys = secrets), keys, ownertrust, !stale, secrets, notes)
            return plan.copy(notes = notes + skipNotes(plan))
        }
    }

    /** A note for each key that GnuPG trusts but that gets no trust here, and why. */
    private fun skipNotes(plan: Plan): List<String> = plan.keys.mapNotNull { k ->
        val label = labelOf(k.userId, k.fingerprint)
        when (decideTrust(k, plan.ownertrust[k.fingerprint], plan.validityUsable, hasSecret = false).skip) {
            TrustSkip.DISABLED -> tr("d_gnupg_note_disabled", label)
            TrustSkip.NOT_ALL_UIDS_VALID -> tr("d_gnupg_note_uids", label)
            null -> null
        }
    }

    private fun holdsSecret(e: com.pgpony.android.data.PGPKeyEntity?): Boolean = e != null && (e.isKeyPair || e.isCardBacked)

    /**
     * The trust changes [apply] would make with these options, key by key, for the user to
     * review. Ultimate is predicted from secrets PGPony holds or will import.
     */
    suspend fun trustPreview(repo: DesktopKeyRepository, plan: Plan, withSecrets: Boolean): List<TrustChange> {
        val incoming = if (withSecrets && plan.scan.gpg != null) {
            plan.secretKeys.filter { !it.onCard && !it.stub }.map { it.fingerprint.uppercase() }.toSet()
        } else emptySet()
        val out = mutableListOf<TrustChange>()
        for (k in plan.keys) {
            val e = repo.byFingerprint(k.fingerprint)
            val hasSecret = holdsSecret(e) || k.fingerprint.uppercase() in incoming
            val level = decideTrust(k, plan.ownertrust[k.fingerprint], plan.validityUsable, hasSecret).level ?: continue
            if (e != null && level.ordinal <= e.trustLevel.ordinal) continue
            out += TrustChange(k.fingerprint, k.userId, e?.trustLevel, level)
        }
        return out
    }

    /**
     * Import what [prepare] found. Trust goes only to keys of this keyring, only to those in
     * [selected] (all when null), and only ever up; Ultimate needs the secret in PGPony.
     */
    suspend fun apply(
        repo: DesktopKeyRepository,
        plan: Plan,
        withTrust: Boolean,
        withSecrets: Boolean,
        selected: Set<String>? = null,
        cancelled: () -> Boolean = { false }
    ): Result {
        val g = plan.scan.gpg?.takeIf { isDefaultHome(plan.scan.home) && !sandboxed() }
        val notes = plan.notes.toMutableList()
        val session = g?.let { GpgSession(it, plan.scan.home) }
        var report = ImportReport(0, 0, 0, 0)
        var secretsImported = 0
        try {
            val publicBytes = if (session != null) session.run(120, "--export") else readPublicKeys(plan.scan.home, cancelled)
            report = if (publicBytes.isEmpty()) ImportReport(0, 0, 0, 0) else repo.importBytes(publicBytes)

            if (withSecrets && session != null) {
                for (s in plan.secretKeys) {
                    if (cancelled()) throw CancellationException()
                    val label = labelOf(s.userId, s.fingerprint)
                    when {
                        s.onCard -> notes += tr("d_gnupg_card_skipped", label)
                        s.stub -> notes += tr("d_gnupg_stub_skipped", label)
                        else -> try {
                            // One key per call, so gpg's pinentry names the key it is asking about.
                            val bytes = session.run(300, "--export-secret-keys", s.fingerprint)
                            val r = repo.importBytes(bytes)
                            if (r.failed == 0 && r.total > 0) secretsImported++ else notes += tr("d_gnupg_secret_not_imported", label)
                            report = report.plus(r)
                        } catch (e: Exception) {
                            notes += tr("d_gnupg_secret_failed", label, e.message.orEmpty())
                        }
                    }
                }
            }
        } finally {
            session?.close()
        }

        val changes = mutableListOf<TrustChange>()
        if (withTrust) {
            val wanted = selected?.map { it.uppercase() }?.toSet()
            for (k in plan.keys) {
                if (wanted != null && k.fingerprint.uppercase() !in wanted) continue
                val e = repo.byFingerprint(k.fingerprint) ?: continue
                val level = decideTrust(k, plan.ownertrust[k.fingerprint], plan.validityUsable, holdsSecret(e)).level ?: continue
                if (level.ordinal > e.trustLevel.ordinal) {
                    repo.updateTrustLevel(e.fingerprint, level)
                    changes += TrustChange(e.fingerprint, k.userId, e.trustLevel, level)
                }
            }
        }
        return Result(report, changes.size, secretsImported, notes, changes)
    }

    /** Prepare and apply in one go, with every trust change: what the command line does. */
    suspend fun import(repo: DesktopKeyRepository, scan: Scan, withTrust: Boolean, withSecrets: Boolean): Result =
        apply(repo, prepare(scan), withTrust, withSecrets)

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
    var plan by remember { mutableStateOf<GnupgImport.Plan?>(null) }
    var preview by remember { mutableStateOf<List<GnupgImport.TrustChange>>(emptyList()) }
    var unticked by remember { mutableStateOf<Set<String>>(emptySet()) }
    var scanError by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(true) }
    var withTrust by remember { mutableStateOf(true) }
    var withSecrets by remember { mutableStateOf(true) }
    var working by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<GnupgImport.Result?>(null) }
    var pickFolder by remember { mutableStateOf(false) }
    val sandboxed = remember { GnupgImport.sandboxed() }

    // Opening the dialog or picking a folder reads files only. A folder without gpg goes straight
    // to the review, since that runs nothing either; the user's own home waits for Continue.
    LaunchedEffect(home) {
        scanning = true
        scanError = null
        scan = null
        plan = null
        unticked = emptySet()
        val (s, p, err) = withContext(Dispatchers.IO) {
            val cancelled = { !isActive }
            if (!GnupgImport.looksLikeHome(home)) Triple(null, null, null)
            else runCatching {
                val sc = GnupgImport.scan(home, cancelled = cancelled)
                Triple(sc, if (sc.gpg == null) GnupgImport.prepare(sc, cancelled) else null, null as String?)
            }.getOrElse { Triple(null, null, it.message ?: it.javaClass.simpleName) }
        }
        scan = s
        plan = p
        withTrust = s?.isDefault == true
        scanError = err
        scanning = false
    }

    LaunchedEffect(plan, withSecrets) {
        val p = plan
        preview = if (p == null) emptyList() else withContext(Dispatchers.IO) {
            runCatching { GnupgImport.trustPreview(state.repository, p, withSecrets) }.getOrDefault(emptyList())
        }
    }

    fun runPrepare() {
        val s = scan ?: return
        working = true
        scope.launch {
            try {
                plan = withContext(Dispatchers.IO) { GnupgImport.prepare(s) }
            } catch (e: Exception) {
                scanError = e.message ?: e.javaClass.simpleName
            } finally {
                working = false
            }
        }
    }

    fun runImport() {
        val p = plan ?: return
        val selected = preview.map { it.fingerprint }.filter { it !in unticked }.toSet()
        working = true
        scope.launch {
            try {
                result = withContext(Dispatchers.IO) {
                    GnupgImport.apply(state.repository, p, withTrust, withSecrets && p.scan.gpg != null, selected)
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
                    done.trustChanges.forEach { c ->
                        Spacer(Modifier.height(4.dp))
                        Text(trustLine(c), style = MaterialTheme.typography.bodySmall)
                    }
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
                val p = plan
                when {
                    scanning -> Text(tr("d_common_working"), style = MaterialTheme.typography.bodyMedium)
                    scanError != null -> Text(scanError!!, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                    s == null -> Text(tr("d_gnupg_no_home"), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                    else -> {
                        val shown = p?.scan ?: s
                        Text(
                            if (p != null && shown.gpg != null) tr("d_gnupg_counts", shown.publicKeys, shown.secretKeys.size)
                            else tr("d_gnupg_counts_public", shown.publicKeys),
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            when {
                                shown.gpg != null -> tr("d_gnupg_gpg_found", shown.gpg.version.ifEmpty { shown.gpg.path.toString() })
                                sandboxed -> tr("d_gnupg_sandboxed")
                                !s.isDefault -> tr("d_gnupg_other_folder")
                                else -> tr("d_gnupg_gpg_missing")
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        if (p == null) {
                            Spacer(Modifier.height(4.dp))
                            Text(tr("d_gnupg_continue_hint"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        } else {
                            Spacer(Modifier.height(8.dp))
                            if (p.scan.gpg != null && p.secretKeys.isNotEmpty()) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Checkbox(checked = withSecrets, onCheckedChange = { withSecrets = it }, enabled = !working)
                                    Text(tr("d_gnupg_opt_secret"), style = MaterialTheme.typography.bodyMedium)
                                }
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = withTrust, onCheckedChange = { withTrust = it }, enabled = !working)
                                Text(tr("d_gnupg_opt_trust"), style = MaterialTheme.typography.bodyMedium)
                            }
                            if (withTrust) {
                                Spacer(Modifier.height(4.dp))
                                Text(tr("d_gnupg_trust_title"), style = MaterialTheme.typography.labelLarge)
                                if (preview.isEmpty()) {
                                    Text(tr("d_gnupg_trust_none"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                preview.forEach { c ->
                                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 8.dp)) {
                                        Checkbox(
                                            checked = c.fingerprint !in unticked,
                                            onCheckedChange = { on -> unticked = if (on) unticked - c.fingerprint else unticked + c.fingerprint },
                                            enabled = !working
                                        )
                                        Text(trustLine(c), style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                            }
                            p.notes.forEach {
                                Spacer(Modifier.height(4.dp))
                                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text(tr("d_gnupg_readonly_note_v2"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
        confirmButton = {
            if (result == null) {
                if (plan == null) {
                    TextButton(enabled = scan != null && !working && !scanning, onClick = { runPrepare() }) {
                        Text(if (working) tr("d_common_working") else tr("d_gnupg_continue"))
                    }
                } else {
                    TextButton(enabled = !working && !scanning, onClick = { runImport() }) {
                        Text(if (working) tr("d_common_working") else tr("d_gnupg_import"))
                    }
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

private fun trustLine(c: GnupgImport.TrustChange): String =
    tr("d_gnupg_trust_item", c.userId.ifBlank { c.fingerprint }, c.fingerprint.takeLast(16), trustName(c.to))

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
