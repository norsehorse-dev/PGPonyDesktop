// DesktopPassStore.kt
// PGPony Desktop — D8: read-only `pass` (password-store) access over java.nio. This is the
// DESKTOP-NATIVE REPLACEMENT for the vendored crypto/pass/PassStoreService.kt (excluded: it is
// built on the Storage Access Framework — Context, Uri, DocumentFile), the same relationship
// PcscCardTransport has to the Android NFC transport. The *models* (PassStoreRef, PassNode,
// PassField, PassEntryContent) and the *parser* (PassEntryParser) are vendored VERBATIM and
// compile untouched, so the entry format and the tree shape are shared with Android by
// construction.
//
// A pass store is just a directory tree of `*.gpg` files — no SAF gymnastics on a desktop:
// ~/.password-store (or $PASSWORD_STORE_DIR, or any folder the user picks) is a plain path we
// read with Files. The tree is walked from FILENAMES ONLY; entries are decrypted lazily, one at
// a time, never in bulk.
//
// Behavior is deliberately identical to the Android walk: names starting with "." are skipped
// (that covers .git, .gpg-id, .gpg-id.sig, editor swap files), `*.gpg` becomes an Entry with the
// extension dropped, folders sort before entries, each group case-insensitively by name.
//
// Two things the SAF version could not have and this one must:
//   * PATH-TRAVERSAL HARDENING. A relativePath here becomes a filesystem path, so "../../.ssh/
//     id_rsa" would escape the store. Every segment is validated and the resolved leaf must
//     still live under the root. Symlinks are NOT resolved away — a pass store that symlinks a
//     shared folder in is a normal setup and keeps working; only the *path we build* is checked.
//   * A SYMLINK DEPTH CAP on the walk, so a folder symlinked to its own ancestor can't spin.

package com.pgpony.desktop

import com.pgpony.android.crypto.pass.PassNode
import com.pgpony.android.crypto.pass.PassStoreRef
import java.net.URI
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.util.UUID
import java.util.prefs.Preferences

/**
 * D8 settings. `pass_store_enabled` is the SAME key and the SAME default (false) as Android:
 * the password-store surface is opt-in there, and a feature that reaches into a folder full of
 * secrets shouldn't appear in the navigation rail until asked for.
 */
object DesktopPassSettings {

    const val KEY_ENABLED = "pass_store_enabled"

    /** Test hook — same pattern as DesktopProxyPrefs / DesktopNetworkPrefs. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun enabled(): Boolean = prefs().getBoolean(KEY_ENABLED, false)
    fun setEnabled(value: Boolean) = prefs().putBoolean(KEY_ENABLED, value)
}

object DesktopPassStore {

    /** How deep the tree walk will recurse before giving up (symlink-loop guard). */
    private const val MAX_DEPTH = 24

    // ── Locating a store ────────────────────────────────────────────────

    /**
     * The conventional store location: $PASSWORD_STORE_DIR when set (the variable the `pass`
     * CLI itself honors), else ~/.password-store. Returned whether or not it exists — the
     * caller decides how to present a missing default.
     */
    fun defaultStorePath(): Path {
        val env = System.getenv("PASSWORD_STORE_DIR")?.trim().orEmpty()
        if (env.isNotEmpty()) return runCatching { Paths.get(env) }.getOrElse { homeStore() }
        return homeStore()
    }

    private fun homeStore(): Path =
        Paths.get(System.getProperty("user.home") ?: ".").resolve(".password-store")

    /** Does [path] look like a pass store (a directory, ideally with a .gpg-id)? */
    fun looksLikeStore(path: Path): Boolean =
        Files.isDirectory(path) && Files.isReadable(path)

    /**
     * Build a store reference from a picked directory, reading the root `.gpg-id`. The display
     * name is the folder name, except for the conventional dot-folder (~/.password-store), which
     * would otherwise show as ".password-store".
     */
    fun buildRef(dir: Path): PassStoreRef {
        val name = dir.fileName?.toString()?.takeIf { it.isNotBlank() && !it.startsWith(".") }
            ?: "Password Store"
        return PassStoreRef(
            id = UUID.randomUUID().toString(),
            displayName = name,
            treeUri = dir.toAbsolutePath().normalize().toUri().toString(),
            rootGpgIds = readGpgId(dir)
        )
    }

    /**
     * Resolve a ref back to a live directory; null when the folder is gone, unreadable, or the
     * stored location no longer parses. [PassStoreRef.treeUri] holds a `file:` URI (the field is
     * named for the Android SAF tree URI it shares the JSON slot with), but a plain path is
     * accepted too so a hand-edited prefs blob still works.
     */
    fun resolveRoot(ref: PassStoreRef): Path? {
        val path = pathOf(ref.treeUri) ?: return null
        return if (Files.isDirectory(path) && Files.isReadable(path)) path else null
    }

    /** The stored location as a Path, whether it was written as a file: URI or a bare path. */
    fun pathOf(treeUri: String): Path? {
        val direct = runCatching { Paths.get(URI.create(treeUri)) }.getOrNull()
        if (direct != null) return direct
        return runCatching { Paths.get(treeUri) }.getOrNull()
    }

    // ── Walking the tree ────────────────────────────────────────────────

    /**
     * Walk the store into a [PassNode.Folder] built from filenames only (no decryption).
     * Null when the root can't be resolved.
     */
    fun walkTree(ref: PassStoreRef): PassNode.Folder? {
        val root = resolveRoot(ref) ?: return null
        return PassNode.Folder(
            folderName = ref.displayName,
            path = "",
            children = walkChildren(root, "", 0)
        )
    }

    private fun walkChildren(dir: Path, prefix: String, depth: Int): List<PassNode> {
        if (depth >= MAX_DEPTH) return emptyList()
        val folders = mutableListOf<PassNode.Folder>()
        val entries = mutableListOf<PassNode.Entry>()

        val children = try {
            Files.newDirectoryStream(dir).use { it.toList() }
        } catch (_: Exception) {
            return emptyList()   // unreadable folder — skip it, don't fail the whole walk
        }

        for (child in children) {
            val childName = child.fileName?.toString() ?: continue
            if (childName.startsWith(".")) continue          // dotfiles + .git + .gpg-id*
            when {
                Files.isDirectory(child) -> {
                    val childPath = if (prefix.isEmpty()) childName else "$prefix/$childName"
                    folders.add(
                        PassNode.Folder(
                            folderName = childName,
                            path = childPath,
                            children = walkChildren(child, childPath, depth + 1)
                        )
                    )
                }
                childName.endsWith(".gpg", ignoreCase = true) && Files.isRegularFile(child) -> {
                    val entryName = childName.dropLast(4)    // strip ".gpg"
                    val rel = if (prefix.isEmpty()) entryName else "$prefix/$entryName"
                    entries.add(PassNode.Entry(entryName = entryName, relativePath = rel))
                }
            }
        }

        folders.sortBy { it.folderName.lowercase() }
        entries.sortBy { it.entryName.lowercase() }
        return folders + entries
    }

    /** Every entry in the tree, depth-first in display order — the search corpus. */
    fun flatten(node: PassNode): List<PassNode.Entry> = when (node) {
        is PassNode.Entry -> listOf(node)
        is PassNode.Folder -> node.children.flatMap { flatten(it) }
    }

    /**
     * Filename search over the flattened tree: every space-separated term must appear somewhere
     * in the entry's relative path, case-insensitively. Matches the "fuzzy enough" feel of
     * `pass find` without pulling in a matcher.
     */
    fun search(root: PassNode.Folder, query: String): List<PassNode.Entry> {
        val terms = query.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (terms.isEmpty()) return emptyList()
        return flatten(root).filter { e ->
            val hay = e.relativePath.lowercase()
            terms.all { hay.contains(it) }
        }
    }

    /** The folder at [path] ("" = root) within an already-walked tree. */
    fun folderAt(root: PassNode.Folder, path: String): PassNode.Folder? {
        if (path.isEmpty()) return root
        var current = root
        for (segment in path.split("/")) {
            current = current.children
                .filterIsInstance<PassNode.Folder>()
                .firstOrNull { it.folderName == segment } ?: return null
        }
        return current
    }

    // ── Reading ─────────────────────────────────────────────────────────

    /**
     * Recipient ids from a `.gpg-id` in [dir] — one id per non-empty line. Informational in
     * read-only mode; load-bearing if writing ever lands.
     */
    fun readGpgId(dir: Path): List<String> {
        val file = dir.resolve(".gpg-id")
        if (!Files.isRegularFile(file)) return emptyList()
        return try {
            Files.readAllBytes(file).toString(Charsets.UTF_8)
                .split("\n", "\r\n", "\r")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * The raw bytes of an entry leaf (`<relativePath>.gpg`), or null if it is missing,
     * unreadable, or the path tries to escape the store.
     *
     * Traversal defence: each segment must be a plain name (no "", ".", "..", no separator, no
     * NUL), and the assembled path — normalized but with symlinks left intact — must still start
     * with the root. Both halves matter: the segment check stops "..", and the startsWith check
     * catches anything platform-specific that slips past it (Windows "C:" drive-relative forms,
     * for one).
     */
    fun readEntryBytes(ref: PassStoreRef, relativePath: String): ByteArray? {
        val root = resolveRoot(ref) ?: return null
        val leaf = resolveLeaf(root, relativePath) ?: return null
        return try {
            if (Files.isRegularFile(leaf)) Files.readAllBytes(leaf) else null
        } catch (_: Exception) {
            null
        }
    }

    /** Visible for tests: the traversal-checked leaf path, or null if the path is unsafe. */
    internal fun resolveLeaf(root: Path, relativePath: String): Path? {
        val segments = relativePath.split("/")
        if (segments.isEmpty() || segments.any { !isSafeSegment(it) }) return null

        return try {
            val base = root.toAbsolutePath().normalize()
            var current = base
            for (i in 0 until segments.size - 1) {
                current = current.resolve(segments[i])
            }
            val leaf = current.resolve(segments.last() + ".gpg").normalize()
            // normalize() only collapses lexical "..", which isSafeSegment already refused; this
            // is the belt to that suspenders — it also catches anything platform-specific that
            // resolve() turns into an absolute path (a Windows "C:" drive-relative form, say).
            // Symlinks are intentionally NOT resolved: a store that symlinks in a shared
            // subfolder is a legitimate setup and must keep working.
            if (leaf.startsWith(base)) leaf else null
        } catch (_: Exception) {
            null    // InvalidPathException on a segment this platform can't represent
        }
    }

    // Entry names may contain spaces, colons, unicode — whatever the filesystem allows. Only the
    // characters that would change the SHAPE of the resolved path are refused.
    private fun isSafeSegment(s: String): Boolean =
        s.isNotEmpty() && s != "." && s != ".." &&
            s.none { it == '/' || it == '\\' || it == '\u0000' }

    /**
     * The nearest `.gpg-id` recipients for an entry path — the entry's own folder, walking up to
     * the root — falling back to the ref's root ids. Shown in the detail pane so the user can
     * see who an entry is encrypted to without decrypting it.
     */
    fun recipientsForEntry(ref: PassStoreRef, relativePath: String): List<String> {
        val root = resolveRoot(ref) ?: return ref.rootGpgIds
        val segments = relativePath.split("/").dropLast(1)
        if (segments.any { !isSafeSegment(it) }) return ref.rootGpgIds

        val base = root.toAbsolutePath().normalize()
        var dir = base
        val chain = mutableListOf(base)
        for (seg in segments) {
            val next = dir.resolve(seg)
            if (!Files.isDirectory(next, LinkOption.NOFOLLOW_LINKS) && !Files.isDirectory(next)) break
            dir = next
            chain.add(dir)
        }
        for (d in chain.asReversed()) {
            val ids = readGpgId(d)
            if (ids.isNotEmpty()) return ids
        }
        return ref.rootGpgIds
    }
}
