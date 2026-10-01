// TarStreamer.kt
// PGPony Desktop — D16 (2.0.0 §3a): the folder-encryption tar leg.
//
// Encrypting a dropped FOLDER used to be an error. This makes it a tarball step on the existing
// streaming encrypt: walk → tar → encryptStream, one <folder>.tar.gpg out; on decrypt, a
// plaintext that is a tarball extracts to a sibling folder. This file is only the tar half;
// FileCryptoOps owns the crypto.
//
// WHY NOT the vendored UstarArchive. The backup codec (vendor/app-backup) is byte-in/byte-out,
// regular-files-only, names ≤100 — right for a keyring backup, wrong here: a folder needs
// directories, names past 100 bytes, and STREAMING so a 10 GB tree never lands in the heap
// (the 3b honesty rule starts here). And it is vendored — fixed upstream, never edited. So this
// is a second, desktop-owned codec, same trade the plan made for the plural table: a
// hand-written ~200-line ustar over Commons Compress, with `gpgtar` interop as the acceptance
// bar (gpgtar -d on our output; our extract on gpgtar's).
//
// FORMAT. POSIX ustar (magic "ustar\0", version "00") for regular files (typeflag '0') and
// directories ('5'). Names over 100 bytes use the GNU long-name extension: an 'L' typeflag
// entry named "././@LongLink" whose body is the real path, immediately followed by the real
// header (its own name field truncated). GNU tar and gpgtar both read this; it is the one
// extension worth carrying because deep folder paths blow past 100 bytes constantly.
//
// SECURITY. Extraction is a parser facing hostile input, so the reader is dumb and the writer
// of files is paranoid: every member path is rejected if absolute, if any component is "..",
// or if its normalized destination escapes the target root (the zip-slip shape). Symlink and
// hardlink members ('1','2') and every other exotic typeflag are skipped, never materialized —
// a tarball cannot plant a link that later redirects a write. mtime is fixed to 0 on write for
// deterministic output; the reader ignores it.
//
// 3.0.0: the writer walks the folder through directory handles (SecureDirectoryStream, where
// the platform has it), so a folder swapped for a link while the archive is being written is
// never followed, and copies exactly the size it declared, failing if a file grew or shrank on
// the way. A member of 8 GiB or more gets the GNU base-256 size encoding (GNU tar, bsdtar and
// gpgtar read it) instead of an octal field that cannot hold it. The reader checks each
// header's checksum, reads base-256 sizes and the PAX "path" and "size" records, and creates
// what it extracts readable by the owner only.

package com.pgpony.desktop

import java.io.BufferedOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.channels.Channels
import java.nio.channels.SeekableByteChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.SecureDirectoryStream
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.BasicFileAttributes

object TarStreamer {

    private const val BLOCK = 512
    private const val NAME_LEN = 100
    private const val LONGLINK = "././@LongLink"

    // Typeflags we write and/or read.
    private const val TYPE_FILE = '0'.code.toByte()
    private const val TYPE_DIR = '5'.code.toByte()
    private const val TYPE_LONGNAME = 'L'.code.toByte()
    private const val TYPE_PAX = 'x'.code.toByte()
    private const val TYPE_PAX_GLOBAL = 'g'.code.toByte()

    /** The largest size an 11-digit octal field holds (8 GiB - 1). */
    internal const val MAX_OCTAL_SIZE = 0x1_FFFF_FFFFL

    /** Counts, for a human summary after archiving. */
    data class Summary(val files: Int, val dirs: Int, val bytes: Long)

    /** A file or folder changed between being listed and being read. The archive is abandoned. */
    class ChangedWhileArchivingException(name: String) :
        IOException("changed while the folder was being archived: $name")

    private class Counts {
        var files = 0
        var dirs = 0
        var bytes = 0L
    }

    // ── Write ────────────────────────────────────────────────────────────────

    /**
     * Stream [root]'s tree into [out] as an uncompressed ustar archive, then two zero blocks.
     * Paths inside the archive are relative to [root]'s PARENT, so the top folder name is the
     * archive's single root entry (untar drops the folder back, not its loose contents). File
     * bodies are copied in 64 KiB chunks — nothing is fully buffered. Deterministic order
     * (sorted by name within each folder, a folder before its contents), so the same tree
     * tars to comparable bytes run to run. Links inside the folder are never archived or
     * followed.
     */
    fun archive(root: Path, out: OutputStream): Summary {
        require(Files.isDirectory(root)) { "not a folder: $root" }
        val named = root.toAbsolutePath().normalize()
        val top = named.fileName?.toString()
            ?: throw IllegalArgumentException("cannot archive a filesystem root")
        // The folder the user picked, through any link they picked it by; below it nothing is
        // followed.
        val real = named.toRealPath()
        val counts = Counts()
        val stream = Files.newDirectoryStream(real)
        if (stream is SecureDirectoryStream<Path>) {
            stream.use { archiveSecure(it, top, out, counts) }
        } else {
            stream.close()
            archiveByPath(real, top, out, counts)
        }
        out.write(ByteArray(BLOCK * 2))
        return Summary(counts.files, counts.dirs, counts.bytes)
    }

    /**
     * Walk [dir] through its open handle: every child is examined, opened and descended into
     * relative to the folder that was listed, without following links, so swapping a folder
     * for a link after it was listed cannot redirect a read.
     */
    private fun archiveSecure(dir: SecureDirectoryStream<Path>, rel: String, out: OutputStream, c: Counts) {
        writeHeader(out, "$rel/", 0L, TYPE_DIR)
        c.dirs++
        val names = ArrayList<Path>()
        for (entry in dir) names.add(entry.fileName)
        names.sortBy { it.toString() }
        for (name in names) {
            val member = "$rel/$name"
            val attrs = try {
                dir.getFileAttributeView(name, BasicFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
                    .readAttributes()
            } catch (_: java.nio.file.NoSuchFileException) {
                continue // removed since the listing: nothing to archive
            }
            when {
                attrs.isSymbolicLink -> continue // never archive a link's target blindly
                attrs.isDirectory -> {
                    val sub = try {
                        dir.newDirectoryStream(name, LinkOption.NOFOLLOW_LINKS)
                    } catch (e: IOException) {
                        throw ChangedWhileArchivingException(member)
                    }
                    sub.use {
                        val opened = it.getFileAttributeView(BasicFileAttributeView::class.java).readAttributes()
                        if (!opened.isDirectory || !sameFile(opened, attrs)) throw ChangedWhileArchivingException(member)
                        archiveSecure(it, member, out, c)
                    }
                }
                attrs.isRegularFile -> {
                    val ch = try {
                        dir.newByteChannel(name, readNoFollow())
                    } catch (e: IOException) {
                        throw ChangedWhileArchivingException(member)
                    }
                    ch.use { writeFile(out, member, attrs.size(), it, c) }
                }
                // sockets, fifos, devices: skip.
            }
        }
    }

    /**
     * The same walk by path, for platforms without directory handles (Windows). Each folder
     * must still resolve to where it was listed, and each file is opened without following a
     * link and must still be the file that was listed.
     */
    private fun archiveByPath(dirReal: Path, rel: String, out: OutputStream, c: Counts) {
        writeHeader(out, "$rel/", 0L, TYPE_DIR)
        c.dirs++
        val names = Files.newDirectoryStream(dirReal).use { s -> s.map { it.fileName.toString() } }.sorted()
        for (name in names) {
            val member = "$rel/$name"
            val path = dirReal.resolve(name)
            val attrs = try {
                Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (_: java.nio.file.NoSuchFileException) {
                continue
            }
            when {
                // A link, or a Windows junction (a directory that is also a reparse point), is
                // skipped like a link: never followed, never archived.
                attrs.isSymbolicLink || attrs.isOther -> continue
                attrs.isDirectory -> {
                    if (path.toRealPath() != path) throw ChangedWhileArchivingException(member)
                    archiveByPath(path, member, out, c)
                }
                attrs.isRegularFile -> {
                    val ch = Files.newByteChannel(path, readNoFollow())
                    ch.use {
                        val now = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                        if (!now.isRegularFile || !sameFile(now, attrs) || path.parent.toRealPath() != dirReal) {
                            throw ChangedWhileArchivingException(member)
                        }
                        writeFile(out, member, attrs.size(), it, c)
                    }
                }
            }
        }
    }

    private fun readNoFollow(): Set<OpenOption> = setOf(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)

    /** Same file system object: the file key where the platform has one, else creation time. */
    private fun sameFile(a: BasicFileAttributes, b: BasicFileAttributes): Boolean {
        val ka = a.fileKey()
        val kb = b.fileKey()
        return if (ka != null && kb != null) ka == kb else a.creationTime() == b.creationTime()
    }

    /**
     * One regular file: its header, then exactly [size] bytes from [ch], then padding. A file
     * that ends early or still has bytes after [size] changed while it was read, and would
     * make the next header land in the wrong place, so the archive is abandoned.
     */
    private fun writeFile(out: OutputStream, name: String, size: Long, ch: SeekableByteChannel, c: Counts) {
        writeHeader(out, name, size, TYPE_FILE)
        val input = Channels.newInputStream(ch)
        val buf = ByteArray(64 * 1024)
        var remaining = size
        while (remaining > 0) {
            val n = input.read(buf, 0, minOf(remaining, buf.size.toLong()).toInt())
            if (n < 0) throw ChangedWhileArchivingException(name)
            out.write(buf, 0, n)
            remaining -= n
        }
        if (input.read() >= 0) throw ChangedWhileArchivingException(name)
        padTo(out, size)
        c.files++
        c.bytes += size
    }

    private fun writeHeader(out: OutputStream, name: String, size: Long, typeflag: Byte) {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        if (nameBytes.size > NAME_LEN) {
            // GNU long-name preamble: an 'L' entry carrying the full path as its body.
            val body = nameBytes + 0 // NUL-terminated, as GNU writes it
            out.write(rawHeader(LONGLINK, body.size.toLong(), TYPE_LONGNAME))
            out.write(body)
            padTo(out, body.size.toLong())
            // The real header's name field is then the truncated path (readers use the L body).
        }
        out.write(rawHeader(name, size, typeflag))
    }

    internal fun rawHeader(name: String, size: Long, typeflag: Byte): ByteArray {
        require(size >= 0) { "negative size" }
        val h = ByteArray(BLOCK)
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        System.arraycopy(nameBytes, 0, h, 0, minOf(nameBytes.size, NAME_LEN))
        putOctal(h, 100, 8, 0b110_100_100.toLong())  // mode 0644 (dirs get 0755 below)
        if (typeflag == TYPE_DIR) putOctal(h, 100, 8, 0b111_101_101.toLong()) // 0755
        putOctal(h, 108, 8, 0)                         // uid
        putOctal(h, 116, 8, 0)                         // gid
        putSize(h, size)                               // size
        putOctal(h, 136, 12, 0)                        // mtime 0 → deterministic
        h[156] = typeflag
        System.arraycopy("ustar".toByteArray(Charsets.US_ASCII), 0, h, 257, 5)
        h[262] = 0
        h[263] = '0'.code.toByte(); h[264] = '0'.code.toByte()
        // checksum: spaces, sum, then "%06o\0 " at 148.
        for (i in 148 until 156) h[i] = ' '.code.toByte()
        var sum = 0
        for (b in h) sum += b.toInt() and 0xFF
        System.arraycopy(String.format("%06o", sum).toByteArray(Charsets.US_ASCII), 0, h, 148, 6)
        h[154] = 0
        h[155] = ' '.code.toByte()
        return h
    }

    /**
     * The 12-byte size field at 124: octal up to [MAX_OCTAL_SIZE], else GNU base-256 (first
     * byte 0x80, then the value big-endian in the remaining 11 bytes).
     */
    private fun putSize(h: ByteArray, size: Long) {
        if (size <= MAX_OCTAL_SIZE) {
            putOctal(h, 124, 12, size)
            return
        }
        h[124] = 0x80.toByte()
        var v = size
        for (i in 135 downTo 125) {
            h[i] = (v and 0xFF).toByte()
            v = v ushr 8
        }
    }

    private fun padTo(out: OutputStream, size: Long) {
        val pad = ((BLOCK - (size % BLOCK)) % BLOCK).toInt()
        if (pad > 0) out.write(ByteArray(pad))
    }

    // ── Read / extract ─────────────────────────────────────────────────────────
    //
    // Streamed from [input] straight to disk under [targetRoot]. Never buffers a whole member.
    // Returns the number of regular files written; directories are created as needed. A member
    // that fails a safety check is REJECTED with an exception (the whole extract fails loud)
    // rather than skipped — a folder that half-extracts around a hostile entry is worse than a
    // clean refusal the user sees.

    class TarSecurityException(message: String) : Exception(message)

    // 3.0.0 (4d) bounds on a hostile archive. A long name is a path, and no file system takes a
    // path past a few KiB; the member count stops a tiny archive from creating files without end.
    private const val MAX_LONG_NAME = 16 * 1024
    private const val MAX_PAX_HEADER = 64 * 1024
    internal const val MAX_MEMBERS = 250_000

    /**
     * Extract [input] under [targetRoot]. With [ownerOnly] (the default: this is decrypted
     * output) every folder and file created is readable by its owner only.
     */
    fun extract(input: InputStream, targetRoot: Path, ownerOnly: Boolean = true): Int {
        val rootNorm = targetRoot.toAbsolutePath().normalize()
        Files.createDirectories(rootNorm, *SafeFiles.dirAttrs(ownerOnly))
        val rootReal = rootNorm.toRealPath()
        var written = 0
        var members = 0
        var pendingLongName: String? = null
        var paxPath: String? = null
        var paxSize: Long? = null
        val header = ByteArray(BLOCK)

        while (true) {
            readFully(input, header) ?: break // clean EOF before a header
            if (isZeroBlock(header)) break
            if (!checksumMatches(header)) throw TarSecurityException("damaged archive header")

            val declaredName = cstr(header, 0, NAME_LEN)
            val prefix = cstr(header, 345, 155)
            val headerName = if (prefix.isNotEmpty()) "$prefix/$declaredName" else declaredName
            val headerSize = parseSize(header)
            if (headerSize < 0) throw TarSecurityException("invalid member size")
            val typeflag = header[156]

            if (++members > MAX_MEMBERS) throw TarSecurityException("more than $MAX_MEMBERS members")

            if (typeflag == TYPE_LONGNAME) {
                // Body is the real path; capture it for the next header, skip its blocks.
                if (headerSize > MAX_LONG_NAME) throw TarSecurityException("long name of $headerSize bytes")
                val body = ByteArray(headerSize.toInt())
                readFully(input, body) ?: throw EOFException("truncated long-name entry")
                skipPadding(input, headerSize)
                pendingLongName = cstrOf(body)
                continue
            }
            if (typeflag == TYPE_PAX || typeflag == TYPE_PAX_GLOBAL) {
                if (headerSize > MAX_PAX_HEADER) throw TarSecurityException("extended header of $headerSize bytes")
                val body = ByteArray(headerSize.toInt())
                readFully(input, body) ?: throw EOFException("truncated extended header")
                skipPadding(input, headerSize)
                if (typeflag == TYPE_PAX) {
                    val records = parsePax(body)
                    records["path"]?.let { paxPath = it }
                    records["size"]?.let {
                        paxSize = it.toLongOrNull()?.takeIf { s -> s >= 0 }
                            ?: throw TarSecurityException("invalid extended size")
                    }
                }
                continue
            }

            val name = paxPath ?: pendingLongName ?: headerName
            val size = paxSize ?: headerSize
            pendingLongName = null
            paxPath = null
            paxSize = null

            when (typeflag) {
                TYPE_DIR -> {
                    val dest = safeResolve(rootNorm, name)
                    Files.createDirectories(dest, *SafeFiles.dirAttrs(ownerOnly))
                    requireInside(rootReal, dest, name)
                    skipExactly(input, size)
                    skipPadding(input, size)
                }
                TYPE_FILE, 0.toByte() -> {
                    val dest = safeResolve(rootNorm, name)
                    Files.createDirectories(dest.parent ?: rootNorm, *SafeFiles.dirAttrs(ownerOnly))
                    // 3.0.0 (4d): the folder the file lands in, resolved through any links, must
                    // still be inside the target; the file itself is created new, never written
                    // through an existing link or over an earlier member of the same name.
                    requireInside(rootReal, dest.parent ?: rootNorm, name)
                    if (Files.exists(dest, LinkOption.NOFOLLOW_LINKS)) {
                        throw TarSecurityException("duplicate or existing member: $name")
                    }
                    copyExactly(input, dest, size, ownerOnly)
                    skipPadding(input, size)
                    written++
                }
                else -> {
                    // Links ('1','2'), devices, fifos: skip the body, materialize nothing.
                    skipExactly(input, size)
                    skipPadding(input, size)
                }
            }
        }
        return written
    }

    /**
     * Resolve [name] under [root], rejecting anything that would escape: an absolute path, a
     * `..` component, or a normalized result outside root. This is the zip-slip guard.
     */
    private fun safeResolve(root: Path, name: String): Path {
        val clean = name.replace('\\', '/').trimStart('/')
        if (clean.isEmpty()) throw TarSecurityException("empty member name")
        val parts = clean.split('/').filter { it.isNotEmpty() && it != "." }
        if (parts.any { it == ".." }) throw TarSecurityException("path traversal in member: $name")
        if (parts.any { !isPortableComponent(it) }) throw TarSecurityException("unsafe member name: $name")
        var dest = root
        try {
            for (p in parts) dest = dest.resolve(p)
        } catch (_: java.nio.file.InvalidPathException) {
            throw TarSecurityException("unsafe member name: $name")
        }
        val norm = dest.normalize()
        if (norm != root && !norm.startsWith(root)) {
            throw TarSecurityException("member escapes the target folder: $name")
        }
        return norm
    }

    /** [dir], resolved through any links, must be [rootReal] or inside it. */
    private fun requireInside(rootReal: Path, dir: Path, name: String) {
        val real = dir.toRealPath()
        if (real != rootReal && !real.startsWith(rootReal)) {
            throw TarSecurityException("member escapes the target folder: $name")
        }
    }

    private val WINDOWS_DEVICE = Regex("(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(\\..*)?")

    /**
     * 3.0.0 (4d): one path component that is a plain name on every desktop OS. Refused: control
     * characters, a colon (a drive or an NTFS alternate data stream on Windows), a trailing dot
     * or space (Windows drops them, so two names become one), and Windows device names, which
     * open the device instead of a file there. The archive is refused, not renamed, so what
     * lands on disk is always exactly what the archive says. (A name Windows cannot hold for
     * other reasons fails there as an unsafe member name.)
     */
    internal fun isPortableComponent(part: String): Boolean {
        if (part.any { it < ' ' || it == '\u007F' || it == ':' }) return false
        if (part.endsWith('.') || part.endsWith(' ')) return false
        if (WINDOWS_DEVICE.matches(part)) return false
        if (com.pgpony.android.crypto.LiteralFilename.isDeviceName(part)) return false
        return true
    }

    // ── Detection ────────────────────────────────────────────────────────────

    /** True when [head] begins with a ustar header (magic "ustar" at offset 257). */
    fun looksLikeTar(head: ByteArray): Boolean {
        if (head.size < 265) return false
        return head[257] == 'u'.code.toByte() && head[258] == 's'.code.toByte() &&
            head[259] == 't'.code.toByte() && head[260] == 'a'.code.toByte() &&
            head[261] == 'r'.code.toByte()
    }

    // ── Byte helpers ─────────────────────────────────────────────────────────

    private fun copyExactly(input: InputStream, dest: Path, size: Long, ownerOnly: Boolean) {
        val ch = Files.newByteChannel(
            dest, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), *SafeFiles.fileAttrs(ownerOnly)
        )
        BufferedOutputStream(Channels.newOutputStream(ch)).use { out ->
            val buf = ByteArray(64 * 1024)
            var remaining = size
            while (remaining > 0) {
                val want = minOf(remaining, buf.size.toLong()).toInt()
                val n = input.read(buf, 0, want)
                if (n < 0) throw EOFException("truncated file body")
                out.write(buf, 0, n)
                remaining -= n
            }
        }
    }

    private fun skipExactly(input: InputStream, size: Long) {
        var remaining = size
        val buf = ByteArray(64 * 1024)
        while (remaining > 0) {
            val n = input.read(buf, 0, minOf(remaining, buf.size.toLong()).toInt())
            if (n < 0) throw EOFException("truncated body")
            remaining -= n
        }
    }

    private fun skipPadding(input: InputStream, size: Long) {
        val pad = ((BLOCK - (size % BLOCK)) % BLOCK).toInt()
        if (pad > 0) {
            val junk = ByteArray(pad)
            readFully(input, junk) ?: throw EOFException("truncated block padding")
        }
    }

    /** Fill [buf] fully, or return null if EOF arrives before a single byte (clean end). */
    private fun readFully(input: InputStream, buf: ByteArray): Unit? {
        var got = 0
        while (got < buf.size) {
            val n = input.read(buf, got, buf.size - got)
            if (n < 0) {
                if (got == 0) return null
                throw EOFException("truncated block")
            }
            got += n
        }
        return Unit
    }

    private fun isZeroBlock(b: ByteArray): Boolean {
        for (byte in b) if (byte.toInt() != 0) return false
        return true
    }

    /** The header checksum (148..155 counted as spaces), unsigned or the old signed form. */
    internal fun checksumMatches(h: ByteArray): Boolean {
        val stored = parseOctal(h, 148, 8)
        var unsigned = 0L
        var signed = 0L
        for (i in 0 until BLOCK) {
            val b = if (i in 148 until 156) ' '.code.toByte() else h[i]
            unsigned += b.toInt() and 0xFF
            signed += b.toInt()
        }
        return stored == unsigned || stored == signed
    }

    private fun cstr(b: ByteArray, off: Int, len: Int): String {
        var end = off
        val limit = off + len
        while (end < limit && b[end].toInt() != 0) end++
        return String(b, off, end - off, Charsets.UTF_8)
    }

    private fun cstrOf(b: ByteArray): String {
        var end = 0
        while (end < b.size && b[end].toInt() != 0) end++
        return String(b, 0, end, Charsets.UTF_8)
    }

    /** The size field: octal, or GNU base-256. -1 when it does not hold a usable size. */
    internal fun parseSize(h: ByteArray): Long {
        val first = h[124].toInt() and 0xFF
        if (first and 0x80 == 0) return parseOctal(h, 124, 12)
        if (first != 0x80) return -1 // negative (0xFF) or a value past 64 bits
        if (h[125].toInt() and 0x80 != 0) return -1 // would not fit a signed Long
        var v = 0L
        for (i in 125 until 136) {
            if (v ushr 55 != 0L) return -1
            v = (v shl 8) or (h[i].toLong() and 0xFF)
        }
        return v
    }

    private fun parseOctal(b: ByteArray, off: Int, len: Int): Long {
        var v = 0L
        var i = off
        val limit = off + len
        while (i < limit && (b[i].toInt() == ' '.code || b[i].toInt() == 0)) i++
        while (i < limit) {
            val c = b[i].toInt()
            if (c < '0'.code || c > '7'.code) break
            v = (v shl 3) + (c - '0'.code)
            i++
        }
        return v
    }

    /** PAX extended header records ("<len> <key>=<value>\n"); malformed input is refused. */
    private fun parsePax(body: ByteArray): Map<String, String> {
        val out = HashMap<String, String>()
        var pos = 0
        while (pos < body.size) {
            if (body[pos].toInt() == 0) break
            var sp = pos
            while (sp < body.size && body[sp] != ' '.code.toByte()) sp++
            val len = String(body, pos, sp - pos, Charsets.US_ASCII).toIntOrNull()
            if (len == null || len <= 0 || pos + len > body.size || sp >= pos + len) {
                throw TarSecurityException("damaged extended header")
            }
            val record = String(body, sp + 1, pos + len - sp - 1, Charsets.UTF_8).removeSuffix("\n")
            val eq = record.indexOf('=')
            if (eq > 0) out[record.substring(0, eq)] = record.substring(eq + 1)
            pos += len
        }
        return out
    }

    private fun putOctal(h: ByteArray, off: Int, len: Int, value: Long) {
        val digits = len - 1
        val s = String.format("%0${digits}o", value)
        val bytes = s.toByteArray(Charsets.US_ASCII)
        require(bytes.size <= digits) { "value too large for a $len-byte field" }
        System.arraycopy(bytes, 0, h, off, bytes.size)
        h[off + digits] = 0
    }
}
