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

package com.pgpony.desktop

import java.io.BufferedOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

object TarStreamer {

    private const val BLOCK = 512
    private const val NAME_LEN = 100
    private const val LONGLINK = "././@LongLink"

    // Typeflags we write and/or read.
    private const val TYPE_FILE = '0'.code.toByte()
    private const val TYPE_DIR = '5'.code.toByte()
    private const val TYPE_LONGNAME = 'L'.code.toByte()

    /** Counts, for a human summary after archiving. */
    data class Summary(val files: Int, val dirs: Int, val bytes: Long)

    // ── Write ────────────────────────────────────────────────────────────────

    /**
     * Stream [root]'s tree into [out] as an uncompressed ustar archive, then two zero blocks.
     * Paths inside the archive are relative to [root]'s PARENT, so the top folder name is the
     * archive's single root entry (untar drops the folder back, not its loose contents). File
     * bodies are copied in 64 KiB chunks — nothing is fully buffered. Deterministic order
     * (sorted), so the same tree tars to comparable bytes run to run.
     */
    fun archive(root: Path, out: OutputStream): Summary {
        require(Files.isDirectory(root)) { "not a folder: $root" }
        val base = root.toAbsolutePath().normalize().parent
            ?: throw IllegalArgumentException("cannot archive a filesystem root")
        var files = 0
        var dirs = 0
        var bytes = 0L
        // Walk sorted so directories precede their contents and output is stable.
        val entries = ArrayList<Path>()
        Files.walk(root).use { stream ->
            stream.sorted().forEach { entries.add(it) }
        }
        for (path in entries) {
            val abs = path.toAbsolutePath().normalize()
            if (abs == root.toAbsolutePath().normalize().parent) continue
            val relName = base.relativize(abs).toString().replace('\\', '/')
            if (relName.isEmpty()) continue
            when {
                Files.isSymbolicLink(path) -> continue // never archive a link's target blindly
                Files.isDirectory(path) -> {
                    writeHeader(out, "$relName/", 0L, TYPE_DIR)
                    dirs++
                }
                Files.isRegularFile(path) -> {
                    val size = Files.size(path)
                    writeHeader(out, relName, size, TYPE_FILE)
                    Files.newInputStream(path).use { it.copyTo(out, 64 * 1024) }
                    padTo(out, size)
                    files++
                    bytes += size
                }
                // sockets, fifos, devices: skip.
            }
        }
        out.write(ByteArray(BLOCK * 2))
        return Summary(files, dirs, bytes)
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

    private fun rawHeader(name: String, size: Long, typeflag: Byte): ByteArray {
        val h = ByteArray(BLOCK)
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        System.arraycopy(nameBytes, 0, h, 0, minOf(nameBytes.size, NAME_LEN))
        putOctal(h, 100, 8, 0b110_100_100.toLong())  // mode 0644 (dirs get 0755 below)
        if (typeflag == TYPE_DIR) putOctal(h, 100, 8, 0b111_101_101.toLong()) // 0755
        putOctal(h, 108, 8, 0)                         // uid
        putOctal(h, 116, 8, 0)                         // gid
        putOctal(h, 124, 12, size)                     // size
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

    fun extract(input: InputStream, targetRoot: Path): Int {
        val rootNorm = targetRoot.toAbsolutePath().normalize()
        Files.createDirectories(rootNorm)
        var written = 0
        var pendingLongName: String? = null
        val header = ByteArray(BLOCK)

        while (true) {
            readFully(input, header) ?: break // clean EOF before a header
            if (isZeroBlock(header)) break

            val declaredName = cstr(header, 0, NAME_LEN)
            val prefix = cstr(header, 345, 155)
            val headerName = if (prefix.isNotEmpty()) "$prefix/$declaredName" else declaredName
            val size = parseOctal(header, 124, 12)
            val typeflag = header[156]

            if (typeflag == TYPE_LONGNAME) {
                // Body is the real path; capture it for the next header, skip its blocks.
                val body = ByteArray(size.toInt())
                readFully(input, body) ?: throw EOFException("truncated long-name entry")
                skipPadding(input, size)
                pendingLongName = cstrOf(body)
                continue
            }

            val name = (pendingLongName ?: headerName)
            pendingLongName = null

            when (typeflag) {
                TYPE_DIR -> {
                    val dest = safeResolve(rootNorm, name)
                    Files.createDirectories(dest)
                }
                TYPE_FILE, 0.toByte() -> {
                    val dest = safeResolve(rootNorm, name)
                    Files.createDirectories(dest.parent ?: rootNorm)
                    // Refuse to follow an existing symlink at the destination (TOCTOU-ish, but
                    // an extract into a prepared tree shouldn't write through a planted link).
                    if (Files.isSymbolicLink(dest)) {
                        throw TarSecurityException("refusing to write through a symlink: $name")
                    }
                    copyExactly(input, dest, size)
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
        var dest = root
        for (p in parts) dest = dest.resolve(p)
        val norm = dest.normalize()
        if (norm != root && !norm.startsWith(root)) {
            throw TarSecurityException("member escapes the target folder: $name")
        }
        return norm
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

    private fun copyExactly(input: InputStream, dest: Path, size: Long) {
        BufferedOutputStream(Files.newOutputStream(dest)).use { out ->
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

    private fun putOctal(h: ByteArray, off: Int, len: Int, value: Long) {
        val digits = len - 1
        val s = String.format("%0${digits}o", value)
        val bytes = s.toByteArray(Charsets.US_ASCII)
        val start = maxOf(0, bytes.size - digits)
        System.arraycopy(bytes, start, h, off, bytes.size - start)
        h[off + digits] = 0
    }
}
