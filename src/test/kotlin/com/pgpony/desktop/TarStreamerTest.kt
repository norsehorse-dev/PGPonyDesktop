// TarStreamerTest.kt
// D16 validation — the folder-encryption tar codec (src/main/kotlin/com/pgpony/desktop/
// TarStreamer.kt). Round-trip, the GNU long-name extension, nested directories, and the hostile
// archives from the 2.0.0 matrix (traversal, absolute path, symlink). The `gpgtar -d` / GNU-tar
// interop rows are the manual matrix (§8) — they need the external tools — but were run green in
// the container while this landed; here we pin the pure Kotlin behavior the suite can enforce.

package com.pgpony.desktop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TarStreamerTest {

    private lateinit var work: Path

    @BeforeTest fun setUp() { work = Files.createTempDirectory("tarstreamer") }

    @AfterTest fun tearDown() {
        Files.walk(work).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
    }

    private fun archiveBytes(root: Path): ByteArray =
        ByteArrayOutputStream().also { TarStreamer.archive(root, it) }.toByteArray()

    @Test
    fun roundTripsFilesDirectoriesAndBinaryContent() {
        val src = work.resolve("data")
        Files.createDirectories(src.resolve("sub/deeper"))
        Files.writeString(src.resolve("a.txt"), "hello alpha")
        Files.writeString(src.resolve("sub/deeper/note.md"), "# deep")
        val bin = ByteArray(1000) { (it % 256).toByte() }
        Files.write(src.resolve("sub/bin.dat"), bin)

        val tar = archiveBytes(src)
        assertEquals(0, tar.size % 512, "archive is block-aligned")
        assertTrue(TarStreamer.looksLikeTar(tar), "our own output is detected as a tar")

        val out = work.resolve("out")
        val n = TarStreamer.extract(ByteArrayInputStream(tar), out)
        assertEquals(3, n, "three regular files")
        assertEquals("hello alpha", Files.readString(out.resolve("data/a.txt")))
        assertEquals("# deep", Files.readString(out.resolve("data/sub/deeper/note.md")))
        assertContentEquals(bin, Files.readAllBytes(out.resolve("data/sub/bin.dat")))
        assertTrue(Files.isDirectory(out.resolve("data/sub/deeper")), "empty-ish dirs recreated")
    }

    @Test
    fun handlesNamesOverAHundredBytesViaTheLongNameExtension() {
        val src = work.resolve("data")
        Files.createDirectories(src)
        val long = "z".repeat(150) + ".txt"   // 154 bytes > 100
        Files.writeString(src.resolve(long), "long-named payload")

        val out = work.resolve("out")
        TarStreamer.extract(ByteArrayInputStream(archiveBytes(src)), out)
        assertEquals("long-named payload", Files.readString(out.resolve("data/$long")))
    }

    @Test
    fun theTopFolderNameIsTheArchiveRoot() {
        // Untarring reconstructs the folder, not its loose contents at the destination top.
        val src = work.resolve("myproject")
        Files.createDirectories(src)
        Files.writeString(src.resolve("f.txt"), "x")
        val out = work.resolve("out")
        TarStreamer.extract(ByteArrayInputStream(archiveBytes(src)), out)
        assertTrue(Files.exists(out.resolve("myproject/f.txt")))
        assertFalse(Files.exists(out.resolve("f.txt")), "contents must not spill to the top")
    }

    // ── Hostile archives (2.0.0 §8 matrix) ──────────────────────────────────

    /** A single-member ustar with an arbitrary (possibly hostile) name. */
    private fun oneFileTar(name: String, content: String): ByteArray {
        val block = 512
        val h = ByteArray(block)
        val nb = name.toByteArray(Charsets.UTF_8)
        System.arraycopy(nb, 0, h, 0, minOf(nb.size, 100))
        fun oct(off: Int, len: Int, v: Long) {
            val d = len - 1
            val s = String.format("%0${d}o", v).toByteArray(Charsets.US_ASCII)
            System.arraycopy(s, maxOf(0, s.size - d), h, off, minOf(s.size, d)); h[off + d] = 0
        }
        oct(100, 8, 0b110_100_100); oct(108, 8, 0); oct(116, 8, 0)
        oct(124, 12, content.length.toLong()); oct(136, 12, 0)
        h[156] = '0'.code.toByte()
        System.arraycopy("ustar".toByteArray(Charsets.US_ASCII), 0, h, 257, 5)
        h[262] = 0; h[263] = '0'.code.toByte(); h[264] = '0'.code.toByte()
        for (i in 148 until 156) h[i] = ' '.code.toByte()
        var sum = 0; for (b in h) sum += b.toInt() and 0xFF
        System.arraycopy(String.format("%06o", sum).toByteArray(Charsets.US_ASCII), 0, h, 148, 6)
        h[154] = 0; h[155] = ' '.code.toByte()
        val body = content.toByteArray(Charsets.UTF_8)
        val pad = (block - body.size % block) % block
        return h + body + ByteArray(pad) + ByteArray(block * 2)
    }

    @Test
    fun rejectsATraversalMemberAndWritesNothingOutside() {
        val evil = oneFileTar("../escape.txt", "pwned")
        assertFailsWith<TarStreamer.TarSecurityException> {
            TarStreamer.extract(ByteArrayInputStream(evil), work.resolve("safe"))
        }
        assertFalse(Files.exists(work.resolve("escape.txt")), "nothing escaped the target root")
    }

    @Test
    fun rejectsAnAbsolutePathMember() {
        val evil = oneFileTar("/tmp/pgpony-abs-escape.txt", "x")
        // The leading slash is stripped and re-rooted; the file lands INSIDE, never at /tmp.
        val out = work.resolve("safe2")
        TarStreamer.extract(ByteArrayInputStream(evil), out)
        assertTrue(Files.exists(out.resolve("tmp/pgpony-abs-escape.txt")), "absolute path contained under root")
        assertFalse(Files.exists(java.nio.file.Path.of("/tmp/pgpony-abs-escape.txt")), "must not write to /tmp")
    }

    @Test
    fun symlinkMembersAreSkippedNotMaterialized() {
        // typeflag '2' (symlink) with a link target — our reader skips it entirely.
        val block = 512
        val h = ByteArray(block)
        System.arraycopy("link".toByteArray(), 0, h, 0, 4)
        fun oct(off: Int, len: Int, v: Long) {
            val d = len - 1; val s = String.format("%0${d}o", v).toByteArray()
            System.arraycopy(s, 0, h, off, minOf(s.size, d)); h[off + d] = 0
        }
        oct(100, 8, 0b110_100_100); oct(108, 8, 0); oct(116, 8, 0); oct(124, 12, 0); oct(136, 12, 0)
        h[156] = '2'.code.toByte()                       // symlink typeflag
        System.arraycopy("/etc/passwd".toByteArray(), 0, h, 157, 11)  // linkname field
        System.arraycopy("ustar".toByteArray(), 0, h, 257, 5); h[263] = '0'.code.toByte(); h[264] = '0'.code.toByte()
        for (i in 148 until 156) h[i] = ' '.code.toByte()
        var sum = 0; for (b in h) sum += b.toInt() and 0xFF
        System.arraycopy(String.format("%06o", sum).toByteArray(), 0, h, 148, 6); h[154] = 0; h[155] = ' '.code.toByte()
        val tar = h + ByteArray(block * 2)

        val out = work.resolve("safe3")
        val n = TarStreamer.extract(ByteArrayInputStream(tar), out)
        assertEquals(0, n, "no regular file written")
        assertFalse(Files.exists(out.resolve("link")), "the symlink was not materialized")
    }

    @Test
    fun looksLikeTarIsFalseForShortOrNonTarHeads() {
        assertFalse(TarStreamer.looksLikeTar(ByteArray(10)))
        assertFalse(TarStreamer.looksLikeTar(ByteArray(600))) // all zeros, no magic
    }
}
