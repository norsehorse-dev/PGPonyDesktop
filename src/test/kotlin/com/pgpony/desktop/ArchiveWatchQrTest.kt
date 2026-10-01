// ArchiveWatchQrTest.kt
// 3.0.0: the folder tar codec's size encoding for 8 GiB and more, header checks and PAX
// records, links inside an archived folder; the watch folders' open-time checks; QR frame
// reassembly checking its sequence id (FILES-3, FILES-4, FILES-9, FILES-10).

package com.pgpony.desktop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ArchiveWatchQrTest {

    private fun tmp(): Path = Files.createTempDirectory("pgpony-b1-awq")

    // ── Tar ──────────────────────────────────────────────────────────────

    @Test
    fun files9SizesOf8GiBAndMoreUseBase256AndReadBack() {
        for (size in listOf(0L, 5L, TarStreamer.MAX_OCTAL_SIZE, TarStreamer.MAX_OCTAL_SIZE + 1, 9L shl 30, 1L shl 40)) {
            val h = TarStreamer.rawHeader("f", size, '0'.code.toByte())
            assertTrue(TarStreamer.checksumMatches(h), "checksum for $size")
            assertEquals(size, TarStreamer.parseSize(h), "size $size")
            assertEquals(size > TarStreamer.MAX_OCTAL_SIZE, h[124] == 0x80.toByte(), "base-256 marker for $size")
        }
    }

    @Test
    fun files9TheReaderTakesABase256SizeAndRefusesANegativeOne() {
        val body = "base-256 body".toByteArray()
        val h = TarStreamer.rawHeader("top/b.txt", body.size.toLong(), '0'.code.toByte())
        // Re-encode the size in base-256 (as GNU tar may) and fix the checksum.
        java.util.Arrays.fill(h, 124, 136, 0)
        h[124] = 0x80.toByte()
        h[135] = body.size.toByte()
        fixChecksum(h)
        val tar = h + body + ByteArray(512 - body.size) + ByteArray(1024)
        val out = tmp().resolve("x")
        assertEquals(1, TarStreamer.extract(ByteArrayInputStream(tar), out))
        assertEquals("base-256 body", Files.readString(out.resolve("top/b.txt")))

        h[124] = 0xFF.toByte()
        fixChecksum(h)
        assertFailsWith<TarStreamer.TarSecurityException> {
            TarStreamer.extract(ByteArrayInputStream(h + ByteArray(1024)), tmp().resolve("y"))
        }
    }

    @Test
    fun files3ADamagedHeaderIsRefused() {
        val h = TarStreamer.rawHeader("a.txt", 1, '0'.code.toByte())
        h[0] = 'b'.code.toByte() // checksum no longer matches
        assertFailsWith<TarStreamer.TarSecurityException> {
            TarStreamer.extract(ByteArrayInputStream(h + ByteArray(512) + ByteArray(1024)), tmp().resolve("z"))
        }
    }

    @Test
    fun paxPathAndSizeRecordsApplyToTheNextMember() {
        val body = "pax sized".toByteArray()
        fun record(k: String, v: String): String {
            var len = k.length + v.length + 3
            while ("$len $k=$v\n".length != len) len = "$len $k=$v\n".length
            return "$len $k=$v\n"
        }
        val pax = (record("path", "top/from-pax.txt") + record("size", body.size.toString())).toByteArray()
        val px = TarStreamer.rawHeader("PaxHeader", pax.size.toLong(), 'x'.code.toByte())
        val member = TarStreamer.rawHeader("top/short", 0, '0'.code.toByte()) // the PAX size wins
        val tar = px + pax + ByteArray(512 - pax.size) + member + body + ByteArray(512 - body.size) + ByteArray(1024)
        val out = tmp().resolve("p")
        assertEquals(1, TarStreamer.extract(ByteArrayInputStream(tar), out))
        assertEquals("pax sized", Files.readString(out.resolve("top/from-pax.txt")))
    }

    @Test
    fun files3LinksInsideAnArchivedFolderAreNeitherArchivedNorFollowed() {
        val base = tmp()
        val secret = Files.createDirectories(base.resolve("secret"))
        Files.writeString(secret.resolve("id_key"), "private")
        val root = Files.createDirectories(base.resolve("share"))
        Files.writeString(root.resolve("ok.txt"), "fine")
        val linked = runCatching {
            Files.createSymbolicLink(root.resolve("sub"), secret)
            Files.createSymbolicLink(root.resolve("key"), secret.resolve("id_key"))
        }.getOrNull() ?: return
        assertTrue(Files.isSymbolicLink(linked))
        val tar = ByteArrayOutputStream().also { TarStreamer.archive(root, it) }.toByteArray()
        val out = base.resolve("out")
        assertEquals(1, TarStreamer.extract(ByteArrayInputStream(tar), out))
        assertEquals(setOf("ok.txt"), Files.list(out.resolve("share")).use { s -> s.map { it.fileName.toString() }.toList() }.toSet())
        assertFalse(String(tar, Charsets.ISO_8859_1).contains("private"))
    }

    @Test
    fun files9AHugeSparseMemberStreamsWithItsRealSize() {
        // 8 GiB of reading: run with -Dpgpony.bigTests=true.
        if (System.getProperty("pgpony.bigTests") != "true") return
        val root = Files.createDirectories(tmp().resolve("big"))
        val size = (8L shl 30) + 3
        java.io.RandomAccessFile(root.resolve("disk.img").toFile(), "rw").use { it.setLength(size) }
        val head = ByteArrayOutputStream()
        var total = 0L
        val sink = object : java.io.OutputStream() {
            override fun write(b: Int) { if (head.size() < 2048) head.write(b); total++ }
            override fun write(b: ByteArray, off: Int, len: Int) {
                val keep = minOf(len, 2048 - head.size()).coerceAtLeast(0)
                head.write(b, off, keep)
                total += len
            }
        }
        TarStreamer.archive(root, sink)
        val second = head.toByteArray().copyOfRange(512, 1024)
        assertEquals(size, TarStreamer.parseSize(second))
        assertEquals(512L + 512 + (size + 511) / 512 * 512 + 1024, total)

        // A standard tar lists the member with its real size.
        val tar = runCatching { ProcessBuilder("tar", "-tvf", "-").redirectErrorStream(true).start() }.getOrNull() ?: return
        val listing = StringBuilder()
        val reader = Thread { listing.append(tar.inputStream.bufferedReader().readText()) }.apply { start() }
        tar.outputStream.use { TarStreamer.archive(root, it) }
        reader.join()
        assertEquals(0, tar.waitFor(), listing.toString())
        assertTrue(listing.contains(size.toString()) && listing.contains("big/disk.img"), listing.toString())
    }

    private fun fixChecksum(h: ByteArray) {
        for (i in 148 until 156) h[i] = ' '.code.toByte()
        var sum = 0
        for (b in h) sum += b.toInt() and 0xFF
        System.arraycopy(String.format("%06o", sum).toByteArray(Charsets.US_ASCII), 0, h, 148, 6)
        h[154] = 0
        h[155] = ' '.code.toByte()
    }

    // ── Watch folders ────────────────────────────────────────────────────

    @Test
    fun files4TheWatchedFileIsOpenedAsItWasSeen() {
        val base = tmp()
        val folder = Files.createDirectories(base.resolve("drop")).toRealPath()
        val f = folder.resolve("report.txt")
        Files.writeString(f, "report")
        val seen = assertNotNull(WatchFolderService.identity(f))
        val opened = WatchInput.open(folder, f, seen)
        assertEquals("report", opened.stream.use { String(it.readAllBytes()) })
        assertEquals(6L, opened.size)
    }

    @Test
    fun files4ALinkSwappedInAfterTheFileWentQuietIsRefused() {
        val base = tmp()
        val folder = Files.createDirectories(base.resolve("drop")).toRealPath()
        val victim = base.resolve("id_key").also { Files.writeString(it, "private") }
        val f = folder.resolve("report.txt")
        Files.writeString(f, "report")
        val seen = assertNotNull(WatchFolderService.identity(f))
        val staged = runCatching { Files.createSymbolicLink(folder.resolve(".staged"), victim) }.getOrNull() ?: return
        Files.move(staged, f, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        assertTrue(Files.isSymbolicLink(f))
        assertFailsWith<WatchInput.Refused> { WatchInput.open(folder, f, seen) }
    }

    @Test
    fun files4AnotherFileSwappedInIsRefused() {
        val base = tmp()
        val folder = Files.createDirectories(base.resolve("drop")).toRealPath()
        val f = folder.resolve("a.txt")
        Files.writeString(f, "first")
        val seen = assertNotNull(WatchFolderService.identity(f))
        val other = folder.resolve(".other").also { Files.writeString(it, "second!") }
        Files.move(other, f, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        assertFailsWith<WatchInput.Refused> { WatchInput.open(folder, f, seen) }
    }

    @Test
    fun files4AFileRenamedAwayAndBackAroundTheOpenIsRefused() {
        val base = tmp()
        val folder = Files.createDirectories(base.resolve("drop")).toRealPath()
        val f = folder.resolve("a.txt")
        Files.writeString(f, "first")
        val seen = assertNotNull(WatchFolderService.identity(f))
        if (seen.ctime == null) return // no status change time on this platform
        Thread.sleep(50) // past the file system's timestamp granularity
        val away = folder.resolve(".away")
        Files.move(f, away, StandardCopyOption.ATOMIC_MOVE)
        Files.move(away, f, StandardCopyOption.ATOMIC_MOVE)
        if (WatchInput.changeTime(f) == seen.ctime) return // this file system keeps ctime on rename
        assertFailsWith<WatchInput.Refused> { WatchInput.open(folder, f, seen) }
    }

    @Test
    fun files4AFileThatGrewAfterItWentQuietIsRefused() {
        val base = tmp()
        val folder = Files.createDirectories(base.resolve("drop")).toRealPath()
        val f = folder.resolve("log.txt")
        Files.writeString(f, "line one\n")
        val seen = assertNotNull(WatchFolderService.identity(f))
        Files.writeString(f, "line two\n", java.nio.file.StandardOpenOption.APPEND)
        assertFailsWith<WatchInput.Refused> { WatchInput.open(folder, f, seen) }
    }

    @Test
    fun files4AFileWithAnotherHardLinkIsRefused() {
        val base = tmp()
        val folder = Files.createDirectories(base.resolve("drop")).toRealPath()
        val victim = base.resolve("history").also { Files.writeString(it, "private") }
        val f = runCatching { Files.createLink(folder.resolve("notes.txt"), victim) }.getOrNull() ?: return
        if (WatchInput.linkCount(f) < 2) return // no link count on this platform
        val seen = assertNotNull(WatchFolderService.identity(f))
        assertFailsWith<WatchInput.Refused> { WatchInput.open(folder, f, seen) }
    }

    // ── QR ───────────────────────────────────────────────────────────────

    private fun armor(seed: Int): String {
        val body = java.util.Base64.getEncoder().encodeToString(kotlin.random.Random(seed).nextBytes(2_400))
        return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + body.chunked(64).joinToString("\n") +
            "\n-----END PGP PUBLIC KEY BLOCK-----\n"
    }

    @Test
    fun files10AReplacedFrameIsAConflictNotAnOverwrite() {
        val frames = assertNotNull(QrChunking.split(armor(1)))
        // Same id, seq and total, another payload.
        val p = assertNotNull(QrChunking.parse(frames[0]))
        val forged = "${QrChunking.PREFIX}${p.seq}:${p.total}:${p.id}:" + "A".repeat(p.payload.length)
        val c = QrChunking.Collector()
        c.offer(frames[0])
        assertIs<QrChunking.Outcome.Conflict>(c.offer(forged))
        assertEquals(QrCode.Import.Mixed, QrCode.importFrom(frames + forged))
    }

    @Test
    fun files10PartsThatDoNotHashToTheIdAreNotAKey() {
        val text = armor(2)
        val frames = assertNotNull(QrChunking.split(text))
        val p = assertNotNull(QrChunking.parse(frames.last()))
        val swapped = "${QrChunking.PREFIX}${p.seq}:${p.total}:${p.id}:" + p.payload.reversed()
        val c = QrChunking.Collector()
        var last: QrChunking.Outcome? = null
        for (f in frames.dropLast(1) + swapped) last = c.offer(f)
        assertEquals(QrChunking.Outcome.Malformed, last)
        assertEquals(QrCode.Import.Mixed, QrCode.importFrom(frames.dropLast(1) + swapped))
        assertEquals(QrCode.Import.Key(text), QrCode.importFrom(frames))
    }

    @Test
    fun files10AWholeKeyNextToFramesIsMixed() {
        val single = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
        val frames = assertNotNull(QrChunking.split(armor(3)))
        assertEquals(QrCode.Import.Mixed, QrCode.importFrom(listOf(single) + frames))
        assertEquals(QrCode.Import.Key(single), QrCode.importFrom(listOf(single, single)))
    }
}
