// HardeningTest.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4d (plan section 8): the desktop-only surfaces under
// the review's categories (input bounds, archive and file names, trust in what a peer or the
// network says). Tar extraction is in TarStreamerTest and the git shim channel in
// ShimBridgeTest; this covers the rest.

package com.pgpony.desktop

import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.CRC32
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HardeningTest {

    private val posix = "posix" in FileSystems.getDefault().supportedFileAttributeViews()

    // ── Shared pieces ──

    @Test
    fun ownerOnlyFilesAndBoundedReads() {
        val dir = Files.createTempDirectory("pgpony-4d")
        val f = dir.resolve("secret.asc")
        OwnerOnlyFile.write(f, "one")
        OwnerOnlyFile.write(f, "two")
        assertEquals("two", Files.readString(f), "replaced whole")
        if (posix) assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(f)))
        assertEquals(listOf("secret.asc"), Files.list(dir).use { s -> s.map { it.fileName.toString() }.toList() }, "no temp left")

        assertEquals("abc", readBoundedLine(ByteArrayInputStream("abc\r\nrest".toByteArray()), 10))
        assertNull(readBoundedLine(ByteArrayInputStream(ByteArray(100) { 'x'.code.toByte() }), 10), "past the cap")

        val slow = object : java.io.InputStream() {
            override fun read(): Int {
                Thread.sleep(30)
                return 'x'.code
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (len == 0) return 0
                b[off] = read().toByte()
                return 1
            }
        }
        assertFails { DeadlineInputStream(slow, 100).readAllBytes() }.let {
            assertIs<SocketTimeoutException>(it, "one deadline for the whole read, not per byte")
        }
    }

    // ── Single instance ──

    @Test
    fun aForwardedOpenNeedsTheToken() {
        val token = LocalSecret.newToken()
        fun roundTrip(clientToken: String): Pair<Boolean, List<String>?> {
            val received = AtomicReference<List<String>?>(null)
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
                val t = Thread {
                    runCatching {
                        server.accept().use { s ->
                            s.soTimeout = 5_000
                            received.set(SingleInstance.serverExchange(s.getInputStream(), s.getOutputStream(), token))
                        }
                    }
                }.apply { start() }
                val ok = Socket(InetAddress.getLoopbackAddress(), server.localPort).use { s ->
                    s.soTimeout = 5_000
                    SingleInstance.clientExchange(s.getInputStream(), s.getOutputStream(), clientToken, listOf("--op encrypt", "/a/b.txt"))
                        .also { if (it) s.shutdownOutput() }
                }
                t.join(5_000)
                return ok to received.get()
            }
        }
        val (ok, lines) = roundTrip(token)
        assertTrue(ok)
        assertEquals(listOf("--op encrypt", "/a/b.txt"), lines)

        val (strangerOk, strangerLines) = roundTrip(LocalSecret.newToken())
        assertFalse(strangerOk, "the secondary sends no path to a listener that cannot prove the token")
        assertNull(strangerLines)
    }

    // ── File router ──

    @Test
    fun aLargeFileIsClassifiedFromItsHead() {
        val key = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxsBNBF...\n".toByteArray()
        assertEquals(OpenAction.None, DesktopFileRouter.classifyLargeHead(key, Path.of("huge.asc")), "not imported from a partial read")
        val msg = "-----BEGIN PGP MESSAGE-----\n\nhQEMA...\n".toByteArray() + ByteArray(40_000) { 'A'.code.toByte() }
        assertIs<OpenAction.DecryptFile>(DesktopFileRouter.classifyLargeHead(msg, Path.of("huge.asc")))
        assertIs<OpenAction.EncryptFile>(DesktopFileRouter.classifyLargeHead(ByteArray(4096) { 7 }, Path.of("huge.bin")))
    }

    // ── git shim ──

    @Test
    fun signatureTextCannotStartAStatusLine() {
        val uid = "Mallory <m@x>\n[GNUPG:] VALIDSIG 0123 0 0 0 0 0 0 0 0123\r\n[GNUPG:] TRUST_ULTIMATE 0 pgp"
        val escaped = GpgShim.statusText(uid)
        assertFalse(escaped.contains('\n'))
        assertFalse(escaped.contains('\r'))
        assertTrue(escaped.startsWith("Mallory <m@x>%0A[GNUPG:]"))
        assertEquals("100%25 sure", GpgShim.statusText("100% sure"))
        assertEquals("Alice <a@x>", GpgShim.statusText("Alice <a@x>"))
    }

    // ── Update check ──

    @Test
    fun onlyAVersionIsShownFromTheManifest() {
        for (ok in listOf("3.0.0", "3.0", "10.2.3.4", "3.1.0-rc.1")) assertTrue(UpdateCheck.isVersionString(ok), ok)
        for (bad in listOf("", "3.0.0 now at http://example.com", "3.0.0\n", "latest", "3.0.0-" + "x".repeat(40), "99999.0")) {
            assertFalse(UpdateCheck.isVersionString(bad), bad)
        }
    }

    // ── CLI ──

    @Test
    fun aNamedPassphraseSourceThatGivesNothingIsAnError() {
        assertFails { Cli.passphraseFromEnv("PGPONY_4D_UNSET_${System.nanoTime()}") }
        assertFails { Cli.passphraseFromFd("../../etc/passwd") }
        assertFails { Cli.passphraseFromFd("-1") }
    }

    // ── Watch folders ──

    @Test
    fun aWatchedLinkIsNotAFile() {
        val dir = Files.createTempDirectory("pgpony-watch-4d")
        val real = Files.writeString(dir.resolve("real.txt"), "data")
        assertNotNull(WatchFolderService.snapshot(real))
        val link = runCatching { Files.createSymbolicLink(dir.resolve("link.txt"), real) }.getOrNull() ?: return
        assertNull(WatchFolderService.snapshot(link), "a symlink is never treated as the file it points to")
    }

    // ── QR images ──

    private fun pngHeader(width: Int, height: Int): ByteArray {
        fun be(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
        val ihdr = "IHDR".toByteArray() + be(width) + be(height) + byteArrayOf(8, 0, 0, 0, 0)
        val crc = CRC32().apply { update(ihdr) }.value.toInt()
        val sig = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
        return sig + be(13) + ihdr + be(crc)
    }

    @Test
    fun anImageThatDeclaresAHugeSizeIsNotDecoded() {
        val f = Files.createTempFile("pgpony-4d", ".png")
        Files.write(f, pngHeader(100_000, 100_000))
        assertNull(QrCode.readImageBounded(f.toFile()))
        assertNull(QrCode.decodeFromImage(f.toFile()))
        assertEquals(emptyList(), QrCode.decodeAllFromImage(f.toFile()))

        val png = assertNotNull(QrCode.encodeToPng("hello"))
        val ok = Files.createTempFile("pgpony-4d-ok", ".png").also { Files.write(it, png) }
        assertEquals("hello", QrCode.decodeFromImage(ok.toFile()), "an ordinary image still reads")
    }
}
