// LocalIpc.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4d (plan section 8): the pieces the two loopback
// channels (SingleInstance and ShimBridge) and the CLI share.
//
// A loopback port is reachable by every account on the machine, so a channel on one proves who
// is talking with a secret only the user can read: a random token in a file created
// owner-only (0600 where the file system has POSIX permissions; the data directory is per-user
// on Windows). Reads from a peer run under one deadline for the whole request, not a per-read
// timeout, so a peer that trickles a byte at a time cannot hold the listener.

package com.pgpony.desktop

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.SocketTimeoutException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object OwnerOnlyFile {

    private fun posix(): Boolean = "posix" in FileSystems.getDefault().supportedFileAttributeViews()

    /** Create [path] new, readable and writable by the owner only. Fails if it exists. */
    fun createNew(path: Path): Path =
        if (posix()) {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        } else {
            Files.createFile(path)
        }

    /** Write [bytes] to [target] owner-only, replacing any old file whole (temp file, then move). */
    fun write(target: Path, bytes: ByteArray) {
        Files.createDirectories(target.toAbsolutePath().parent)
        val tmp = target.resolveSibling(".${target.fileName}.tmp")
        Files.deleteIfExists(tmp)
        createNew(tmp)
        try {
            Files.write(tmp, bytes, StandardOpenOption.TRUNCATE_EXISTING)
            try {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    fun write(target: Path, text: String) = write(target, text.toByteArray(Charsets.UTF_8))
}

object LocalSecret {

    /** 32 random bytes as hex. */
    fun newToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return hex(bytes)
    }

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /** HMAC-SHA256 of [label] and [nonce] under [token], hex. */
    fun proof(token: String, label: String, nonce: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(token.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return hex(mac.doFinal("$label:$nonce".toByteArray(Charsets.UTF_8)))
    }

    fun sameText(a: String?, b: String?): Boolean =
        a != null && b != null && MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))
}

/**
 * [source] under one deadline for everything read through it. Each read is also bounded by the
 * socket's own timeout, which the caller sets no longer than the deadline.
 */
class DeadlineInputStream(private val source: InputStream, budgetMs: Long) : InputStream() {
    private val deadline = System.nanoTime() + budgetMs * 1_000_000

    private fun check() {
        if (System.nanoTime() > deadline) throw SocketTimeoutException("request took too long")
    }

    override fun read(): Int {
        check()
        return source.read().also { check() }
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        check()
        return source.read(b, off, len).also { check() }
    }

    override fun close() = source.close()
}

/** One line without its newline, or null at the end of input or past [max] bytes. */
fun readBoundedLine(input: InputStream, max: Int): String? {
    val buf = ByteArrayOutputStream()
    while (true) {
        val b = try {
            input.read()
        } catch (_: IOException) {
            return null
        }
        if (b < 0) return null
        if (b == '\n'.code) return buf.toString(Charsets.UTF_8).removeSuffix("\r")
        if (buf.size() >= max) return null
        buf.write(b)
    }
}
