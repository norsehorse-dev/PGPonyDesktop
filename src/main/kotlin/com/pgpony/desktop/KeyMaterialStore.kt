// KeyMaterialStore.kt
// PGPony Desktop — armored key material at rest (D2a).
//
// The desktop counterpart of Android's SecureKeyStore, holding the actual key blocks while Room
// holds metadata. D0-3 "GnuPG posture": one armored file per half under <dataDir>/keys/, mode
// 0600 where the filesystem supports it. Secret blocks keep their own S2K protection exactly as
// imported — this store adds no crypto of its own, so there is nothing here to lose or leak
// beyond what the armor itself protects.
//
// 3.0.0: every write goes to an owner-only temporary file in the same folder, is flushed to the
// disk, and then replaces the old file in one atomic rename, so a crash, a kill or a full disk in
// the middle of an edit leaves either the old key or the new one, never a truncated file. Files
// left from older versions are set to owner-only when the store opens.
//
// 3.0.4: key blocks are kept with current-format packet headers (PacketFraming below). A file
// written by 3.0.3 or older is rewritten that way the first time it is read.

package com.pgpony.desktop

import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom

class KeyMaterialStore(private val dir: Path) {

    init {
        OwnerOnlyPaths.createPrivateDirectories(dir)
        OwnerOnlyPaths.restrictTree(dir)
    }

    private fun pubFile(fingerprint: String): Path = dir.resolve("${norm(fingerprint)}.pub.asc")
    private fun secFile(fingerprint: String): Path = dir.resolve("${norm(fingerprint)}.sec.asc")

    fun storePublic(fingerprint: String, armored: String) = write(pubFile(fingerprint), PacketFraming.currentArmor(armored))
    fun storeSecret(fingerprint: String, armored: String) = write(secFile(fingerprint), PacketFraming.currentArmor(armored))

    fun loadPublic(fingerprint: String): String? = load(pubFile(fingerprint))
    fun loadSecret(fingerprint: String): String? = load(secFile(fingerprint))

    fun hasSecret(fingerprint: String): Boolean = Files.exists(secFile(fingerprint))

    fun delete(fingerprint: String) {
        Files.deleteIfExists(pubFile(fingerprint))
        Files.deleteIfExists(secFile(fingerprint))
    }

    private fun write(file: Path, armored: String) = OwnerOnlyPaths.writeAtomically(file, armored.toByteArray(Charsets.UTF_8))

    private fun readOrNull(file: Path): String? =
        if (Files.exists(file)) Files.readString(file) else null

    /** The stored block in current-format headers; a file still in the legacy format is rewritten once. */
    private fun load(file: Path): String? {
        val stored = readOrNull(file) ?: return null
        val current = PacketFraming.currentArmor(stored)
        if (current != stored) runCatching { write(file, current) }
        return current
    }

    private fun norm(fingerprint: String) = fingerprint.lowercase()
}

/**
 * 3.0.4: OpenPGP packets in the current header format. RFC 9580 section 4.2 says the legacy
 * format SHOULD NOT be used to generate new data, but BouncyCastle writes legacy headers for the
 * packets it builds, so a stored key mixed the two formats while its export used the current one.
 * The two files then differed in their Base64 although every packet was the same. Only headers
 * change here: each packet body is copied unchanged, so fingerprints and signatures are untouched.
 * Text that is not exactly one armored key block, has a bad checksum, or does not parse comes back
 * unchanged, and so does a block that already uses the current format.
 */
internal object PacketFraming {

    private val BLOCKS = listOf("PGP PUBLIC KEY BLOCK", "PGP PRIVATE KEY BLOCK")

    fun currentArmor(armored: String): String = runCatching { reframe(armored) }.getOrNull() ?: armored

    private fun reframe(armored: String): String? {
        val nl = if (armored.contains("\r\n")) "\r\n" else "\n"
        val lines = armored.replace("\r\n", "\n").split("\n")
        val begins = lines.withIndex().filter { it.value.trim().startsWith("-----BEGIN ") }
        if (begins.size != 1) return null
        val label = BLOCKS.firstOrNull { begins[0].value.trim() == "-----BEGIN $it-----" } ?: return null
        val start = begins[0].index
        val end = lines.indexOfFirst { it.trim() == "-----END $label-----" }
        if (end <= start) return null
        if (lines.take(start).any { it.isNotBlank() } || lines.drop(end + 1).any { it.isNotBlank() }) return null
        var i = start + 1
        val headers = ArrayList<String>()
        while (i < end && lines[i].isNotBlank()) {
            if (!lines[i].contains(": ")) return null
            headers += lines[i].trimEnd()
            i++
        }
        val body = StringBuilder()
        var crcLine: String? = null
        for (line in lines.subList(i, end)) {
            val t = line.trim()
            if (t.isEmpty()) continue
            if (t.startsWith("=")) { crcLine = t.substring(1); continue }
            if (crcLine != null) return null
            body.append(t)
        }
        val raw = java.util.Base64.getDecoder().decode(body.toString())
        if (crcLine != null) {
            val crc = java.util.Base64.getDecoder().decode(crcLine)
            if (crc.size != 3 || crc24(raw) != (((crc[0].toInt() and 0xFF) shl 16) or ((crc[1].toInt() and 0xFF) shl 8) or (crc[2].toInt() and 0xFF))) return null
        }
        val current = currentFormat(raw) ?: return null
        if (current.contentEquals(raw)) return null
        val b64 = java.util.Base64.getEncoder().encodeToString(current).chunked(64)
        val c = crc24(current)
        val crc = java.util.Base64.getEncoder().encodeToString(byteArrayOf((c ushr 16).toByte(), (c ushr 8).toByte(), c.toByte()))
        val out = ArrayList<String>()
        out += "-----BEGIN $label-----"
        out += headers
        out += ""
        out += b64
        out += "=$crc"
        out += "-----END $label-----"
        val trailing = if (armored.endsWith("\n")) nl else ""
        return out.joinToString(nl) + trailing
    }

    /**
     * [raw] with every legacy packet header rewritten in the current format, bodies as they are.
     * Null when a packet cannot be framed that way: an indeterminate legacy length, a partial body
     * length, or a truncated packet.
     */
    fun currentFormat(raw: ByteArray): ByteArray? {
        val out = java.io.ByteArrayOutputStream(raw.size + 16)
        var p = 0
        while (p < raw.size) {
            val ctb = raw[p].toInt() and 0xFF
            if (ctb and 0x80 == 0) return null
            val headerStart = p
            p++
            val len: Long
            if (ctb and 0x40 != 0) {
                if (p >= raw.size) return null
                val l0 = raw[p].toInt() and 0xFF
                len = when {
                    l0 < 192 -> { p += 1; l0.toLong() }
                    l0 < 224 -> {
                        if (p + 1 >= raw.size) return null
                        val v = ((l0 - 192) shl 8) + (raw[p + 1].toInt() and 0xFF) + 192
                        p += 2; v.toLong()
                    }
                    l0 == 255 -> { if (p + 4 >= raw.size) return null; val v = be32(raw, p + 1); p += 5; v }
                    else -> return null
                }
                if (len > raw.size - p) return null
                out.write(raw, headerStart, (p - headerStart) + len.toInt())
            } else {
                val tag = (ctb shr 2) and 0x0F
                len = when (ctb and 0x03) {
                    0 -> { if (p >= raw.size) return null; val v = (raw[p].toLong() and 0xFF); p += 1; v }
                    1 -> { if (p + 1 >= raw.size) return null; val v = ((raw[p].toLong() and 0xFF) shl 8) or (raw[p + 1].toLong() and 0xFF); p += 2; v }
                    2 -> { if (p + 3 >= raw.size) return null; val v = be32(raw, p); p += 4; v }
                    else -> return null
                }
                if (len > raw.size - p) return null
                out.write(0xC0 or tag)
                writeLength(out, len)
                out.write(raw, p, len.toInt())
            }
            p += len.toInt()
        }
        return out.toByteArray()
    }

    private fun writeLength(out: java.io.ByteArrayOutputStream, len: Long) {
        when {
            len < 192 -> out.write(len.toInt())
            len < 8384 -> {
                val v = len - 192
                out.write(((v shr 8) + 192).toInt())
                out.write((v and 0xFF).toInt())
            }
            else -> {
                out.write(0xFF)
                out.write((len shr 24).toInt() and 0xFF); out.write((len shr 16).toInt() and 0xFF)
                out.write((len shr 8).toInt() and 0xFF); out.write(len.toInt() and 0xFF)
            }
        }
    }

    private fun be32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or
            ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)

    private fun crc24(data: ByteArray): Int {
        var crc = 0xB704CE
        for (b in data) {
            crc = crc xor ((b.toInt() and 0xFF) shl 16)
            for (k in 0 until 8) {
                crc = crc shl 1
                if (crc and 0x1000000 != 0) crc = crc xor 0x1864CFB
            }
        }
        return crc and 0xFFFFFF
    }
}

/**
 * Owner-only files and folders for the data directory, the database and the key store. On POSIX
 * systems folders are 0700 and files 0600. Other systems (Windows) keep their per-user profile
 * ACLs; nothing is changed there.
 */
object OwnerOnlyPaths {

    private val random = SecureRandom()

    fun posix(): Boolean = "posix" in FileSystems.getDefault().supportedFileAttributeViews()

    private val DIR_PERMS = PosixFilePermissions.fromString("rwx------")
    private val FILE_PERMS = PosixFilePermissions.fromString("rw-------")

    /** Create [dir] (and missing parents); the leaf folder is created owner-only and set so. */
    fun createPrivateDirectories(dir: Path) {
        if (!Files.isDirectory(dir)) {
            dir.toAbsolutePath().parent?.let { Files.createDirectories(it) }
            try {
                if (posix()) Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(DIR_PERMS))
                else Files.createDirectory(dir)
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                // Created by another process in the meantime.
            }
        }
        restrict(dir)
    }

    /** Set [path] owner-only (0700 for a folder, 0600 for a file). Links are left alone. */
    fun restrict(path: Path) {
        if (!posix()) return
        runCatching {
            if (Files.isSymbolicLink(path)) return
            val perms = if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) DIR_PERMS else FILE_PERMS
            if (Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) != perms) {
                Files.setPosixFilePermissions(path, perms)
            }
        }
    }

    /** [restrict] [dir] and every regular file directly inside it. */
    fun restrictTree(dir: Path) {
        if (!posix()) return
        restrict(dir)
        runCatching {
            Files.newDirectoryStream(dir).use { stream ->
                for (p in stream) if (Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) restrict(p)
            }
        }
    }

    /** Create [file] empty and owner-only when it does not exist yet; set it owner-only when it does. */
    fun ensureFile(file: Path) {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            runCatching {
                if (posix()) Files.createFile(file, PosixFilePermissions.asFileAttribute(FILE_PERMS))
                else Files.createFile(file)
            }
        }
        restrict(file)
    }

    /**
     * Replace [target] with [bytes] in one step: an owner-only temporary file in the same folder,
     * written and flushed to the disk, then renamed over [target]. Readers see the old content or
     * the new content, never a part of it. The temporary file is removed when anything fails.
     */
    fun writeAtomically(target: Path, bytes: ByteArray) {
        val parent = target.toAbsolutePath().parent
        Files.createDirectories(parent)
        val tmp = parent.resolve(".${target.fileName}.${java.lang.Long.toHexString(random.nextLong())}.tmp")
        try {
            if (posix()) Files.createFile(tmp, PosixFilePermissions.asFileAttribute(FILE_PERMS))
            else Files.createFile(tmp)
            FileChannel.open(tmp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING).use { ch ->
                val buf = java.nio.ByteBuffer.wrap(bytes)
                while (buf.hasRemaining()) ch.write(buf)
                ch.force(true)
            }
            try {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            runCatching { Files.deleteIfExists(tmp) }
        }
        restrict(target)
        // Make the rename itself durable where the platform allows opening a folder.
        if (posix()) runCatching { FileChannel.open(parent, StandardOpenOption.READ).use { it.force(true) } }
    }

    /** Overwrite [file] with zeros (best effort) and delete it. */
    fun wipe(file: Path) {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return
        if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            runCatching {
                val size = Files.size(file).coerceIn(0L, 64L * 1024 * 1024).toInt()
                FileChannel.open(file, StandardOpenOption.WRITE).use { ch ->
                    ch.write(java.nio.ByteBuffer.wrap(ByteArray(size)))
                    ch.force(true)
                }
            }
        }
        runCatching { Files.deleteIfExists(file) }
    }
}
