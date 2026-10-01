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

    fun storePublic(fingerprint: String, armored: String) = write(pubFile(fingerprint), armored)
    fun storeSecret(fingerprint: String, armored: String) = write(secFile(fingerprint), armored)

    fun loadPublic(fingerprint: String): String? = readOrNull(pubFile(fingerprint))
    fun loadSecret(fingerprint: String): String? = readOrNull(secFile(fingerprint))

    fun hasSecret(fingerprint: String): Boolean = Files.exists(secFile(fingerprint))

    fun delete(fingerprint: String) {
        Files.deleteIfExists(pubFile(fingerprint))
        Files.deleteIfExists(secFile(fingerprint))
    }

    private fun write(file: Path, armored: String) = OwnerOnlyPaths.writeAtomically(file, armored.toByteArray(Charsets.UTF_8))

    private fun readOrNull(file: Path): String? =
        if (Files.exists(file)) Files.readString(file) else null

    private fun norm(fingerprint: String) = fingerprint.lowercase()
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
