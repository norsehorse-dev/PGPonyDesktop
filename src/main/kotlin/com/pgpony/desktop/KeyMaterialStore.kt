// KeyMaterialStore.kt
// PGPony Desktop — armored key material at rest (D2a).
//
// The desktop counterpart of Android's SecureKeyStore, holding the actual key blocks while Room
// holds metadata. D0-3 "GnuPG posture": one armored file per half under <dataDir>/keys/, mode
// 0600 where the filesystem supports it. Secret blocks keep their own S2K protection exactly as
// imported — this store adds no crypto of its own, so there is nothing here to lose or leak
// beyond what the armor itself protects.

package com.pgpony.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions

class KeyMaterialStore(private val dir: Path) {

    init {
        Files.createDirectories(dir)
        restrictToOwner(dir, directory = true)
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

    private fun write(file: Path, armored: String) {
        Files.writeString(file, armored)
        restrictToOwner(file)
    }

    private fun readOrNull(file: Path): String? =
        if (Files.exists(file)) Files.readString(file) else null

    private fun norm(fingerprint: String) = fingerprint.lowercase()

    private fun restrictToOwner(path: Path, directory: Boolean = false) {
        runCatching {
            val perms = if (directory) "rwx------" else "rw-------"
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(perms))
        }
    }
}
