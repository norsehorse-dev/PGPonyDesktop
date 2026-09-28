// ZipTransport.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4c (plan section 7; Android 4.3.0 #31, 4.4.1 audit
// item 9). The desktop port of Android's ZipPackaging (app layer, so not vendored).
//
// A .zip here is transport packaging, not encryption: it wraps an already encrypted .gpg or .asc
// so a channel that mangles those extensions (some mail and chat services) still delivers the
// ciphertext intact. One entry, streamed both ways, so a large file is never held in memory.
//
// Reading is bounded the way Android 4.6.0 bounds it: an entry count cap and a payload size cap,
// so a small crafted archive cannot fill the disk before any OpenPGP limit applies. Entry names
// are reduced to a plain base name on write and on read, so nothing lands outside the folder.
// A zip with no PGP entry, or with several, is reported rather than guessed at.

package com.pgpony.desktop

import com.pgpony.android.crypto.LiteralFilename
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.SecurityLimits
import com.pgpony.android.data.settings.SettingsStores
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

object ZipTransport {

    /** PGP ciphertext extensions recognized as the payload inside a zip. */
    private val PGP_EXTENSIONS = listOf(".gpg", ".pgp", ".asc")

    const val ZIP_SUFFIX = ".zip"

    /** Android's key, so the choice reads the same wherever the settings are shared. */
    private const val KEY_WRAP = "wrap_output_in_zip"

    /** Whether the Files encrypt option starts on (remembered, as on Android). */
    fun wrapByDefault(): Boolean = SettingsStores.open()?.getBoolean(KEY_WRAP, false) ?: false

    fun setWrapByDefault(value: Boolean) {
        SettingsStores.open()?.putBoolean(KEY_WRAP, value)
    }

    /** True when [prefix] starts with the local-file-header magic (PK 03 04). */
    fun looksLikeZip(prefix: ByteArray): Boolean =
        prefix.size >= 4 && prefix[0] == 0x50.toByte() && prefix[1] == 0x4B.toByte() &&
            prefix[2] == 0x03.toByte() && prefix[3] == 0x04.toByte()

    fun looksLikeZip(file: Path): Boolean = runCatching {
        Files.newInputStream(file).use { looksLikeZip(it.readNBytes(4)) }
    }.getOrDefault(false)

    /** The name an entry is written under: a plain base name, never a path. */
    fun safeEntryName(name: String?): String = LiteralFilename.sanitize(name) ?: "encrypted.gpg"

    fun isPgpEntryName(name: String): Boolean = PGP_EXTENSIONS.any { name.lowercase().endsWith(it) }

    /**
     * Write one entry named [entryName] into [sink], its bytes from [body], and finish the
     * archive. Does not close [sink]; the caller owns it.
     */
    fun writeSingleEntry(sink: OutputStream, entryName: String, body: (OutputStream) -> Unit) {
        val zip = ZipOutputStream(sink)
        zip.putNextEntry(ZipEntry(safeEntryName(entryName)))
        body(zip)
        zip.closeEntry()
        zip.finish()
        zip.flush()
    }

    /** Copy [input] to [out], refusing past [max] bytes. Returns the bytes copied. */
    fun copyToCapped(input: InputStream, out: OutputStream, max: Long = SecurityLimits.MAX_ZIP_PAYLOAD_BYTES): Long {
        val buf = ByteArray(DEFAULT_BUFFER_SIZE)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) return total
            total += n
            if (total > max) throw PGPCryptoError.ResourceLimitExceeded("zip entry larger than $max bytes")
            out.write(buf, 0, n)
        }
    }

    /** Counts entries as a scan walks an archive, refusing past the cap. */
    class EntryBudget(private val max: Int = SecurityLimits.MAX_ZIP_ENTRIES) {
        private var seen = 0
        fun next() {
            if (++seen > max) throw PGPCryptoError.ResourceLimitExceeded("zip has more than $max entries")
        }
    }

    /** What a zip held. */
    sealed interface Found {
        /** Exactly one PGP entry; its bytes went to the output. [name] is a safe base name. */
        class One(val name: String) : Found
        data object None : Found
        data object Several : Found
    }

    /**
     * Scan [source] (streamed) and copy its PGP entry into [out] when there is exactly one.
     * With none or several, what reached [out] must be discarded by the caller. Closes neither.
     */
    fun extractSinglePgpEntry(
        source: InputStream,
        out: OutputStream,
        max: Long = SecurityLimits.MAX_ZIP_PAYLOAD_BYTES
    ): Found {
        val zip = ZipInputStream(source)
        val budget = EntryBudget()
        var count = 0
        var name: String? = null
        var e: ZipEntry? = zip.nextEntry
        while (e != null) {
            budget.next()
            if (!e.isDirectory && isPgpEntryName(e.name)) {
                count++
                if (name == null) {
                    name = safeEntryName(e.name)
                    copyToCapped(zip, out, max)
                }
            }
            zip.closeEntry()
            e = zip.nextEntry
        }
        return when {
            name == null -> Found.None
            count > 1 -> Found.Several
            else -> Found.One(name)
        }
    }

    /** How many PGP entries [source] holds (the file router's question). Closes nothing. */
    fun pgpEntryCount(source: InputStream): Int {
        val zip = ZipInputStream(source)
        val budget = EntryBudget()
        var count = 0
        var e: ZipEntry? = zip.nextEntry
        while (e != null) {
            budget.next()
            if (!e.isDirectory && isPgpEntryName(e.name)) count++
            zip.closeEntry()
            e = zip.nextEntry
        }
        return count
    }
}
