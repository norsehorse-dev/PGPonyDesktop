// PcscLibrary.kt
// PGPony Desktop 3.0.1 (#6): which libpcsclite javax.smartcardio loads on Linux.
//
// Left to itself, the JDK picks the PC/SC client library by its own search, which looks for the
// unversioned development name (libpcsclite.so) in a fixed list of directories. That is not the
// file the system's own PC/SC tools run against, which is the runtime library by its soname,
// libpcsclite.so.1. In #6 (Fedora 44, pcsc-lite 2.4.1) the default search left PGPony unable to
// see a working YubiKey while pcscd logged "Communication protocol mismatch", and pointing the JDK
// at /usr/lib64/libpcsclite.so.1 fixed it.
//
// So on Linux, unless the property is already set (on the command line, through
// JAVA_TOOL_OPTIONS, or by Flatpak.apply for the sandbox's own copy), the JDK is pointed at the
// first libpcsclite.so.1 in the distribution library directories that is a 64-bit ELF file for
// this JVM's architecture. Checking the ELF header keeps a 32-bit or foreign-architecture copy
// (a multilib /usr/lib on Fedora, for one) from being chosen. When none matches, nothing is set
// and the JDK's own search runs as it did before.
//
// The JDK reads the property once, when javax.smartcardio first loads, so Main calls apply()
// before any other code runs.

package com.pgpony.desktop

import java.io.File
import java.io.RandomAccessFile

object PcscLibrary {

    const val PROPERTY = "sun.security.smartcardio.library"
    private const val SONAME = "libpcsclite.so.1"

    /** ELF e_machine for a JVM architecture, or null for one PGPony does not ship. */
    internal fun machine(arch: String): Int? = when (arch.lowercase()) {
        "amd64", "x86_64" -> 0x3E
        "aarch64", "arm64" -> 0xB7
        else -> null
    }

    /** Where distributions put the runtime library, most specific first. */
    internal fun candidates(arch: String): List<String> {
        val triplet = when (machine(arch)) {
            0x3E -> "x86_64-linux-gnu"
            0xB7 -> "aarch64-linux-gnu"
            else -> null
        }
        val dirs = buildList {
            add("/usr/lib64")                                  // Fedora, openSUSE, RHEL
            if (triplet != null) {
                add("/usr/lib/$triplet")                       // Debian, Ubuntu
                add("/lib/$triplet")
            }
            add("/usr/lib")                                    // Arch
            add("/usr/local/lib64")
            add("/usr/local/lib")
        }
        return dirs.map { "$it/$SONAME" }
    }

    /** True when [header] (the first 20 bytes of a file) is a 64-bit ELF file for [machine]. */
    internal fun matches(header: ByteArray, machine: Int): Boolean {
        if (header.size < 20) return false
        if (header[0] != 0x7F.toByte() || header[1] != 'E'.code.toByte() ||
            header[2] != 'L'.code.toByte() || header[3] != 'F'.code.toByte()
        ) return false
        if (header[4].toInt() != 2) return false               // ELFCLASS64
        val lo = header[18].toInt() and 0xFF
        val hi = header[19].toInt() and 0xFF
        val found = if (header[5].toInt() == 1) lo or (hi shl 8) else (lo shl 8) or hi
        return found == machine
    }

    /** The library to use, or null to leave the JDK's own search alone. */
    internal fun choose(osName: String, arch: String, readHeader: (String) -> ByteArray?): String? {
        if (!osName.lowercase().startsWith("linux")) return null
        val machine = machine(arch) ?: return null
        return candidates(arch).firstOrNull { path -> readHeader(path)?.let { matches(it, machine) } == true }
    }

    private fun header(path: String): ByteArray? = runCatching {
        val file = File(path)
        if (!file.isFile) null
        else RandomAccessFile(file, "r").use { r -> ByteArray(20).also { r.readFully(it) } }
    }.getOrNull()

    /** Point javax.smartcardio at the system's runtime library. A no-op off Linux, under Flatpak, or when already set. */
    fun apply() {
        if (System.getProperty(PROPERTY) != null || Flatpak.active) return
        val lib = choose(System.getProperty("os.name") ?: "", System.getProperty("os.arch") ?: "", ::header) ?: return
        System.setProperty(PROPERTY, lib)
    }
}
