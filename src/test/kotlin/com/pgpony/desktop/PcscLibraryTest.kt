// PcscLibraryTest.kt
// PGPony Desktop 3.0.1 (#6): the libpcsclite javax.smartcardio is pointed at on Linux. The
// filesystem is passed in as a map of path to file header, so nothing here depends on the machine.

package com.pgpony.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PcscLibraryTest {

    /** The first 20 bytes of an ELF file: class (1 = 32-bit, 2 = 64-bit), little-endian, e_machine. */
    private fun elf(elfClass: Int, machine: Int): ByteArray = ByteArray(20).also {
        it[0] = 0x7F; it[1] = 'E'.code.toByte(); it[2] = 'L'.code.toByte(); it[3] = 'F'.code.toByte()
        it[4] = elfClass.toByte(); it[5] = 1
        it[18] = (machine and 0xFF).toByte(); it[19] = (machine shr 8).toByte()
    }

    private val x64 = elf(2, 0x3E)
    private val arm64 = elf(2, 0xB7)
    private val i386 = elf(1, 0x03)

    private fun fs(vararg files: Pair<String, ByteArray>): (String) -> ByteArray? = mapOf(*files)::get

    @Test
    fun fedoraGetsLib64() {
        assertEquals(
            "/usr/lib64/libpcsclite.so.1",
            PcscLibrary.choose("Linux", "amd64", fs("/usr/lib64/libpcsclite.so.1" to x64, "/usr/lib/libpcsclite.so.1" to i386))
        )
    }

    @Test
    fun debianGetsItsTripletDirectory() {
        assertEquals(
            "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1",
            PcscLibrary.choose("Linux", "amd64", fs("/usr/lib/x86_64-linux-gnu/libpcsclite.so.1" to x64))
        )
        assertEquals(
            "/usr/lib/aarch64-linux-gnu/libpcsclite.so.1",
            PcscLibrary.choose("Linux", "aarch64", fs("/usr/lib/aarch64-linux-gnu/libpcsclite.so.1" to arm64))
        )
    }

    @Test
    fun archGetsUsrLib() {
        assertEquals("/usr/lib/libpcsclite.so.1", PcscLibrary.choose("Linux", "amd64", fs("/usr/lib/libpcsclite.so.1" to x64)))
    }

    @Test
    fun aThirtyTwoBitOrForeignCopyIsPassedOver() {
        // A multilib /usr/lib holding only the 32-bit library, and an arm64 file on an x86_64 JVM.
        assertNull(PcscLibrary.choose("Linux", "amd64", fs("/usr/lib/libpcsclite.so.1" to i386)))
        assertNull(PcscLibrary.choose("Linux", "amd64", fs("/usr/lib64/libpcsclite.so.1" to arm64)))
    }

    @Test
    fun nothingFoundOrNotLinuxLeavesTheJdkAlone() {
        assertNull(PcscLibrary.choose("Linux", "amd64", fs()))
        assertNull(PcscLibrary.choose("Mac OS X", "aarch64", fs("/usr/lib64/libpcsclite.so.1" to arm64)))
        assertNull(PcscLibrary.choose("Windows 11", "amd64", fs("/usr/lib64/libpcsclite.so.1" to x64)))
        assertNull(PcscLibrary.choose("Linux", "riscv64", fs("/usr/lib64/libpcsclite.so.1" to x64)))
    }

    @Test
    fun headerCheck() {
        assertTrue(PcscLibrary.matches(x64, 0x3E))
        assertFalse(PcscLibrary.matches(x64, 0xB7))
        assertFalse(PcscLibrary.matches(i386, 0x3E))
        assertFalse(PcscLibrary.matches("not an elf file at all".toByteArray(), 0x3E))
        assertFalse(PcscLibrary.matches(ByteArray(4), 0x3E))
    }
}
