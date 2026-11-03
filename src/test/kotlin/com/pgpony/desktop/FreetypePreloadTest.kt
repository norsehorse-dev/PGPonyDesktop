// FreetypePreloadTest.kt
// PGPony Desktop 3.1.0 (#12): when a GUI launch starts itself again with the system libfreetype
// preloaded. The environment and the filesystem are passed in, so nothing depends on the machine.

package com.pgpony.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class FreetypePreloadTest {

    private fun elf(elfClass: Int, machine: Int): ByteArray = ByteArray(20).also {
        it[0] = 0x7F; it[1] = 'E'.code.toByte(); it[2] = 'L'.code.toByte(); it[3] = 'F'.code.toByte()
        it[4] = elfClass.toByte(); it[5] = 1
        it[18] = (machine and 0xFF).toByte(); it[19] = (machine shr 8).toByte()
    }

    private val x64 = elf(2, 0x3E)
    private val arm64 = elf(2, 0xB7)
    private val i386 = elf(1, 0x03)

    private val debian = mapOf(
        "/usr/lib/x86_64-linux-gnu/libfreetype.so.6" to x64,
        "/usr/lib/i386-linux-gnu/libfreetype.so.6" to i386
    )
    private val app = "/opt/pgpony/bin/PGPony.bin"

    private fun plan(
        env: Map<String, String> = emptyMap(),
        files: Map<String, ByteArray> = debian,
        osName: String = "Linux",
        arch: String = "amd64",
        appPath: String? = app,
        flatpak: Boolean = false,
        argv: List<String> = listOf("notes.asc")
    ) = FreetypePreload.plan(osName, arch, env::get, appPath, flatpak, argv, files::get)

    @Test
    fun aLaunchThatSkippedTheWrapperStartsAgainWithThePreload() {
        val p = plan()
        assertEquals(listOf(app, "notes.asc"), p?.command)
        assertEquals("/usr/lib/x86_64-linux-gnu/libfreetype.so.6", p?.ldPreload)
    }

    @Test
    fun anotherPreloadIsKeptAfterIt() {
        assertEquals(
            "/usr/lib/x86_64-linux-gnu/libfreetype.so.6:/usr/lib/libgtk3-nocsd.so.0",
            plan(env = mapOf("LD_PRELOAD" to "/usr/lib/libgtk3-nocsd.so.0"))?.ldPreload
        )
    }

    @Test
    fun theWrapperOrAppRunAlreadyPreloadedIt() {
        assertNull(plan(env = mapOf("LD_PRELOAD" to "/lib/x86_64-linux-gnu/libfreetype.so.6")))
        assertNull(plan(env = mapOf("LD_PRELOAD" to "/usr/lib/libfoo.so /usr/lib64/libfreetype.so.6.20.1")))
    }

    @Test
    fun theSecondLaunchNeverLoops() {
        assertNull(plan(env = mapOf(FreetypePreload.GUARD to "1")))
    }

    @Test
    fun itCanBeTurnedOff() {
        assertNull(plan(env = mapOf(FreetypePreload.OPT_OUT to "1")))
    }

    @Test
    fun onlyAnInstalledLinuxBuildOutsideFlatpak() {
        assertNull(plan(osName = "Mac OS X"))
        assertNull(plan(osName = "Windows 11"))
        assertNull(plan(flatpak = true))
        assertNull(plan(appPath = null), "a development run has no launcher to start again")
    }

    @Test
    fun aMultiarchI386CopyIsNeverPicked() {
        assertNull(plan(files = mapOf("/usr/lib/i386-linux-gnu/libfreetype.so.6" to i386, "/usr/lib/libfreetype.so.6" to i386)))
        assertNull(plan(files = emptyMap()), "no system libfreetype: carry on as before")
    }

    @Test
    fun armAndFedoraFindTheirs() {
        assertEquals(
            "/usr/lib/aarch64-linux-gnu/libfreetype.so.6",
            plan(arch = "aarch64", files = mapOf("/usr/lib/aarch64-linux-gnu/libfreetype.so.6" to arm64))?.ldPreload
        )
        assertEquals(
            "/usr/lib64/libfreetype.so.6",
            plan(files = mapOf("/usr/lib64/libfreetype.so.6" to x64, "/usr/lib/libfreetype.so.6" to i386))?.ldPreload
        )
    }

    @Test
    fun theSecondLaunchDoesNotInheritTheJpackageLauncherState() {
        val env = FreetypePreload.childEnvironment(
            mapOf("_JPACKAGE_LAUNCHER" to "12345", "HOME" to "/home/u", "LD_PRELOAD" to "/old.so"),
            "/usr/lib/x86_64-linux-gnu/libfreetype.so.6:/old.so"
        )
        assertNull(env["_JPACKAGE_LAUNCHER"], "with it set, the launcher hands its arguments to the JVM")
        assertEquals("/home/u", env["HOME"])
        assertEquals("/usr/lib/x86_64-linux-gnu/libfreetype.so.6:/old.so", env["LD_PRELOAD"])
        assertEquals("1", env[FreetypePreload.GUARD])
    }
}
