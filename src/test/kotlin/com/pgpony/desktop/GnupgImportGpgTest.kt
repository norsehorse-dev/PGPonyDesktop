// GnupgImportGpgTest.kt
// Import from GnuPG with a real gpg: which folders gpg runs against, what configuration it
// reads, per-user-ID trust, a stale trust database, disabled keys, and the gpg-agent that the
// import starts being stopped again. Skipped when no gpg is installed. Every GnuPG home is a
// throwaway directory under /tmp (short, for the agent's socket path).

package com.pgpony.desktop

import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GnupgImportGpgTest {

    private val homes = mutableListOf<Path>()
    private var gpg: String? = null

    private fun requireGpg(): String {
        val found = GnupgImport.locateGpg()?.path?.toString()
        assumeTrue("gpg is not installed", found != null && !GnupgImport.sandboxed())
        gpg = found
        return found!!
    }

    private fun newHome(name: String): Path {
        val base = runCatching { Files.createTempDirectory(Path.of("/tmp"), "pgh") }.getOrElse { Files.createTempDirectory("pgh") }
        val h = Files.createDirectories(base.resolve(name))
        runCatching { Files.setPosixFilePermissions(h, PosixFilePermissions.fromString("rwx------")) }
        homes.add(h)
        return h
    }

    private fun run(cmd: List<String>, stdin: ByteArray = ByteArray(0)): ByteArray {
        val p = ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.DISCARD).start()
        p.outputStream.use { it.write(stdin) }
        val out = p.inputStream.readBytes()
        assertTrue(p.waitFor(60, TimeUnit.SECONDS), "timed out: $cmd")
        return out
    }

    /** gpg for setting a home up, with no passphrases and no automatic trustdb check. */
    private fun g(home: Path, vararg args: String, stdin: ByteArray = ByteArray(0)): ByteArray =
        run(
            listOf(gpg!!, "--homedir", home.toString(), "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase=", "--no-auto-check-trustdb") + args,
            stdin
        )

    private fun newKey(home: Path, uid: String): String {
        g(home, "--quick-gen-key", uid, "future-default", "default", "0")
        return String(g(home, "--with-colons", "--list-keys", uid)).lineSequence()
            .first { it.startsWith("fpr:") }.split(':')[9]
    }

    private fun connectAgent(home: Path): Path? =
        Path.of(gpg!!).parent?.resolve("gpg-connect-agent")?.takeIf { Files.isExecutable(it) }

    private fun agentRunning(home: Path): Boolean {
        val tool = connectAgent(home) ?: return false
        return String(run(listOf(tool.toString(), "--homedir", home.toString(), "--no-autostart", "GETINFO pid", "/bye")))
            .lineSequence().any { it.startsWith("D ") }
    }

    private fun stopAgent(home: Path) {
        val tool = connectAgent(home) ?: return
        run(listOf(tool.toString(), "--homedir", home.toString(), "--no-autostart", "KILLAGENT", "/bye"))
        repeat(20) { if (agentRunning(home)) Thread.sleep(100) }
    }

    /** A gpg.conf naming a program gpg would start, and the file that program would create. */
    private fun plantAgentProgram(home: Path): Path {
        val marker = home.parent.resolve("agent-program-ran")
        val script = home.parent.resolve("agent.sh")
        Files.writeString(script, "#!/bin/sh\ntouch '$marker'\nexit 1\n")
        script.toFile().setExecutable(true)
        Files.writeString(home.resolve("gpg.conf"), "agent-program $script\n")
        return marker
    }

    private fun snapshot(dir: Path): Map<String, Pair<Long, Long>> =
        Files.walk(dir).use { s ->
            s.filter { Files.isRegularFile(it) || Files.isDirectory(it) }.toList()
                .associate { dir.relativize(it).toString() to (Files.getLastModifiedTime(it).toMillis() to (if (Files.isRegularFile(it)) Files.size(it) else -1L)) }
        }

    @AfterTest
    fun cleanUp() {
        GnupgImport.defaultHomeOverride = null
        if (gpg != null) homes.forEach { runCatching { stopAgent(it) } }
        homes.forEach { h -> runCatching { h.parent.toFile().deleteRecursively() } }
    }

    @Test
    fun gnupg1And7APickedFolderIsOnlyRead() = runBlocking {
        requireGpg()
        val picked = newHome("picked")
        val fp = newKey(picked, "Someone <someone@example.org>")
        stopAgent(picked)
        val marker = plantAgentProgram(picked)
        GnupgImport.defaultHomeOverride = newHome("mine")
        val before = snapshot(picked)

        val repoDir = Files.createTempDirectory("pgpony-gnupg-gpg")
        val db = Db.open(repoDir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(repoDir.resolve("keys")))
        val scan = GnupgImport.scan(picked)
        assertNull(scan.gpg)
        val result = GnupgImport.import(repo, scan, withTrust = true, withSecrets = true)
        assertEquals(1, result.report.inserted)
        assertNotNull(repo.byFingerprint(fp))
        assertFalse(Files.exists(marker), "nothing from the folder's gpg.conf ran")
        assertFalse(agentRunning(picked), "no agent was started for the folder")
        assertEquals(before, snapshot(picked), "the folder is unchanged")
        db.close()
    }

    @Test
    fun theOwnHomeGoesThroughGpgWithPerUserIdTrust() = runBlocking {
        requireGpg()
        val home = newHome("own")
        val mallory = newHome("mallory")
        val bob = newHome("bob")
        val dave = newHome("dave")
        val mine = newKey(home, "Mine <mine@example.org>")
        val mFp = newKey(mallory, "Mallory <mallory@example.org>")
        val bFp = newKey(bob, "Bob <bob@example.org>")
        val dFp = newKey(dave, "Dave <dave@example.org>")
        for (other in listOf(mallory, bob, dave)) g(home, "--import", stdin = g(other, "--export"))
        for (fp in listOf(mFp, bFp, dFp)) g(home, "--quick-sign-key", fp)
        g(home, "--check-trustdb")
        // gnupg2: Mallory adds an identity nobody certified and makes it primary.
        g(mallory, "--quick-add-uid", mFp, "Alice <alice@corp.example>")
        g(mallory, "--quick-set-primary-uid", mFp, "Alice <alice@corp.example>")
        g(home, "--import", stdin = g(mallory, "--export"))
        // gnupg5: Dave is fully valid but disabled.
        g(home, "--edit-key", dFp, "disable", "quit")
        listOf(home, mallory, bob, dave).forEach { stopAgent(it) }
        val marker = plantAgentProgram(home)
        GnupgImport.defaultHomeOverride = home

        val scan = GnupgImport.scan(home)
        assertTrue(scan.isDefault)
        assertNotNull(scan.gpg, "gpg is offered for the own home")
        assertEquals("", scan.gpg!!.version, "gnupg8: located, not run")

        // gnupg4: the import of Mallory's new user ID left the trust database due for a check.
        val stalePlan = GnupgImport.prepare(scan)
        assertFalse(stalePlan.validityUsable)
        assertFalse(agentRunning(home), "gnupg7: the agent the scan needed was stopped again")

        stopAgent(home)
        Files.delete(home.resolve("gpg.conf"))
        g(home, "--check-trustdb")
        stopAgent(home)
        plantAgentProgram(home)

        val plan = GnupgImport.prepare(scan)
        assertTrue(plan.validityUsable)
        assertEquals(4, plan.keys.size)
        assertEquals(2, plan.notes.size, "one note for Mallory, one for Dave: ${plan.notes}")
        assertEquals(listOf(mine), plan.secretKeys.map { it.fingerprint })
        assertTrue(plan.notes.any { it.contains("Alice") || it == "d_gnupg_note_uids" }, "gnupg2: Mallory is named: ${plan.notes}")
        assertTrue(plan.notes.any { it.contains("Dave") || it == "d_gnupg_note_disabled" }, "gnupg5: Dave is named: ${plan.notes}")

        val repoDir = Files.createTempDirectory("pgpony-gnupg-gpg")
        val db = Db.open(repoDir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(repoDir.resolve("keys")))
        val preview = GnupgImport.trustPreview(repo, plan, withSecrets = true).associate { it.fingerprint to it.to }
        assertEquals(mapOf(mine to TrustLevel.ULTIMATE, bFp to TrustLevel.VERIFIED), preview)
        assertEquals(mapOf(mine to TrustLevel.VERIFIED, bFp to TrustLevel.VERIFIED),
            GnupgImport.trustPreview(repo, plan, withSecrets = false).associate { it.fingerprint to it.to },
            "without the secret, the own key is not Ultimate")

        val result = GnupgImport.apply(repo, plan, withTrust = true, withSecrets = true)
        assertEquals(1, result.secretsImported, "notes: ${result.notes}")
        assertEquals(TrustLevel.ULTIMATE, repo.byFingerprint(mine)!!.trustLevel)
        assertEquals(TrustLevel.VERIFIED, repo.byFingerprint(bFp)!!.trustLevel)
        assertFalse(repo.byFingerprint(mFp)!!.trustLevel.ordinal >= TrustLevel.VERIFIED.ordinal, "gnupg2")
        assertFalse(repo.byFingerprint(dFp)!!.trustLevel.ordinal >= TrustLevel.VERIFIED.ordinal, "gnupg5")

        assertFalse(Files.exists(marker), "gnupg1: gpg.conf was not read")
        assertFalse(agentRunning(home), "gnupg7: no agent left running")
        db.close()
    }

    @Test
    fun gnupg7AnAgentThatWasAlreadyRunningIsLeftAlone() = runBlocking {
        requireGpg()
        val home = newHome("running")
        newKey(home, "Runner <runner@example.org>")
        g(home, "--list-secret-keys")
        assumeTrue("gpg-connect-agent is not installed", connectAgent(home) != null)
        assertTrue(agentRunning(home))
        GnupgImport.defaultHomeOverride = home
        GnupgImport.prepare(GnupgImport.scan(home))
        assertTrue(agentRunning(home), "the user's own agent keeps running")
    }
}
