// GpgInteropTest.kt
// D5 — the desktop-local gpg harness: the adb-free version of the Android interop loop.
// Gated exactly like the vendored harnesses (-DrunInterop=true); finds gpg on the usual paths
// or via -Dpgpony.gpg=/path/to/gpg, and runs every call inside a throwaway GNUPGHOME.
//
// Directions asserted HARD are the ones the 4.0.0 cycle validated (SCOPE_2b docs):
//   · classic v4: both directions, including gpg reporting "Good signature" on ours
//   · LibrePGP composite (algo 8): gpg 2.5.x encrypts to our key → we decrypt
// Deliberately absent, with reasons:
//   · gpg-decrypts-our-composite-secret — the upstream PLANNING_4_1_0 §1 blocker (gpg cannot
//     import ANY standard-form algo-8 secret).
//   · v6 (RFC 9580) vs gpg — GnuPG does not implement RFC 9580 v6 (the LibrePGP split); the
//     app's v6 interop story runs through Sequoia/SOP tools by design (docs/
//     V6_INTEROP_MATRIX.md). The v6 case here therefore drives `sqop` (matrix rows A+B),
//     skipping when it isn't installed.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.SigningService
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit

class GpgInteropTest {

    private lateinit var gpg: String
    private lateinit var home: Path

    @Before
    fun gate() {
        assumeTrue(
            "manual interop harness — run with -DrunInterop=true",
            System.getProperty("runInterop") == "true"
        )
        // Discovery order: explicit -Dpgpony.gpg, then the SHELL's gpg (the one manual
        // validation used — the test JVM inherits the terminal PATH), then fixed paths.
        val bin = System.getProperty("pgpony.gpg")
            ?: shellWhich("gpg")
            ?: sequenceOf(
                "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg",
                "/usr/local/MacGPG2/bin/gpg2"
            ).firstOrNull { File(it).canExecute() }
        assumeTrue("gpg not found — set -Dpgpony.gpg=/path/to/gpg", bin != null)
        gpg = bin!!
        // SHORT GNUPGHOME: macOS unix-socket paths cap at 104 bytes, and the default
        // /var/folders/… temp dir puts S.gpg-agent.* right at the limit — which silently
        // breaks the agent and with it secret-key import. /tmp keeps it far under.
        home = runCatching { Files.createTempDirectory(Path.of("/tmp"), "pg-gh") }
            .getOrElse { Files.createTempDirectory("pg-gh") }
        runCatching {
            Files.setPosixFilePermissions(home, PosixFilePermissions.fromString("rwx------"))
        }
        val version = runGpg("--version").stdout.toString(Charsets.UTF_8).lineSequence().firstOrNull()
        println("GpgInteropTest → $gpg ($version), GNUPGHOME=$home")
    }

    private data class GpgResult(val code: Int, val stdout: ByteArray, val stderr: String)

    /** Generic tool runner — small stdin payloads only (single pipe-buffer write). */
    private fun exec(
        cmd: List<String>,
        stdin: ByteArray? = null,
        env: Map<String, String> = emptyMap()
    ): GpgResult {
        val p = ProcessBuilder(cmd).apply { environment().putAll(env) }.start()
        stdin?.let { p.outputStream.write(it) }
        p.outputStream.close()
        val out = p.inputStream.readBytes()
        val err = p.errorStream.readBytes().toString(Charsets.UTF_8)
        assertTrue("timed out: ${cmd.joinToString(" ")}", p.waitFor(60, TimeUnit.SECONDS))
        return GpgResult(p.exitValue(), out, err)
    }

    private fun shellWhich(name: String): String? = runCatching {
        val p = ProcessBuilder("/bin/sh", "-c", "command -v $name").start()
        if (p.waitFor(5, TimeUnit.SECONDS))
            p.inputStream.readBytes().toString(Charsets.UTF_8).trim().ifBlank { null }
        else null
    }.getOrNull()

    private fun runGpg(vararg args: String, stdin: ByteArray? = null): GpgResult = exec(
        listOf(gpg, "--batch", "--yes", "--no-tty", "--pinentry-mode", "loopback", "--trust-model", "always") + args,
        stdin = stdin,
        env = mapOf("GNUPGHOME" to home.toString())
    )

    private fun repo(): Pair<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository> {
        val dir = Files.createTempDirectory("pgpony-gpg-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    private fun roundTrip(algorithm: KeyAlgorithm, email: String) = runBlocking {
        val (db, repo) = repo()
        val entity = repo.generateKey("Gpg RT", email, algorithm, "test-passphrase")

        val imp = runGpg("--import", stdin = repo.exportArmoredPrivateKey(entity.fingerprint)!!.toByteArray())
        assertEquals("gpg --import failed: ${imp.stderr}", 0, imp.code)

        // gpg → desktop
        val enc = runGpg("--armor", "--encrypt", "--recipient", email, stdin = "hello from gpg".toByteArray())
        assertEquals("gpg --encrypt failed: ${enc.stderr}", 0, enc.code)
        val dec = repo.decryptText(String(enc.stdout, Charsets.UTF_8), "test-passphrase")
        assertEquals("hello from gpg", dec.plaintext)

        // desktop (signed) → gpg
        val armored = repo.encryptText(
            "hello from desktop",
            listOf(repo.loadPublicKeyRing(entity.fingerprint)!!),
            repo.loadSecretKeyRing(entity.fingerprint),
            "test-passphrase"
        )
        val gdec = runGpg("--passphrase", "test-passphrase", "--decrypt", stdin = armored.toByteArray())
        assertEquals("gpg --decrypt failed: ${gdec.stderr}", 0, gdec.code)
        assertEquals("hello from desktop", String(gdec.stdout, Charsets.UTF_8))
        assertTrue("gpg should report a good signature:\n${gdec.stderr}", gdec.stderr.contains("Good signature"))
        db.close()
    }

    @Test
    fun classicV4BothDirectionsWithGpg() = roundTrip(KeyAlgorithm.ED25519_CV25519, "gpg-v4@pgpony.app")

    /**
     * v6 belongs to the SOP lane, not gpg (see header). Matrix rows A+B against sqop:
     * sqop encrypts to a desktop v6 cert → desktop decrypts; desktop encrypts to a
     * sqop-generated rfc9580 key → sqop decrypts.
     */
    @Test
    fun v6RoundTripWithSopTool() = runBlocking {
        val sop = shellWhich("sqop")
        assumeTrue(
            "sqop not found — install sequoia's sqop to run the v6 SOP lane " +
                "(v6-vs-gpg is intentionally absent: GnuPG does not implement RFC 9580)",
            sop != null
        )
        val (db, repo) = repo()
        val work = Files.createTempDirectory("pgpony-sop")

        // Row A: tool encrypts → desktop decrypts.
        val entity = repo.generateKey("Sop V6", "sop-v6@pgpony.app", KeyAlgorithm.V6_ED25519, "test-passphrase")
        val certFile = work.resolve("pgpony.cert")
        Files.writeString(certFile, repo.exportArmoredPublicKey(entity.fingerprint)!!)
        val enc = exec(listOf(sop!!, "encrypt", certFile.toString()), stdin = "hello from sop".toByteArray())
        assertEquals("sqop encrypt failed: ${enc.stderr}", 0, enc.code)
        val dec = repo.decryptText(String(enc.stdout, Charsets.UTF_8), "test-passphrase")
        assertEquals("hello from sop", dec.plaintext)

        // Row B: desktop encrypts → tool decrypts.
        val gen = exec(listOf(sop, "generate-key", "--profile", "rfc9580", "SOP Tester <sop@example.org>"))
        assertEquals("sqop generate-key failed: ${gen.stderr}", 0, gen.code)
        val tskFile = work.resolve("sop.tsk"); Files.write(tskFile, gen.stdout)
        val cert = exec(listOf(sop, "extract-cert"), stdin = gen.stdout)
        assertEquals("sqop extract-cert failed: ${cert.stderr}", 0, cert.code)
        val report = repo.importArmoredText(String(cert.stdout, Charsets.UTF_8))
        assertEquals("SOP cert should import", 1, report.inserted)
        val sopKey = repo.allKeys().first { it.userEmail == "sop@example.org" }
        val armored = repo.encryptText(
            "hello from desktop v6",
            listOf(repo.loadPublicKeyRing(sopKey.fingerprint)!!),
            null, null
        )
        val sdec = exec(listOf(sop, "decrypt", tskFile.toString()), stdin = armored.toByteArray())
        assertEquals("sqop decrypt failed: ${sdec.stderr}", 0, sdec.code)
        assertEquals("hello from desktop v6", String(sdec.stdout, Charsets.UTF_8))
        db.close()
    }

    @Test
    fun librePgpCompositeGpgEncryptsDesktopDecrypts() = runBlocking {
        val (db, repo) = repo()
        val entity = repo.generateKey(
            "Gpg PQC", "gpg-pqc@pgpony.app", KeyAlgorithm.MLKEM768_X25519_LIBREPGP, "test-passphrase"
        )
        // Public HALF only — the algo-8 secret import into gpg is the §1 upstream blocker.
        val imp = runGpg("--import", stdin = repo.exportArmoredPublicKey(entity.fingerprint)!!.toByteArray())
        assertEquals("gpg --import (composite public) failed: ${imp.stderr}", 0, imp.code)

        val enc = runGpg(
            "--armor", "--encrypt", "--recipient", "gpg-pqc@pgpony.app",
            stdin = "quantum-resistant hello".toByteArray()
        )
        assertEquals("gpg --encrypt to algo-8 failed: ${enc.stderr}", 0, enc.code)
        val dec = repo.decryptText(String(enc.stdout, Charsets.UTF_8), "test-passphrase")
        assertEquals("quantum-resistant hello", dec.plaintext)
        db.close()
    }

    @Test
    fun desktopDetachedSignatureVerifiesInGpg() = runBlocking {
        val (db, repo) = repo()
        val entity = repo.generateKey("Gpg Sig", "gpg-sig@pgpony.app", KeyAlgorithm.ED25519_CV25519, "test-passphrase")
        runGpg("--import", stdin = repo.exportArmoredPublicKey(entity.fingerprint)!!.toByteArray())

        val content = home.resolve("artifact.bin")
        Files.write(content, ByteArray(10_000) { (it % 251).toByte() })
        val sig = home.resolve("artifact.bin.asc")
        Files.write(
            sig,
            SigningService.shared.signDetached(
                Files.readAllBytes(content),
                repo.loadSecretKeyRing(entity.fingerprint)!!,
                "test-passphrase"
            )
        )

        val verify = runGpg("--verify", sig.toString(), content.toString())
        assertEquals("gpg --verify failed: ${verify.stderr}", 0, verify.code)
        assertTrue("gpg should report a good signature:\n${verify.stderr}", verify.stderr.contains("Good signature"))
        db.close()
    }
}
