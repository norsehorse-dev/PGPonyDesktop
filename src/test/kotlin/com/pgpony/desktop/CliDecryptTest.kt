// CliDecryptTest.kt
// 3.0.0: `pgpony decrypt` holds its output until the message passed every check, writes it
// owner-only, never through a link, leaves nothing behind on failure, and exits non-zero on a
// bad signature; key-derived text reaches the terminal with control characters escaped
// (FILES-1, ENGINE-5, ENGINE-2, LOCAL-IPC-1, LOCAL-IPC-2).

package com.pgpony.desktop

import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CliDecryptTest {

    private class Run(val code: Int, val out: ByteArray, val err: String)

    private fun cli(repo: DesktopKeyRepository, vararg args: String, stdin: ByteArray = ByteArray(0)): Run {
        val oldOut = System.out
        val oldErr = System.err
        val oldIn = System.`in`
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        Cli.repoOverride = repo
        System.setOut(PrintStream(out, true))
        System.setErr(PrintStream(err, true))
        System.setIn(ByteArrayInputStream(stdin))
        try {
            val code = Cli.run(arrayOf(*args))
            return Run(code, out.toByteArray(), err.toString(Charsets.UTF_8))
        } finally {
            System.setOut(oldOut)
            System.setErr(oldErr)
            System.setIn(oldIn)
            Cli.repoOverride = null
        }
    }

    @AfterTest fun reset() { Cli.repoOverride = null }

    private fun names(dir: Path): Set<String> = Files.list(dir).use { s -> s.map { it.fileName.toString() }.toList() }.toSet()

    @Test
    fun aGoodMessageIsWrittenOwnerOnlyAndExitsZero() = runBlocking {
        val env = B1Fixtures.env()
        val me = B1Fixtures.key(env.repo, "Me")
        env.repo.updateTrustLevel(me.fingerprint, com.pgpony.android.data.TrustLevel.ULTIMATE)
        val msg = env.dir.resolve("m.gpg")
        Files.write(
            msg,
            B1Fixtures.encrypt(
                B1Fixtures.pub(env.repo, me.fingerprint), "hello".toByteArray(), "m.txt", armor = false,
                signer = B1Fixtures.sec(env.repo, me.fingerprint)
            )
        )
        val box = Files.createDirectories(env.dir.resolve("out"))
        val r = cli(env.repo, "decrypt", "-o", box.resolve("m.txt").toString(), msg.toString())
        assertEquals(ExitCode.OK, r.code, r.err)
        assertEquals("hello", Files.readString(box.resolve("m.txt")))
        if (B1Fixtures.posix) assertEquals("rw-------", B1Fixtures.perms(box.resolve("m.txt")))
        assertTrue(r.err.contains("Good signature"), r.err)
        assertTrue(r.err.contains("Me <me@pgpony.app>"), "the signer is the key that verified: ${r.err}")
        assertEquals(setOf("m.txt"), names(box))

        val s = cli(env.repo, "decrypt", msg.toString())
        assertEquals(ExitCode.OK, s.code, s.err)
        assertEquals("hello", String(s.out))
        env.close()
    }

    @Test
    fun aBadSignatureExitsFour() = runBlocking {
        val env = B1Fixtures.env()
        val alice = B1Fixtures.key(env.repo, "Alice")
        val bob = B1Fixtures.key(env.repo, "Bob")
        val packets = B1Fixtures.signedParts(
            B1Fixtures.sec(env.repo, alice.fingerprint), "the content".toByteArray(), signedOver = "other content".toByteArray()
        )
        val msg = env.dir.resolve("bad.gpg")
        Files.write(msg, B1Fixtures.encryptRaw(packets, B1Fixtures.pub(env.repo, bob.fingerprint)))

        val r = cli(env.repo, "decrypt", msg.toString())
        assertEquals(ExitCode.UNVERIFIED, r.code, r.err)
        assertTrue(r.err.contains("BAD signature"), r.err)
        assertEquals("the content", String(r.out), "written, as gpg does, with a non-zero exit")

        val box = Files.createDirectories(env.dir.resolve("req"))
        val q = cli(env.repo, "decrypt", "--require-signature", "-o", box.resolve("x").toString(), msg.toString())
        assertEquals(ExitCode.UNVERIFIED, q.code, q.err)
        assertEquals(emptySet(), names(box), "with --require-signature nothing is written")
        env.close()
    }

    @Test
    fun requireSignatureWithholdsAnUnsignedMessage() = runBlocking {
        val env = B1Fixtures.env()
        val me = B1Fixtures.key(env.repo, "Me")
        val msg = env.dir.resolve("u.gpg")
        Files.write(msg, B1Fixtures.encrypt(B1Fixtures.pub(env.repo, me.fingerprint), "unsigned".toByteArray(), "u", armor = false))
        val r = cli(env.repo, "decrypt", "--require-signature", msg.toString())
        assertEquals(ExitCode.UNVERIFIED, r.code, r.err)
        assertEquals(0, r.out.size, "nothing reaches stdout")
        val ok = cli(env.repo, "decrypt", msg.toString())
        assertEquals(ExitCode.OK, ok.code, ok.err)
        assertEquals("unsigned", String(ok.out))
        env.close()
    }

    @Test
    fun aMessageThatFailsItsChecksWritesNothingAndExitsThree() = runBlocking {
        val env = B1Fixtures.env()
        val alice = B1Fixtures.key(env.repo, "Alice")
        val bob = B1Fixtures.key(env.repo, "Bob")
        val bobPub = B1Fixtures.pub(env.repo, bob.fingerprint)
        val signed = B1Fixtures.signedParts(B1Fixtures.sec(env.repo, alice.fingerprint), "notes".toByteArray())
        val prefixed = B1Fixtures.encryptRaw(B1Fixtures.literal(ByteArray(200_000) { 'E'.code.toByte() }, "e") + signed, bobPub)
        val good = B1Fixtures.encrypt(bobPub, ByteArray(300_000) { 'p'.code.toByte() }, "p", armor = false)
        val tampered = good.copyOf().also { it[it.size - 30] = (it[it.size - 30].toInt() xor 1).toByte() }

        for ((label, bytes) in listOf("prefixed" to prefixed, "tampered" to tampered)) {
            val box = Files.createDirectories(env.dir.resolve(label))
            val msg = env.dir.resolve("$label.gpg").also { Files.write(it, bytes) }
            val toFile = cli(env.repo, "decrypt", "-o", box.resolve("out.txt").toString(), msg.toString())
            assertEquals(ExitCode.FAILED, toFile.code, "$label: ${toFile.err}")
            assertEquals(emptySet(), names(box), "$label: no output and no temp file")
            val toStdout = cli(env.repo, "decrypt", msg.toString())
            assertEquals(ExitCode.FAILED, toStdout.code, label)
            assertEquals(0, toStdout.out.size, "$label: nothing reached stdout")
            val fromStdin = cli(env.repo, "decrypt", stdin = bytes)
            assertEquals(ExitCode.FAILED, fromStdin.code, label)
            assertEquals(0, fromStdin.out.size, "$label: nothing reached stdout")
        }
        env.close()
    }

    @Test
    fun aLinkAtTheOutputPathIsReplacedNotFollowed() = runBlocking {
        val env = B1Fixtures.env()
        val me = B1Fixtures.key(env.repo, "Me")
        val msg = env.dir.resolve("m.gpg")
        Files.write(msg, B1Fixtures.encrypt(B1Fixtures.pub(env.repo, me.fingerprint), "fresh".toByteArray(), "m", armor = false))
        val target = env.dir.resolve("elsewhere.txt")
        val link = runCatching { Files.createSymbolicLink(env.dir.resolve("out.txt"), target) }.getOrNull()
            ?: return@runBlocking env.close()
        val r = cli(env.repo, "decrypt", "-o", link.toString(), msg.toString())
        assertEquals(ExitCode.OK, r.code, r.err)
        assertFalse(Files.exists(target, LinkOption.NOFOLLOW_LINKS), "nothing written through the link")
        assertFalse(Files.isSymbolicLink(link))
        assertEquals("fresh", Files.readString(link))
        env.close()
    }

    @Test
    fun aZippedMessageDecryptsFromStdinAndAFile() = runBlocking {
        val env = B1Fixtures.env()
        val me = B1Fixtures.key(env.repo, "Me")
        val enc = B1Fixtures.encrypt(B1Fixtures.pub(env.repo, me.fingerprint), "zipped".toByteArray(), "z", armor = false)
        val zip = ByteArrayOutputStream().also { bo -> ZipTransport.writeSingleEntry(bo, "z.gpg") { it.write(enc) } }.toByteArray()
        val zf = env.dir.resolve("z.zip").also { Files.write(it, zip) }
        assertEquals("zipped", String(cli(env.repo, "decrypt", zf.toString()).out))
        assertEquals("zipped", String(cli(env.repo, "decrypt", "-", stdin = zip).out))
        env.close()
    }

    @Test
    fun keyTextIsEscapedForTheTerminal() = runBlocking {
        assertEquals("Alice\\x1B[8m>\\u202E\\x0A\\x9B", Cli.safe("Alice\u001b[8m>‮\n\u009b"))
        assertEquals("plain é text", Cli.safe("plain é text"))
        assertEquals("line one\nline\\x1B two", Cli.terminalText("line one\nline\u001b two"))

        val env = B1Fixtures.env()
        env.repo.generateKey("Mallory\u001b[8m", "m@pgpony.app", com.pgpony.android.crypto.KeyAlgorithm.ED25519_CV25519, null)
        val r = cli(env.repo, "list-keys")
        assertEquals(ExitCode.OK, r.code)
        assertFalse(r.out.any { it == 0x1B.toByte() }, "no raw escape reaches the terminal")
        env.close()
    }

    @Test
    fun verifyReportsTheKeyThatVerified() = runBlocking {
        val env = B1Fixtures.env()
        val me = B1Fixtures.key(env.repo, "Signer")
        val data = env.dir.resolve("d.txt").also { Files.writeString(it, "signed data") }
        val sigOut = env.dir.resolve("d.txt.sig")
        val s = cli(env.repo, "sign", "-u", me.fingerprint, "-b", "-o", sigOut.toString(), data.toString())
        assertEquals(ExitCode.OK, s.code, s.err)
        val v = cli(env.repo, "verify", "-s", sigOut.toString(), data.toString())
        assertEquals(ExitCode.OK, v.code, v.err)
        val text = String(v.out)
        assertTrue(text.contains("Signer fingerprint: ${me.fingerprint.uppercase()}"), text)
        val strict = cli(env.repo, "verify", "--require-verified", "-s", sigOut.toString(), data.toString())
        assertEquals(ExitCode.UNVERIFIED, strict.code, "an unverified signer fails --require-verified")
        env.close()
    }

    @Test
    fun anOutputThatIsNotAPlainFileIsWrittenInPlace() = runBlocking {
        val devNull = Path.of("/dev/null")
        if (!Files.exists(devNull) || Files.isRegularFile(devNull)) return@runBlocking
        val env = B1Fixtures.env()
        val me = B1Fixtures.key(env.repo, "Me")
        val msg = env.dir.resolve("m.gpg")
        Files.write(msg, B1Fixtures.encrypt(B1Fixtures.pub(env.repo, me.fingerprint), "check only".toByteArray(), "m", armor = false))
        val d = cli(env.repo, "decrypt", "-o", "/dev/null", msg.toString())
        assertEquals(ExitCode.OK, d.code, d.err)
        val plain = env.dir.resolve("p.txt").also { Files.writeString(it, "to nowhere") }
        val e = cli(env.repo, "encrypt", "-r", me.fingerprint, "-o", "/dev/null", plain.toString())
        assertEquals(ExitCode.OK, e.code, e.err)
        assertTrue(Files.exists(devNull) && !Files.isRegularFile(devNull), "/dev/null is still the device")
        env.close()
    }
}
