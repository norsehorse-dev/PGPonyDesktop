// SopLibrePgpV5Test.kt
// PGPony Desktop 3.0.3: pgpony-sop with a LibrePGP v5 key, the kind GnuPG and Kleopatra make for
// Ed448 (an Ed448 primary and an X448 encryption subkey). Uses the throwaway key and the gpg-made
// vectors in /gnupg448 (see GnuPgX448InteropTest). The engine fixes come from PGPony Android 4.7.3
// (GnuPgX448, LibrePgpV5Sig, PonySigGen); this test covers the SOP wrapper on top of them, which
// verifies each signature packet again on its own and so needs the v5 document block too.

package com.pgpony.desktop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SopLibrePgpV5Test {

    private lateinit var dir: Path

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("pgpony-sop-v5-test")
        KeyUsePolicy.forced = false
    }

    @AfterTest
    fun tearDown() {
        KeyUsePolicy.forced = null
    }

    private class Run(val code: Int, val out: ByteArray, val err: String) {
        val text: String get() = String(out, Charsets.UTF_8)
    }

    private fun sop(vararg args: String, input: ByteArray = ByteArray(0)): Run {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = Sop.run(args.toList(), ByteArrayInputStream(input), out, PrintStream(err, true)) { null }
        return Run(code, out.toByteArray(), err.toString(Charsets.UTF_8))
    }

    private fun ok(r: Run): Run {
        assertEquals(0, r.code, "stderr: ${r.err}")
        return r
    }

    private fun vector(name: String): ByteArray = javaClass.getResourceAsStream("/gnupg448/$name")!!.readBytes()

    private fun file(name: String, bytes: ByteArray): String = dir.resolve(name).also { Files.write(it, bytes) }.toString()

    private val keyFile by lazy { file("x448.key", vector("x448-secret.asc")) }
    private val certFile by lazy { file("x448.cert", vector("x448-public.asc")) }
    private val plain by lazy { vector("plain.txt") }

    private val primaryFp by lazy {
        val cert = org.bouncycastle.openpgp.PGPPublicKeyRing(
            org.bouncycastle.bcpg.ArmoredInputStream(vector("x448-public.asc").inputStream()).readBytes(),
            org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator()
        )
        cert.publicKey.fingerprint.joinToString("") { "%02X".format(it) }
    }

    /** Exactly one VERIFICATIONS line, made by the test key's primary (it signs with the primary). */
    private fun assertOneLine(lines: String, mode: String) {
        val l = lines.lines().filter { it.isNotBlank() }
        assertEquals(1, l.size, "one verification: $lines")
        assertTrue(Regex("^\\S+Z $primaryFp $primaryFp mode:$mode$").matches(l[0]), l[0])
    }

    @Test
    fun verifiesGnuPgDetached() {
        val sig = file("plain.txt.asc", vector("plain.txt.asc"))
        assertOneLine(ok(sop("verify", sig, certFile, input = plain)).text, "binary")
        assertEquals(SopExit.NO_SIGNATURE, sop("verify", sig, certFile, input = plain + 0x21).code)
    }

    @Test
    fun inlineVerifiesGnuPgCleartext() {
        val ver = dir.resolve("clear.ver").toString()
        val out = ok(sop("inline-verify", "--verifications-out=$ver", certFile, input = vector("clearsigned.asc"))).out
        // The line ending before the signature belongs to the framing, not the text.
        assertEquals(String(plain, Charsets.UTF_8).trimEnd('\n'), String(out, Charsets.UTF_8))
        assertOneLine(Files.readString(Path.of(ver)), "text")
    }

    @Test
    fun inlineVerifiesGnuPgInline() {
        val ver = dir.resolve("inline.ver").toString()
        val out = ok(sop("inline-verify", "--verifications-out=$ver", certFile, input = vector("signed.asc"))).out
        assertContentEquals(plain, out)
        assertOneLine(Files.readString(Path.of(ver)), "binary")
    }

    @Test
    fun decryptsGnuPgMessages() {
        assertContentEquals(plain, ok(sop("decrypt", keyFile, input = vector("gpg-encrypted.asc"))).out)
        val ver = dir.resolve("dec.ver").toString()
        val out = ok(sop("decrypt", "--verify-with=$certFile", "--verifications-out=$ver", keyFile,
            input = vector("gpg-signed-encrypted.asc"))).out
        assertContentEquals(plain, out)
        assertOneLine(Files.readString(Path.of(ver)), "binary")
    }

    @Test
    fun signsAndVerifiesDetached() {
        for (mode in listOf("binary", "text")) {
            val sig = file("v5-$mode.sig", ok(sop("sign", "--as=$mode", keyFile, input = plain)).out)
            assertOneLine(ok(sop("verify", sig, certFile, input = plain)).text, mode)
            assertEquals(SopExit.NO_SIGNATURE, sop("verify", sig, certFile, input = plain + 0x21).code)
        }
    }

    @Test
    fun inlineSignsAndVerifies() {
        for (mode in listOf("binary", "text", "clearsigned")) {
            val signed = ok(sop("inline-sign", "--as=$mode", keyFile, input = plain)).out
            val ver = dir.resolve("$mode.ver").toString()
            assertContentEquals(plain, ok(sop("inline-verify", "--verifications-out=$ver", certFile, input = signed)).out, mode)
            assertOneLine(Files.readString(Path.of(ver)), if (mode == "binary") "binary" else "text")
        }
    }

    @Test
    fun encryptsToTheX448SubkeyAloneAndWithAnother() {
        val other = ok(sop("generate-key", "Other <other@example.invalid>")).out
        val otherKey = file("other.key", other)
        val otherCert = file("other.cert", ok(sop("extract-cert", input = other)).out)

        val alone = ok(sop("encrypt", certFile, input = plain)).out
        assertContentEquals(plain, ok(sop("decrypt", keyFile, input = alone)).out)

        val both = ok(sop("encrypt", "--sign-with=$keyFile", certFile, otherCert, input = plain)).out
        val ver = dir.resolve("both.ver").toString()
        assertContentEquals(plain, ok(sop("decrypt", "--verify-with=$certFile", "--verifications-out=$ver", keyFile, input = both)).out)
        assertOneLine(Files.readString(Path.of(ver)), "binary")
        assertContentEquals(plain, ok(sop("decrypt", otherKey, input = both)).out)
    }
    @Test
    fun severalSignersWithAV5Key() {
        val other = ok(sop("generate-key", "Other <other@example.invalid>")).out
        val otherKey = file("other2.key", other)
        val otherCert = file("other2.cert", ok(sop("extract-cert", input = other)).out)
        for (mode in listOf("binary", "text", "clearsigned")) {
            val signed = ok(sop("inline-sign", "--as=$mode", keyFile, otherKey, input = plain)).out
            val ver = dir.resolve("multi-$mode.ver").toString()
            assertContentEquals(plain, ok(sop("inline-verify", "--verifications-out=$ver", certFile, otherCert, input = signed)).out, mode)
            val lines = Files.readAllLines(Path.of(ver)).filter { it.isNotBlank() }
            assertEquals(2, lines.size, "$mode: $lines")
            assertTrue(lines.any { it.contains(" $primaryFp $primaryFp ") }, "$mode: $lines")
        }
    }

    @Test
    fun aV5SignatureMovedToOtherContentFails() {
        val signed = ok(sop("inline-sign", "--as=clearsigned", keyFile, input = plain)).out
        val tampered = String(signed, Charsets.UTF_8).replace("gpg to pgpony", "gpg to pgponY").toByteArray()
        assertEquals(SopExit.NO_SIGNATURE, sop("inline-verify", certFile, input = tampered).code)
    }
}
