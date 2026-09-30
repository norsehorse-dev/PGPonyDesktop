// SopTest.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5a: pgpony-sop end to end, through Sop.run with
// in-memory streams and temporary files, the way the interop suite drives it. Round trips for
// each key profile, the verification line format, and the exit codes the spec names.
// 5d-4: several signing keys, the Cleartext Signature Framework, text-mode signing inside an
// encrypted message, and the rfc9580 password profile.

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

class SopTest {

    private lateinit var dir: Path

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("pgpony-sop-test")
        KeyUsePolicy.forced = false
    }

    @AfterTest
    fun tearDown() {
        KeyUsePolicy.forced = null
    }

    private class Run(val code: Int, val out: ByteArray, val err: String) {
        val text: String get() = String(out, Charsets.UTF_8)
    }

    private fun sop(vararg args: String, input: ByteArray = ByteArray(0), env: Map<String, String> = emptyMap()): Run {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = Sop.run(args.toList(), ByteArrayInputStream(input), out, PrintStream(err, true)) { env[it] }
        return Run(code, out.toByteArray(), err.toString(Charsets.UTF_8))
    }

    private fun file(name: String, bytes: ByteArray): String = dir.resolve(name).also { Files.write(it, bytes) }.toString()

    private fun ok(r: Run): Run {
        assertEquals(0, r.code, "stderr: ${r.err}")
        return r
    }

    private val message = "Hello, interop.\nSecond line.\n".toByteArray()

    private fun roundTrip(profile: String) {
        val key = ok(sop("generate-key", "--profile=$profile", "Alice Lovelace <alice@openpgp.example>")).out
        assertTrue(String(key).startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"), profile)
        val cert = ok(sop("extract-cert", input = key)).out
        assertTrue(String(cert).startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"), profile)
        val keyFile = file("$profile.key", key)
        val certFile = file("$profile.cert", cert)

        // Detached, binary then text.
        for (mode in listOf("binary", "text")) {
            val sig = ok(sop("sign", "--as=$mode", keyFile, input = message)).out
            val sigFile = file("$profile-$mode.sig", sig)
            val v = ok(sop("verify", sigFile, certFile, input = message)).text
            assertTrue(Regex("^\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\dZ [0-9A-F]{40,64} [0-9A-F]{40,64} mode:$mode\\n$").matches(v), "$profile $mode: $v")
            assertEquals(SopExit.NO_SIGNATURE, sop("verify", sigFile, certFile, input = "tampered".toByteArray()).code)
        }

        // Encrypt and sign, decrypt and verify.
        val ct = ok(sop("encrypt", "--sign-with=$keyFile", certFile, input = message)).out
        val verOut = dir.resolve("$profile.verifications").toString()
        val pt = ok(sop("decrypt", "--verify-with=$certFile", "--verifications-out=$verOut", keyFile, input = ct)).out
        assertContentEquals(message, pt)
        assertEquals(1, Files.readAllLines(Path.of(verOut)).size, "one verification for one signature")

        // Inline signed, binary and cleartext.
        val inline = ok(sop("inline-sign", keyFile, input = message)).out
        assertContentEquals(message, ok(sop("inline-verify", certFile, input = inline)).out)
        val clear = ok(sop("inline-sign", "--as=clearsigned", keyFile, input = message)).out
        assertTrue(String(clear).startsWith("-----BEGIN PGP SIGNED MESSAGE-----"))
        assertTrue(ok(sop("inline-verify", certFile, input = clear)).text.startsWith("Hello, interop."))
    }

    @Test fun roundTripV4Ed25519() = roundTrip("draft-koch-eddsa-for-openpgp-00")

    @Test fun roundTripV6() = roundTrip("rfc9580")

    @Test fun roundTripPostQuantum() = roundTrip("draft-ietf-openpgp-pqc")

    @Test
    fun versionAndProfiles() {
        assertTrue(ok(sop("version")).text.startsWith("pgpony-sop "))
        assertEquals(Sop.SPEC + "\n", ok(sop("version", "--sop-spec")).text)
        val profiles = ok(sop("list-profiles", "generate-key")).text.lines().filter { it.isNotBlank() }
        assertEquals(Sop.KEY_PROFILES.size, profiles.size)
        assertTrue(profiles.first().startsWith("draft-koch-eddsa-for-openpgp-00: "))
        assertEquals(SopExit.UNSUPPORTED_PROFILE, sop("list-profiles", "sign").code)
        assertEquals(SopExit.UNSUPPORTED_PROFILE, sop("generate-key", "--profile=nope", "a <a@x>").code)
    }

    @Test
    fun armorAndDearmorAreInverses() {
        val key = ok(sop("generate-key", "Bob <bob@openpgp.example>")).out
        val binary = ok(sop("dearmor", input = key)).out
        assertTrue(binary.isNotEmpty() && binary[0].toInt() and 0x80 != 0)
        val again = ok(sop("armor", input = binary)).out
        assertTrue(String(again).startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        assertContentEquals(binary, ok(sop("dearmor", input = again)).out)
        assertContentEquals(key, ok(sop("armor", input = key)).out, "armoring armor changes nothing")
        assertContentEquals(binary, ok(sop("dearmor", input = binary)).out, "dearmoring binary changes nothing")
    }

    @Test
    fun passwordsAndProtectedKeys() {
        val pwFile = file("pw", "correct horse\n".toByteArray())
        val ct = ok(sop("encrypt", "--with-password=$pwFile", input = message)).out
        assertContentEquals(message, ok(sop("decrypt", "--with-password=$pwFile", input = ct)).out, "trailing newline trimmed")
        assertEquals(SopExit.CANNOT_DECRYPT, sop("decrypt", "--with-password=${file("bad", "wrong".toByteArray())}", input = ct).code)

        val key = ok(sop("generate-key", "--with-key-password=@ENV:PW", "Carol <carol@openpgp.example>", env = mapOf("PW" to "s3cret"))).out
        val keyFile = file("carol.key", key)
        assertEquals(SopExit.KEY_IS_PROTECTED, sop("sign", keyFile, input = message).code)
        ok(sop("sign", "--with-key-password=@ENV:PW", keyFile, input = message, env = mapOf("PW" to "s3cret")))
        val cert = file("carol.cert", ok(sop("extract-cert", input = key)).out)
        val ct2 = ok(sop("encrypt", cert, input = message)).out
        assertEquals(SopExit.KEY_IS_PROTECTED, sop("decrypt", keyFile, input = ct2).code)
        assertContentEquals(message, ok(sop("decrypt", "--with-key-password=@ENV:PW", keyFile, input = ct2, env = mapOf("PW" to "s3cret"))).out)
    }

    @Test
    fun exitCodesTheSpecNames() {
        assertEquals(SopExit.UNSUPPORTED_SUBCOMMAND, sop("frobnicate").code)
        assertEquals(SopExit.UNSUPPORTED_OPTION, sop("sign", "--frob", "x").code)
        assertEquals(SopExit.MISSING_ARG, sop("sign", input = message).code)
        assertEquals(SopExit.MISSING_INPUT, sop("sign", dir.resolve("nope.key").toString(), input = message).code)
        assertEquals(SopExit.UNSUPPORTED_SPECIAL_PREFIX, sop("sign", "@HTTP:x", input = message).code)
        assertEquals(SopExit.BAD_DATA, sop("dearmor", input = "not openpgp".toByteArray()).code)
        assertEquals(SopExit.BAD_DATA, sop("decrypt", "--with-password=${file("p", "x".toByteArray())}", input = "plain".toByteArray()).code)

        val key = ok(sop("generate-key", "Dave <dave@openpgp.example>")).out
        val keyFile = file("dave.key", key)
        val existing = file("exists", "x".toByteArray())
        assertEquals(SopExit.OUTPUT_EXISTS, sop("sign", "--micalg-out=$existing", keyFile, input = message).code)
        assertEquals(SopExit.EXPECTED_TEXT, sop("sign", "--as=text", keyFile, input = byteArrayOf(0xFF.toByte(), 0xFE.toByte())).code)
        assertEquals(SopExit.INCOMPATIBLE_OPTIONS, sop("inline-sign", "--as=clearsigned", "--no-armor", keyFile, input = message).code)
        assertEquals(SopExit.UNSUPPORTED_OPTION, sop("decrypt", "--session-key-out=${dir.resolve("sk")}", keyFile, input = message).code)

        val otherCert = file("erin.cert", ok(sop("extract-cert", input = ok(sop("generate-key", "Erin <erin@openpgp.example>")).out)).out)
        val ct = ok(sop("encrypt", otherCert, input = message)).out
        assertEquals(SopExit.CANNOT_DECRYPT, sop("decrypt", keyFile, input = ct).code)
    }

    @Test
    fun signatureInfoIsReadWithoutBouncyCastle() {
        val key = file("f.key", ok(sop("generate-key", "--profile=rfc9580", "Frank <frank@openpgp.example>")).out)
        val sig = ok(sop("sign", "--as=text", "--no-armor", key, input = message)).out
        val info = SopSigInfo.parse(SopPackets.signatures(sig).single())!!
        assertEquals(6, info.version)
        assertTrue(info.isText)
        assertTrue(info.issuerFingerprint!!.length == 64)
        assertTrue(info.created!!.time <= System.currentTimeMillis())
    }

    // ── 5d-4 ─────────────────────────────────────────────────────────

    private class Party(val key: String, val cert: String)

    private fun party(name: String, profile: String): Party {
        val key = ok(sop("generate-key", "--profile=$profile", "$name <${name.lowercase()}@openpgp.example>")).out
        return Party(file("$name.key", key), file("$name.cert", ok(sop("extract-cert", input = key)).out))
    }

    private fun lines(path: String): List<String> = Files.readAllLines(Path.of(path)).filter { it.isNotBlank() }

    @Test
    fun inlineSignWithSeveralKeys() {
        val signers = listOf(
            party("V4", "draft-koch-eddsa-for-openpgp-00"),
            party("V6", "rfc9580"),
            party("Pqc", "draft-ietf-openpgp-pqc")
        )
        // CRLF and LF lines, a line starting with a dash, trailing spaces: the text comes back
        // as it went in, except that a cleartext signature does not cover trailing spaces, so
        // those are not handed back.
        val text = "First line  \r\n- dashed\nlast line\n".toByteArray()
        val clearText = "First line\r\n- dashed\nlast line\n".toByteArray()
        for (mode in listOf("binary", "text", "clearsigned")) {
            val signed = ok(sop("inline-sign", "--as=$mode", *signers.map { it.key }.toTypedArray(), input = text)).out
            for (s in signers) {
                val ver = dir.resolve("inline-$mode-${s.cert.hashCode()}").toString()
                val out = ok(sop("inline-verify", "--verifications-out=$ver", s.cert, input = signed)).out
                assertContentEquals(if (mode == "clearsigned") clearText else text, out, "$mode, verified with ${s.cert}")
                assertEquals(1, lines(ver).size, "$mode: one verification per matching cert")
            }
        }
    }

    @Test
    fun cleartextFrameworkIsReadStrictly() {
        val p = party("Clear", "rfc9580")
        val clear = String(ok(sop("inline-sign", "--as=clearsigned", p.key, input = message)).out)
        assertContentEquals(message, SopCleartext.parse(clear.toByteArray()).text)
        assertContentEquals("Hello, interop.\r\nSecond line.\r\n".toByteArray(), SopCleartext.signedOctetsOf(message))

        // The line ending in front of the signature belongs to the framework: a text that ends
        // in a line ending is followed by an empty line, and one that does not is not.
        val sigBlock = clear.substring(clear.indexOf("-----BEGIN PGP SIGNATURE-----"))
        val framed = "-----BEGIN PGP SIGNED MESSAGE-----\n\ntest\r\nmessage\r\n\n$sigBlock"
        val parsed = SopCleartext.parse(framed.toByteArray())
        assertContentEquals("test\r\nmessage\r\n".toByteArray(), parsed.text)
        assertContentEquals("test\r\nmessage\r\n".toByteArray(), parsed.signed)
        for (t in listOf("Hello World :)", "test\nmessage\n", "a\r\nb\n\n")) {
            val w = String(SopCleartext.write(t.toByteArray(), emptyList()))
            assertContentEquals(t.toByteArray(), SopCleartext.parse(w.toByteArray()).text, t)
        }

        val header = "-----BEGIN PGP SIGNED MESSAGE-----\n"
        val bad = listOf(
            "Unsigned text\n" + clear,
            clear.replaceFirst(header, header + "Comment: signed\n"),
            clear + "Unsigned text\n"
        )
        for (b in bad) {
            assertEquals(SopExit.BAD_DATA, runCatching { SopCleartext.parse(b.toByteArray()) }.exceptionOrNull().let { (it as SopException).code })
            assertTrue(sop("inline-verify", p.cert, input = b.toByteArray()).code != 0)
        }
        ok(sop("inline-verify", p.cert, input = clear.replaceFirst(header, header + "Hash: SHA512\n").toByteArray()))
    }

    @Test
    fun encryptWithSeveralSignersAndText() {
        val a = party("SignerA", "rfc9580")
        val b = party("SignerB", "draft-ietf-openpgp-pqc")
        val r = party("Reader", "rfc9580")
        val ct = ok(sop("encrypt", "--as=text", "--sign-with=${a.key}", "--sign-with=${b.key}", r.cert, input = message)).out
        val ver = dir.resolve("two.verifications").toString()
        val pt = ok(sop("decrypt", "--verify-with=${a.cert}", "--verify-with=${b.cert}", "--verifications-out=$ver", r.key, input = ct)).out
        assertContentEquals(message, pt)
        val v = lines(ver)
        assertEquals(2, v.size)
        assertTrue(v.all { it.contains("mode:text") }, v.toString())
    }

    @Test
    fun passwordProfiles() {
        val pwFile = file("pw9580", "correct horse\n".toByteArray())
        val v6 = ok(sop("encrypt", "--no-armor", "--profile=rfc9580", "--with-password=$pwFile", input = message)).out
        assertEquals(0xC3, v6[0].toInt() and 0xFF, "a symmetric-key encrypted session key packet")
        assertEquals(6, v6[2].toInt(), "SKESK version 6")
        assertContentEquals(message, ok(sop("decrypt", "--with-password=$pwFile", input = v6)).out)
        val v4 = ok(sop("encrypt", "--no-armor", "--with-password=$pwFile", input = message)).out
        assertEquals(4, v4[2].toInt(), "the default profile keeps SKESK version 4")
    }
}
