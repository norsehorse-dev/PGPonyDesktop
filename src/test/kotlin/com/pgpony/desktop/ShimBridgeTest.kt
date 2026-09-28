// ShimBridgeTest.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4b: pgpony-gpg holds no passphrase and asks the
// running app to sign with a protected key (plan section 7). The wire format, the token, the
// endpoint file, and the app side's remembered passphrase and prompt.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.data.settings.SettingsStores
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ShimBridgeTest {

    private val fp = "0123456789abcdef0123456789abcdef01234567"
    private val token = "a".repeat(64)

    @BeforeTest
    fun hooks() {
        val node = MemoryPreferences()
        SettingsStores.install { _, _ -> DesktopPrefsSettings(node) }
        PassphraseCache.clearAll()
    }

    @AfterTest
    fun unhook() {
        ShimBridge.stop()
        PassphraseCache.clearAll()
        SettingsStores.uninstall()
    }

    private fun sign(bytes: ByteArray) = ShimBridge.readSign(ByteArrayInputStream(bytes))

    @Test
    fun requestsAndRepliesAreBounded() {
        fun body(line: String, length: String) = "$line\n$length\n".toByteArray()
        val ok = assertIs<ShimBridge.Request.Sign>(sign(body("SIGN $fp", "7") + "payload".toByteArray()))
        assertEquals(fp, ok.fingerprint)
        assertContentEquals("payload".toByteArray(), ok.payload)
        assertIs<ShimBridge.Request.Bad>(sign(body("SIGN ../../etc/passwd", "1") + byteArrayOf(1)), "not a fingerprint")
        assertIs<ShimBridge.Request.Bad>(sign(body("EXPORT $fp", "0")), "only signing is served")
        assertIs<ShimBridge.Request.Bad>(sign(body("SIGN $fp", "${ShimBridge.MAX_PAYLOAD + 1}")), "too large")
        assertIs<ShimBridge.Request.Bad>(sign(body("SIGN $fp", "10") + byteArrayOf(1, 2)), "ended early")
        assertIs<ShimBridge.Request.Bad>(sign(ByteArray(10_000) { 'A'.code.toByte() }), "an endless line")

        val out = ByteArrayOutputStream()
        ShimBridge.writeReply(out, ShimBridge.Reply.Signed("sig".toByteArray(), 22, 8))
        val signed = assertIs<ShimBridge.Reply.Signed>(ShimBridge.readReply(ByteArrayInputStream(out.toByteArray())))
        assertContentEquals("sig".toByteArray(), signed.armored)
        assertEquals(22, signed.pkAlgo)
        assertEquals(8, signed.hashAlgo)

        val refusedOut = ByteArrayOutputStream()
        ShimBridge.writeReply(refusedOut, ShimBridge.Reply.Refused("two\nlines"))
        val refused = assertIs<ShimBridge.Reply.Refused>(ShimBridge.readReply(ByteArrayInputStream(refusedOut.toByteArray())))
        assertEquals("twolines", refused.message)
        assertEquals(ShimBridge.Reply.Unreachable, ShimBridge.readReply(ByteArrayInputStream(ByteArray(0))))
    }

    @Test
    fun theHandshakeNeverSendsTheTokenOrTheCommitToAStranger() {
        // The shim talking to a listener that does not hold the token: it answers HELLO with a
        // wrong proof. The shim must stop after its first line.
        val stranger = ByteArrayInputStream("HELLO ${"c".repeat(64)} ${"d".repeat(64)}\n".toByteArray())
        val sent = ByteArrayOutputStream()
        val reply = ShimBridge.clientExchange(stranger, sent, token, fp, "secret commit".toByteArray())
        assertEquals(ShimBridge.Reply.Unreachable, reply)
        val wire = sent.toString(Charsets.UTF_8)
        assertEquals(2, wire.lines().filter { it.isNotEmpty() }.size, "protocol line and nonce only: $wire")
        assertFalse(wire.contains(token), "the token never crosses the socket")
        assertFalse(wire.contains("secret commit"))

        // The app talking to a client that cannot prove the token.
        val shimNonce = "e".repeat(64)
        val impostor = ByteArrayInputStream("PGPONY-SHIM 2\n$shimNonce\n${"f".repeat(64)}\nSIGN $fp\n1\nx".toByteArray())
        val hello = ByteArrayOutputStream()
        val request = ShimBridge.serverExchange(impostor, hello, token)
        assertEquals("not authorized", assertIs<ShimBridge.Request.Bad>(request).message)
        assertTrue(hello.toString(Charsets.UTF_8).endsWith(LocalSecret.proof(token, "server", shimNonce) + "\n"))
    }

    @Test
    fun theShimReachesOnlyARunningApp() {
        val dir = Files.createTempDirectory("pgpony-bridge-test")
        assertEquals(ShimBridge.Reply.Unreachable, ShimBridge.requestSignature(dir, fp, "x".toByteArray()), "no app running")

        var seen: String? = null
        assertTrue(ShimBridge.start(dir) { f, payload -> seen = f; ShimBridge.Reply.Signed(payload.reversedArray(), 22, 8) })
        val endpoint = dir.resolve(ShimBridge.FILE_NAME)
        if ("posix" in FileSystems.getDefault().supportedFileAttributeViews()) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(endpoint)), "the token is the user's only")
        }
        val reply = assertIs<ShimBridge.Reply.Signed>(ShimBridge.requestSignature(dir, fp, "abc".toByteArray()))
        assertEquals("cba", String(reply.armored))
        assertEquals(fp, seen)

        // The same port with another token (a stale file, another account): nothing is signed.
        seen = null
        val other = Files.createTempDirectory("pgpony-bridge-other")
        val port = Files.readString(endpoint).trim().substringBefore(' ')
        Files.writeString(other.resolve(ShimBridge.FILE_NAME), "$port ${"0".repeat(64)}\n")
        assertEquals(ShimBridge.Reply.Unreachable, ShimBridge.requestSignature(other, fp, "abc".toByteArray()))
        assertNull(seen)

        ShimBridge.stop()
        assertFalse(Files.exists(endpoint), "the endpoint goes with the app")
        assertEquals(ShimBridge.Reply.Unreachable, ShimBridge.requestSignature(dir, fp, "x".toByteArray()))
    }

    @Test
    fun theAppSignsWithTheRememberedPassphraseOrAsks() = runBlocking {
        val dir = Files.createTempDirectory("pgpony-bridge-keys")
        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        val key = repo.generateKey("Git", "git@pgpony.app", KeyAlgorithm.ED25519_CV25519, "git-pass")
        val payload = "tree 0000\nauthor Git\n\ncommit message\n".toByteArray()

        assertEquals(ShimSigner.Result.Locked, ShimSigner.sign(repo, key, payload, null), "the shim alone cannot sign")
        assertEquals(ShimSigner.Result.WrongPassphrase, ShimSigner.sign(repo, key, payload, "nope"))

        var prompts = 0
        val first = ShimSigner.signForShim(repo, key.fingerprint, payload) { prompts++; if (prompts == 1) "nope" else "git-pass" }
        val signed = assertIs<ShimBridge.Reply.Signed>(first)
        assertEquals(2, prompts, "a wrong answer asks again")
        assertEquals("git-pass", PassphraseCache.get(key.fingerprint), "remembered for the session")
        val verdict = VerifyService.shared.verifyDetached(signed.armored, payload, listOf(repo.loadPublicKeyRing(key.fingerprint)!!))
        assertIs<VerificationResult.Verified>(verdict)

        assertIs<ShimBridge.Reply.Signed>(ShimSigner.signForShim(repo, key.fingerprint, payload) { prompts++; null })
        assertEquals(2, prompts, "no prompt while remembered")

        PassphraseCache.put(key.fingerprint, "stale")
        assertIs<ShimBridge.Reply.Signed>(ShimSigner.signForShim(repo, key.fingerprint, payload) { prompts++; "git-pass" })
        assertEquals(3, prompts, "a stale passphrase is dropped and the prompt comes back")

        PassphraseCache.clearAll()
        assertIs<ShimBridge.Reply.Refused>(ShimSigner.signForShim(repo, key.fingerprint, payload) { null }, "cancelled")
        assertIs<ShimBridge.Reply.Refused>(ShimSigner.signForShim(repo, "ff".repeat(20), payload) { "x" }, "not a key here")

        val pq = repo.generateKey("PQ Git", "pqgit@pgpony.app", KeyAlgorithm.MLDSA65_ED25519_V6, "pq-pass")
        assertEquals(ShimSigner.Result.Locked, ShimSigner.sign(repo, pq, payload, null))
        assertIs<ShimSigner.Result.Signed>(ShimSigner.sign(repo, pq, payload, "pq-pass"))
        db.close()
    }
}
