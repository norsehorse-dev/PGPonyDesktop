// StreamingFilePathsTest.kt
// PGPony Android — 4.0.4
//
// Covers the streaming file paths added for issue #6 ("App freezes/
// crashes by decrypt any file" — a 13 MB file OOMed, a 35 KB one was
// fine). The UI now forks at INLINE_FILE_LIMIT: small files take the
// pre-4.0.4 buffered path, large ones stream through encryptStream /
// decryptStream into a scratch file.
//
// The contracts asserted here are the ones that fork depends on:
//
//   - The streamed and buffered paths are interchangeable in BOTH
//     directions. A file encrypted by one must decrypt with the other,
//     or a user who crosses the size threshold between operations gets
//     an unreadable file.
//   - encryptStream's new messagePassword produces a message the
//     existing buffered decrypt reads, and encryptSymmetric's output
//     reads back through decryptStream. Password mode had no streaming
//     option before 4.0.4, so this is the compatibility seam.
//   - inspectEncryptedMessage works from a TRUNCATED head. This is what
//     lets IntentHandler classify a shared file it can't hold in
//     memory, and what lets the Decrypt tab detect a card recipient by
//     reading a few KB. If BC ever needed more than the head, the large
//     paths would silently misroute.
//   - A passphrase-protected key with no passphrase raises
//     PassphraseRequired, not InvalidPassphrase — the 4.0.4 fix for the
//     API prompt opening pre-flagged "wrong passphrase" on a cold start.
//   - The literal-data filename survives a streamed decrypt, since the
//     scratch file is renamed to it.
//
// Pure JVM: nothing here touches ScratchFiles or the ViewModels, which
// need an Android Context. The chunking itself is exercised by the
// multi-megabyte round trip, which crosses decryptStream's 64 KiB
// buffer many times over.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class StreamingFilePathsTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"

    private fun pub(data: ByteArray) =
        PGPPublicKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun sec(data: ByteArray) =
        PGPSecretKeyRing(ByteArrayInputStream(data), JcaKeyFingerprintCalculator())

    private fun newKey(passphrase: String? = null) = svc.generateKeyPair(
        "Streamer", "s@pgpony.app", KeyAlgorithm.ED25519_CV25519, passphrase, null
    )

    private fun encryptStreamed(
        plaintext: ByteArray,
        recipients: List<PGPPublicKeyRing>,
        password: String? = null,
        filename: String? = null,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        svc.encryptStream(
            input = ByteArrayInputStream(plaintext),
            output = out,
            recipientPublicKeys = recipients,
            filename = filename,
            armor = false,
            messagePassword = password,
        )
        return out.toByteArray()
    }

    private fun decryptStreamed(
        ciphertext: ByteArray,
        rings: List<PGPSecretKeyRing>,
        passphrase: String? = null,
    ): Pair<ByteArray, DecryptStreamResult> {
        val out = ByteArrayOutputStream()
        val result = svc.decryptStream(
            input = ByteArrayInputStream(ciphertext),
            output = out,
            secretKeyRings = rings,
            passphrase = passphrase,
        )
        return out.toByteArray() to result
    }

    // ── Streamed round-trips ───────────────────────────────────────────

    @Test
    fun `public-key round-trips through both streams`() {
        val k = newKey()
        val plaintext = "the eagle has landed".toByteArray()
        val ct = encryptStreamed(plaintext, listOf(pub(k.publicKeyData)))
        val (recovered, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun `multi-megabyte payload round-trips across many chunk boundaries`() {
        val k = newKey()
        // 5 MiB of non-repeating bytes: over INLINE_FILE_LIMIT, and well
        // past decryptStream's 64 KiB buffer so the chunk loop runs ~80x.
        // Non-repeating so a truncation or a duplicated chunk shows up as
        // a mismatch rather than being masked by compression.
        val plaintext = ByteArray(5 * 1024 * 1024) { (it * 31 + (it shr 8)).toByte() }
        val ct = encryptStreamed(plaintext, listOf(pub(k.publicKeyData)))
        val (recovered, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertEquals(plaintext.size, recovered.size)
        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun `streamed decrypt preserves the literal filename`() {
        val k = newKey()
        val ct = encryptStreamed(
            "payload".toByteArray(), listOf(pub(k.publicKeyData)), filename = "quarterly.pdf"
        )
        val (_, result) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertEquals("quarterly.pdf", result.filename)
    }

    // ── Buffered <-> streamed interchange ──────────────────────────────

    @Test
    fun `buffered encrypt decrypts through the stream`() {
        val k = newKey()
        val plaintext = "crossing the threshold".toByteArray()
        val ct = svc.encrypt(
            data = plaintext,
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        val (recovered, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun `streamed encrypt decrypts through the buffer`() {
        val k = newKey()
        val plaintext = "crossing back".toByteArray()
        val ct = encryptStreamed(plaintext, listOf(pub(k.publicKeyData)))
        val result = svc.decrypt(ct, secretKeyRings = listOf(sec(k.privateKeyData)), passphrase = null)
        assertArrayEquals(plaintext, result.data)
    }

    // ── Password (SKESK) interchange — new in 4.0.4 ────────────────────

    @Test
    fun `streamed password encrypt decrypts through the buffer`() {
        val plaintext = "gpg -c but streamed".toByteArray()
        val ct = encryptStreamed(plaintext, emptyList(), password = pass)
        val result = svc.decrypt(ct, secretKeyRings = emptyList(), passphrase = pass)
        assertArrayEquals(plaintext, result.data)
    }

    @Test
    fun `encryptSymmetric output decrypts through the stream`() {
        val plaintext = "buffered symmetric".toByteArray()
        val ct = svc.encryptSymmetric(plaintext, passphrase = pass, armor = false)
        val (recovered, _) = decryptStreamed(ct, emptyList(), passphrase = pass)
        assertArrayEquals(plaintext, recovered)
    }

    @Test
    fun `streamed password message is detected as symmetric-only`() {
        val ct = encryptStreamed("secret".toByteArray(), emptyList(), password = pass)
        val info = svc.inspectEncryptedMessage(ct)
        assertTrue(info.isPasswordEncrypted)
        assertTrue(info.isSymmetricOnly)
    }

    @Test
    fun `a message can carry both a key recipient and a password`() {
        val k = newKey()
        val plaintext = "either way in".toByteArray()
        val ct = encryptStreamed(plaintext, listOf(pub(k.publicKeyData)), password = pass)

        // Via the key...
        val (viaKey, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)))
        assertArrayEquals(plaintext, viaKey)

        // ...and via the password, holding no key at all.
        val (viaPass, _) = decryptStreamed(ct, emptyList(), passphrase = pass)
        assertArrayEquals(plaintext, viaPass)
    }

    @Test
    fun `no recipients and no password is rejected`() {
        try {
            encryptStreamed("x".toByteArray(), emptyList())
            fail("expected EncryptionFailed")
        } catch (e: PGPCryptoError.EncryptionFailed) {
            // expected
        }
    }

    // ── Head-only inspection ───────────────────────────────────────────
    //
    // IntentHandler.classifyLargeFileUri and the Decrypt tab's card
    // detection both read a bounded head instead of the file. These
    // assert that BC finds the session-key packets there.

    @Test
    fun `inspect finds recipients in a truncated head`() {
        val k = newKey()
        // 2 MiB body, so the head is a tiny fraction of the message.
        val ct = encryptStreamed(ByteArray(2 * 1024 * 1024), listOf(pub(k.publicKeyData)))
        val head = ct.copyOf(minOf(ct.size, 64 * 1024))
        val info = svc.inspectEncryptedMessage(ByteArrayInputStream(head))
        assertTrue(
            "session-key packets must be readable from the head alone",
            info.publicKeyIDs.isNotEmpty()
        )
    }

    @Test
    fun `inspect finds a password packet in a truncated head`() {
        val ct = encryptStreamed(ByteArray(2 * 1024 * 1024), emptyList(), password = pass)
        val head = ct.copyOf(minOf(ct.size, 64 * 1024))
        val info = svc.inspectEncryptedMessage(ByteArrayInputStream(head))
        assertTrue(info.isPasswordEncrypted)
    }

    @Test
    fun `stream and byte-array inspection agree`() {
        val k = newKey()
        val ct = encryptStreamed("agreement".toByteArray(), listOf(pub(k.publicKeyData)))
        val fromBytes = svc.inspectEncryptedMessage(ct)
        val fromStream = svc.inspectEncryptedMessage(ByteArrayInputStream(ct))
        assertEquals(fromBytes.publicKeyIDs, fromStream.publicKeyIDs)
        assertEquals(fromBytes.isPasswordEncrypted, fromStream.isPasswordEncrypted)
    }

    // ── 4.0.4 passphrase-typing fix ────────────────────────────────────
    //
    // A protected key with no passphrase in hand must raise
    // PassphraseRequired. Before 4.0.4 the public-key branch let
    // extractPrivateKey throw a checksum PGPException, which the catch
    // mapped to InvalidPassphrase — so the OpenPGP API's prompt opened
    // already flagged "wrong passphrase" before the user typed anything.

    @Test
    fun `streamed decrypt with a protected key and no passphrase is PassphraseRequired`() {
        val k = newKey(passphrase = pass)
        val ct = encryptStreamed("locked".toByteArray(), listOf(pub(k.publicKeyData)))
        try {
            decryptStreamed(ct, listOf(sec(k.privateKeyData)), passphrase = null)
            fail("expected PassphraseRequired")
        } catch (e: PGPCryptoError.PassphraseRequired) {
            // expected
        } catch (e: PGPCryptoError.InvalidPassphrase) {
            fail("no passphrase supplied must not report an INVALID one")
        }
    }

    @Test
    fun `buffered decrypt with a protected key and no passphrase is PassphraseRequired`() {
        val k = newKey(passphrase = pass)
        val ct = svc.encrypt(
            data = "locked".toByteArray(),
            recipientPublicKeys = listOf(pub(k.publicKeyData)),
            armor = false
        )
        try {
            svc.decrypt(ct, secretKeyRings = listOf(sec(k.privateKeyData)), passphrase = null)
            fail("expected PassphraseRequired")
        } catch (e: PGPCryptoError.PassphraseRequired) {
            // expected
        } catch (e: PGPCryptoError.InvalidPassphrase) {
            fail("no passphrase supplied must not report an INVALID one")
        }
    }

    @Test
    fun `a genuinely wrong passphrase still reports InvalidPassphrase`() {
        val k = newKey(passphrase = pass)
        val ct = encryptStreamed("locked".toByteArray(), listOf(pub(k.publicKeyData)))
        try {
            decryptStreamed(ct, listOf(sec(k.privateKeyData)), passphrase = "not the passphrase")
            fail("expected InvalidPassphrase")
        } catch (e: PGPCryptoError.InvalidPassphrase) {
            // expected — the guard must not swallow a real mismatch
        }
    }

    @Test
    fun `an unprotected key still decrypts with no passphrase`() {
        val k = newKey(passphrase = null)
        val plaintext = "open".toByteArray()
        val ct = encryptStreamed(plaintext, listOf(pub(k.publicKeyData)))
        val (recovered, _) = decryptStreamed(ct, listOf(sec(k.privateKeyData)), passphrase = null)
        assertArrayEquals(plaintext, recovered)
    }
}
