// DesktopFileRouterTest.kt
// D9 validation — the open-a-file decision tree matches Android's IntentHandler routing, built
// from real key/message bytes (no filesystem: classifyBytes takes the bytes + a path for the
// name/extension sniff).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopFileRouterTest {

    private val crypto = PGPCryptoService.shared
    private fun path(name: String): Path = Path.of("/tmp/$name")

    private fun gen(email: String = "router@pgpony.app") = crypto.generateKeyPair(
        name = "Router Test", email = email,
        algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "pw"
    )

    @Test
    fun publicKeyBlockRoutesToImport() {
        val g = gen()
        val a = DesktopFileRouter.classifyBytes(g.armoredPublicKey.toByteArray(), path("key.asc"))
        assertTrue(a is OpenAction.ImportKey, "got $a")
    }

    @Test
    fun privateKeyBlockRoutesToImport() {
        val g = gen()
        val a = DesktopFileRouter.classifyBytes(g.armoredPrivateKey.toByteArray(), path("secret.asc"))
        assertTrue(a is OpenAction.ImportKey, "got $a")
    }

    @Test
    fun armoredMessageRoutesToDecryptText() {
        val g = gen()
        val ring = crypto.importArmoredKey(g.armoredPublicKey).publicKeyRing!!
        val armored = crypto.encryptMessage("hello", listOf(ring), null, null)
        val a = DesktopFileRouter.classifyBytes(armored.toByteArray(), path("msg.asc"))
        assertTrue(a is OpenAction.DecryptText, "got $a")
    }

    @Test
    fun binaryEncryptedMessageRoutesToDecryptFile() {
        val g = gen()
        val ring = crypto.importArmoredKey(g.armoredPublicKey).publicKeyRing!!
        val binary = crypto.encrypt(
            data = "hello".toByteArray(), recipientPublicKeys = listOf(ring), armor = false
        )
        val a = DesktopFileRouter.classifyBytes(binary, path("msg.gpg"))
        assertTrue(a is OpenAction.DecryptFile, "got $a")
    }

    @Test
    fun detachedSignatureRoutesToVerify() {
        val g = gen()
        val ring = crypto.importArmoredKey(g.armoredPrivateKey).secretKeyRing!!
        val sig = com.pgpony.android.crypto.SigningService.shared
            .signDetached("data".toByteArray(), ring, "pw")   // armored detached signature
        val a = DesktopFileRouter.classifyBytes(sig, path("data.sig"))
        assertTrue(a is OpenAction.VerifyDetachedSignature, "got $a")
    }

    @Test
    fun pgponyExtensionRoutesToRestore() {
        val a = DesktopFileRouter.classifyBytes("anything".toByteArray(), path("keys.pgpony"))
        assertTrue(a is OpenAction.RestoreBackup, "got $a")
    }

    @Test
    fun pgponyBackupCommentInHeadRoutesToRestore() {
        val armored = "-----BEGIN PGP MESSAGE-----\nComment: PGPony Backup v1\n\nZm9v\n-----END PGP MESSAGE-----"
        val a = DesktopFileRouter.classifyBytes(armored.toByteArray(), path("blob.asc"))
        assertTrue(a is OpenAction.RestoreBackup, "the backup comment wins over generic message routing; got $a")
    }

    @Test
    fun nonPgpFileRoutesToEncryptFile() {
        // Plain text with no PGP markers and a first byte whose high bit is clear (so it is not
        // mistaken for an OpenPGP packet) → the C1 "everything else opens to Encrypt" route.
        val note = "just some plain notes, nothing PGP in here".toByteArray()
        val a = DesktopFileRouter.classifyBytes(note, path("notes.txt"))
        assertTrue(a is OpenAction.EncryptFile, "got $a")
        // A JPEG (0xFF 0xD8 → new-format tag 63, not a signature) also routes to Encrypt.
        val jpeg = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte()) + ByteArray(32)
        assertTrue(DesktopFileRouter.classifyBytes(jpeg, path("photo.jpg")) is OpenAction.EncryptFile)
    }

    @Test
    fun emlEnvelopeRoutesToDecryptFile() {
        val eml = "MIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"\r\n\r\nbody"
        val a = DesktopFileRouter.classifyBytes(eml.toByteArray(), path("message.eml"))
        assertTrue(a is OpenAction.DecryptFile, "got $a")
    }

    @Test
    fun emptyFileRoutesToNone() {
        assertEquals(OpenAction.None, DesktopFileRouter.classifyBytes(ByteArray(0), path("empty")))
    }

    // ── Forced operations (D14 — `open --op`, the context-menu verbs) ──────

    @Test
    fun forcedEncryptWinsOverKeyClassification() {
        val g = gen()
        val bytes = g.armoredPublicKey.toByteArray()
        // Classification says Import; the user's right-click said Encrypt. The click wins.
        assertTrue(DesktopFileRouter.classifyBytes(bytes, path("key.asc")) is OpenAction.ImportKey)
        val forced = DesktopFileRouter.classifyBytes(bytes, path("key.asc"), ForcedOp.ENCRYPT)
        assertTrue(forced is OpenAction.EncryptFile, "got $forced")
    }

    @Test
    fun forcedImportConsumesTheTextEvenWhenClassificationWouldNot() {
        // The Import surface owns the "not a key" error, which names the op the user asked for.
        val note = "not a key at all".toByteArray()
        val forced = DesktopFileRouter.classifyBytes(note, path("notes.txt"), ForcedOp.IMPORT)
        assertTrue(forced is OpenAction.ImportKey, "got $forced")
        assertEquals("not a key at all", (forced as OpenAction.ImportKey).armored)
    }

    @Test
    fun forcedDecryptKeepsTheTextFileSplitButNeverTheOp() {
        val g = gen()
        val ring = crypto.importArmoredKey(g.armoredPublicKey).publicKeyRing!!
        val armored = crypto.encryptMessage("hello", listOf(ring), null, null).toByteArray()
        val small = DesktopFileRouter.classifyBytes(armored, path("msg.asc"), ForcedOp.DECRYPT)
        assertTrue(small is OpenAction.DecryptText, "got $small")
        // Binary content picks the file VARIANT; the bytes never override the op itself.
        val jpeg = byteArrayOf(0xFF.toByte(), 0xD8.toByte()) + ByteArray(16)
        val big = DesktopFileRouter.classifyBytes(jpeg, path("photo.jpg"), ForcedOp.DECRYPT)
        assertTrue(big is OpenAction.DecryptFile, "got $big")
    }

    @Test
    fun forcedVerifyAndRestoreNameTheirActions() {
        // Content decides nothing for these two — classify(path, op) doesn't even read it.
        val verify = DesktopFileRouter.classifyBytes(ByteArray(0), path("x.sig"), ForcedOp.VERIFY)
        assertTrue(verify is OpenAction.VerifyDetachedSignature, "got $verify")
        val restore = DesktopFileRouter.classifyBytes(ByteArray(0), path("x.bin"), ForcedOp.RESTORE)
        assertTrue(restore is OpenAction.RestoreBackup, "got $restore")
    }

    @Test
    fun forcedOpNamesParseCaseInsensitivelyAndUnknownIsNull() {
        assertEquals(ForcedOp.ENCRYPT, ForcedOp.fromCli("Encrypt"))
        assertEquals(ForcedOp.DECRYPT, ForcedOp.fromCli(" decrypt "))
        assertNull(ForcedOp.fromCli("sign"), "sign is not a forced op until signing UX exists")
    }
}
