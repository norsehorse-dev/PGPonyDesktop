// MimeBundleTest.kt
// D3c validation: PGP/MIME bundles both directions on the vendored mime/ package — signed
// bundle round-trip with binary attachment fidelity, non-MIME passthrough, .eml wrap +
// payload extraction (decrypting the .eml directly), and symmetric bundles.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.mime.MimeParser
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class MimeBundleTest {

    private fun setup(): Triple<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository, Path> {
        val dir = Files.createTempDirectory("pgpony-mime-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Triple(db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))), dir)
    }

    private suspend fun DesktopKeyRepository.gen(name: String, email: String) =
        generateKey(name, email, KeyAlgorithm.ED25519_CV25519, "test-passphrase")

    @Test
    fun signedBundleRoundTripWithBinaryAttachment() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.gen("Bundle", "bundle@pgpony.app")
        val ops = MimeOps(repo)

        val textAttachment = dir.resolve("readme.txt").also { Files.writeString(it, "attached text") }
        val binaryPayload = Random(11).nextBytes(80_000)
        val binaryAttachment = dir.resolve("photo.jpg").also { Files.write(it, binaryPayload) }

        val armored = ops.encryptBundle(
            "bundle body text",
            listOf(textAttachment, binaryAttachment),
            listOf(key.fingerprint),
            key.fingerprint,
            "test-passphrase"
        )
        assertTrue(armored.contains("BEGIN PGP MESSAGE"))

        val result = ops.decryptStructured(armored, "test-passphrase")
        assertEquals("bundle body text", result.body.trim())
        assertEquals(2, result.attachments.size)
        assertTrue(result.signatureVerified, "bundle signature must verify")

        val text = result.attachments.first { it.filename == "readme.txt" }
        assertEquals("attached text", String(text.data, Charsets.UTF_8))
        val binary = result.attachments.first { it.filename == "photo.jpg" }
        assertContentEquals(binaryPayload, binary.data, "binary attachment survives base64 transfer")
        db.close()
    }

    @Test
    fun nonMimePlaintextPassesThrough() = runBlocking {
        val (db, repo, _) = setup()
        val key = repo.gen("Plain", "plain@pgpony.app")
        val ops = MimeOps(repo)

        val armored = repo.encryptText(
            "just ordinary text",
            listOf(repo.loadPublicKeyRing(key.fingerprint)!!),
            null, null
        )
        val result = ops.decryptStructured(armored, "test-passphrase")
        assertEquals("just ordinary text", result.body)
        assertTrue(result.attachments.isEmpty())
        db.close()
    }

    @Test
    fun emlWrapExtractsAndDecrypts() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.gen("Eml", "eml@pgpony.app")
        val ops = MimeOps(repo)

        val attachment = dir.resolve("doc.txt").also { Files.writeString(it, "eml attachment") }
        val armored = ops.encryptBundle(
            "eml body", listOf(attachment), listOf(key.fingerprint), null, null
        )
        val eml = ops.buildEml(armored, subject = "Test bundle")

        assertTrue(eml.startsWith("Subject: Test bundle"))
        assertTrue(eml.contains("multipart/encrypted"))
        assertTrue(eml.contains("application/pgp-encrypted"))
        assertNotNull(
            MimeParser.pgpMimeEncryptedPayload(eml),
            "the armored payload must be extractable from the .eml"
        )

        // Decrypting the FULL .eml text must work — the structured path strips it first.
        val result = ops.decryptStructured(eml, "test-passphrase")
        assertEquals("eml body", result.body.trim())
        assertEquals(1, result.attachments.size)
        assertEquals("eml attachment", String(result.attachments.single().data, Charsets.UTF_8))
        db.close()
    }

    @Test
    fun emlFileDecryptsToBundleFolder() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.gen("EmlFile", "emlfile@pgpony.app")
        val mimeOps = MimeOps(repo)
        val fileOps = FileCryptoOps(repo)

        val attachment = dir.resolve("plan.txt").also { Files.writeString(it, "the plan") }
        val armored = mimeOps.encryptBundle(
            "eml file body", listOf(attachment), listOf(key.fingerprint), key.fingerprint, "test-passphrase"
        )
        val emlFile = dir.resolve("message.eml")
        Files.writeString(emlFile, mimeOps.buildEml(armored))

        // The field-reported flow: the .eml goes through the FILES decrypt path.
        val outcome = fileOps.decryptFile(emlFile, "test-passphrase")
        assertTrue(outcome.ok, outcome.detail)
        val outDir = outcome.output!!
        assertTrue(Files.isDirectory(outDir), "bundle unpacks into a folder")
        assertEquals("message", outDir.fileName.toString())
        assertEquals("eml file body", Files.readString(outDir.resolve("body.txt")).trim())
        assertEquals("the plan", Files.readString(outDir.resolve("plan.txt")))
        assertTrue(outcome.detail.contains("VERIFIED"), outcome.detail)

        // A bare armored-message FILE (non-eml) also decrypts via the text path.
        val plainArmored = repo.encryptText(
            "armored file body", listOf(repo.loadPublicKeyRing(key.fingerprint)!!), null, null
        )
        val ascFile = dir.resolve("note.asc")
        Files.writeString(ascFile, plainArmored)
        val plain = fileOps.decryptFile(ascFile, "test-passphrase")
        assertTrue(plain.ok, plain.detail)
        assertEquals("note", plain.output!!.fileName.toString())
        assertEquals("armored file body", Files.readString(plain.output))
        db.close()
    }

    @Test
    fun symmetricBundleRoundTrip() = runBlocking {
        val (db, repo, dir) = setup()
        repo.gen("Sym", "sym@pgpony.app")   // ensures decrypt has rings to try before SKESK
        val ops = MimeOps(repo)

        val attachment = dir.resolve("data.bin").also { Files.write(it, Random(3).nextBytes(10_000)) }
        val armored = ops.encryptBundleSymmetric("symmetric bundle", listOf(attachment), "horse-staple")
        val result = ops.decryptStructured(armored, "horse-staple")
        assertEquals("symmetric bundle", result.body.trim())
        assertEquals(1, result.attachments.size)
        db.close()
    }
}
