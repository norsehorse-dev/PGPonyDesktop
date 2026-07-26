// FileCryptoTest.kt
// D3b validation: file round-trips on the vendored STREAM APIs — binary + armored encrypt,
// literal-filename restoration, signature survival in file decrypts, detached file signatures
// with tamper detection, no-overwrite output naming, and the verify pairing helper.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class FileCryptoTest {

    private fun setup(): Triple<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository, Path> {
        val dir = Files.createTempDirectory("pgpony-file-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Triple(db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))), dir)
    }

    private suspend fun DesktopKeyRepository.gen(name: String, email: String) =
        generateKey(name, email, KeyAlgorithm.ED25519_CV25519, "test-passphrase")

    @Test
    fun binaryFileSignedRoundTrip() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.gen("File RT", "filert@pgpony.app")
        val ops = FileCryptoOps(repo)

        val payload = Random(42).nextBytes(200_000)   // deterministic 200 KB binary
        val original = dir.resolve("report.pdf")
        Files.write(original, payload)

        val enc = ops.encryptFile(
            original, listOf(key.fingerprint), key.fingerprint, "test-passphrase", armor = false
        )
        assertTrue(enc.ok, enc.detail)
        assertEquals("report.pdf.gpg", enc.output!!.fileName.toString())

        // Move the ciphertext elsewhere so name restoration must come from the literal packet.
        val moved = dir.resolve("sub").also { Files.createDirectories(it) }.resolve("blob.gpg")
        Files.move(enc.output, moved)

        val dec = ops.decryptFile(moved, "test-passphrase")
        assertTrue(dec.ok, dec.detail)
        assertEquals("report.pdf", dec.output!!.fileName.toString(), "literal filename restored")
        assertContentEquals(payload, Files.readAllBytes(dec.output), "bytes survive")
        assertTrue(dec.detail.contains("VERIFIED"), "signature state surfaces: ${dec.detail}")
        db.close()
    }

    @Test
    fun armoredFileRoundTripAndNoOverwrite() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.gen("Armor RT", "armorrt@pgpony.app")
        val ops = FileCryptoOps(repo)

        val original = dir.resolve("notes.txt")
        Files.writeString(original, "armored file payload")

        val enc = ops.encryptFile(original, listOf(key.fingerprint), null, null, armor = true)
        assertTrue(enc.ok, enc.detail)
        assertEquals("notes.txt.asc", enc.output!!.fileName.toString())
        assertTrue(Files.readString(enc.output).contains("BEGIN PGP MESSAGE"))

        // Decrypting next to the original must not overwrite it.
        val dec = ops.decryptFile(enc.output, "test-passphrase")
        assertTrue(dec.ok, dec.detail)
        assertEquals("notes-1.txt", dec.output!!.fileName.toString(), "no-overwrite naming")
        assertEquals("armored file payload", Files.readString(dec.output))
        assertFalse(dec.detail.contains("VERIFIED"), "unsigned encrypt stays unsigned")
        db.close()
    }

    @Test
    fun detachedFileSignatureVerifiesAndTamperFails() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.gen("Detached File", "detfile@pgpony.app")
        val ops = FileCryptoOps(repo)

        val artifact = dir.resolve("artifact.bin")
        Files.write(artifact, Random(7).nextBytes(50_000))

        val signed = ops.signFileDetached(artifact, key.fingerprint, "test-passphrase", armor = true)
        assertTrue(signed.ok, signed.detail)
        assertEquals("artifact.bin.asc", signed.output!!.fileName.toString())

        val ok = ops.verifyFileDetached(signed.output, artifact)
        assertTrue(ok.ok, ok.detail)
        assertTrue(ok.detail.contains("VERIFIED"))

        Files.write(artifact, Random(8).nextBytes(50_000))   // tamper
        val bad = ops.verifyFileDetached(signed.output, artifact)
        assertFalse(bad.ok)
        assertTrue(bad.detail.contains("INVALID"), bad.detail)
        db.close()
    }

    @Test
    fun multiFileEncryptLoopAndVerifyPairing() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.gen("Multi", "multi@pgpony.app")
        val ops = FileCryptoOps(repo)

        val files = (1..3).map { i ->
            dir.resolve("doc$i.txt").also { Files.writeString(it, "content $i") }
        }
        val outcomes = files.map { ops.encryptFile(it, listOf(key.fingerprint), null, null, armor = false) }
        assertEquals(3, outcomes.count { it.ok })
        outcomes.forEachIndexed { i, o -> assertEquals("doc${i + 1}.txt.gpg", o.output!!.fileName.toString()) }

        // pairDetached: sibling-based pairing
        val content = dir.resolve("paired.txt").also { Files.writeString(it, "pair me") }
        val sigOutcome = ops.signFileDetached(content, key.fingerprint, "test-passphrase", armor = false)
        assertNotNull(sigOutcome.output)
        assertEquals("paired.txt.sig", sigOutcome.output.fileName.toString())
        val pairs = FileCryptoOps.pairDetached(listOf(sigOutcome.output))
        assertEquals(1, pairs.size)
        assertEquals(content, pairs.single().second)

        // two-file fallback pairing
        val other = dir.resolve("other.dat").also { Files.write(it, byteArrayOf(1, 2, 3)) }
        val sig2 = ops.signFileDetached(other, key.fingerprint, "test-passphrase", armor = true)
        val renamedSig = dir.resolve("somewhere.asc")
        Files.move(sig2.output!!, renamedSig)
        val fallbackPairs = FileCryptoOps.pairDetached(listOf(other, renamedSig))
        assertEquals(1, fallbackPairs.size)
        assertEquals(renamedSig, fallbackPairs.single().first)
        assertTrue(ops.verifyFileDetached(renamedSig, other).ok)
        db.close()
    }
}
