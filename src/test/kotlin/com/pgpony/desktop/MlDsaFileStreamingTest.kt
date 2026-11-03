// MlDsaFileStreamingTest.kt
// PGPony Desktop 3.1.0 (#14): files signed with an ML-DSA (composite) key stream like any other.
// Encrypt-and-sign and detached signing used to read the whole file into memory under a 512 MB
// ceiling; Android 4.7.0 item 23 hashes the content as it streams, and the desktop now takes
// that path for single files, folders and detached signatures. The decrypt side grades the
// streamed signature from its digests (DecryptStreamResult.compositeStreamed), which the
// summary has to read, or a good signature would show as "signed by a key not held".
//
// The size check past the old limit is gated (-DrunLarge=true): it writes a 600 MB file.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.runBlocking
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.Path
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MlDsaFileStreamingTest {

    private class Env(val db: com.pgpony.android.data.PGPDatabase, val repo: DesktopKeyRepository, val dir: Path)

    private fun env(): Env {
        val dir = Files.createTempDirectory("pgpony-mldsa-stream")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Env(db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))), dir)
    }

    /** An ML-DSA-65 + Ed25519 v6 key (with its ML-KEM encryption subkey), trusted, no passphrase. */
    private suspend fun DesktopKeyRepository.mlDsaKey(name: String) =
        generateKey(name, "${name.lowercase().replace(' ', '.')}@example.invalid", KeyAlgorithm.MLDSA65_ED25519_V6, null)
            .also { updateTrustLevel(it.fingerprint, TrustLevel.ULTIMATE) }

    @Test
    fun anMlDsaSignedFileEncryptsAsAStreamAndItsSignatureVerifies() = runBlocking {
        val e = env()
        val key = e.repo.mlDsaKey("Stream Signer")
        val ops = FileCryptoOps(e.repo)
        val payload = Random(23).nextBytes(3 * 1024 * 1024 + 17)
        val original = e.dir.resolve("big.bin")
        Files.write(original, payload)

        val enc = ops.encryptFile(original, listOf(key.fingerprint), key.fingerprint, null, armor = false)
        assertTrue(enc.ok, enc.detail)

        val moved = e.dir.resolve("out").also { Files.createDirectories(it) }.resolve("big.bin.gpg")
        Files.move(enc.output!!, moved)
        val dec = ops.decryptFile(moved, null)
        assertTrue(dec.ok, dec.detail)
        assertContentEquals(payload, Files.readAllBytes(dec.output!!))
        assertTrue(dec.detail.contains("VERIFIED"), "the streamed ML-DSA signature verifies: ${dec.detail}")
        e.db.close()
    }

    @Test
    fun anMlDsaSignedFolderEncryptsAsAStream() = runBlocking {
        val e = env()
        val key = e.repo.mlDsaKey("Folder Signer")
        val ops = FileCryptoOps(e.repo)
        val folder = e.dir.resolve("project").also { Files.createDirectories(it) }
        Files.write(folder.resolve("a.bin"), Random(1).nextBytes(400_000))
        Files.writeString(folder.resolve("b.txt"), "second file")

        val enc = ops.encryptFolder(folder, listOf(key.fingerprint), key.fingerprint, null, armor = false)
        assertTrue(enc.ok, enc.detail)
        val dec = ops.decryptFile(enc.output!!, null)
        assertTrue(dec.ok, dec.detail)
        assertTrue(dec.detail.contains("VERIFIED"), dec.detail)
        e.db.close()
    }

    @Test
    fun anMlDsaDetachedSignatureStreamsAndCatchesTampering() = runBlocking {
        val e = env()
        val key = e.repo.mlDsaKey("Detached Signer")
        val ops = FileCryptoOps(e.repo)
        val artifact = e.dir.resolve("release.tar.gz")
        Files.write(artifact, Random(5).nextBytes(2 * 1024 * 1024))

        for (armor in listOf(true, false)) {
            val signed = ops.signFileDetached(artifact, key.fingerprint, null, armor = armor)
            assertTrue(signed.ok, signed.detail)
            val ok = ops.verifyFileDetached(signed.output!!, artifact)
            assertTrue(ok.ok, ok.detail)
            assertTrue(ok.detail.contains("VERIFIED"), ok.detail)
            Files.delete(signed.output)
        }

        val signed = ops.signFileDetached(artifact, key.fingerprint, null, armor = false)
        RandomAccessFile(artifact.toFile(), "rw").use { it.seek(1_000_000); it.write(0x42) }
        val bad = ops.verifyFileDetached(signed.output!!, artifact)
        assertFalse(bad.ok, bad.detail)
        e.db.close()
    }

    @Test
    fun aFilePastTheOld512MbLimitEncryptsAndSigns() = runBlocking {
        if (System.getProperty("runLarge") != "true") return@runBlocking
        val e = env()
        val key = e.repo.mlDsaKey("Large Signer")
        val ops = FileCryptoOps(e.repo)
        val big = e.dir.resolve("huge.img")
        val chunk = Random(9).nextBytes(1 shl 20)
        Files.newOutputStream(big).use { out -> repeat(600) { out.write(chunk) } }

        val enc = ops.encryptFile(big, listOf(key.fingerprint), key.fingerprint, null, armor = false)
        assertTrue(enc.ok, enc.detail)
        val signed = ops.signFileDetached(big, key.fingerprint, null, armor = false)
        assertTrue(signed.ok, signed.detail)
        val ok = ops.verifyFileDetached(signed.output!!, big)
        assertTrue(ok.ok, ok.detail)
        assertEquals(true, ok.detail.contains("VERIFIED"), ok.detail)
        e.db.close()
    }
}
