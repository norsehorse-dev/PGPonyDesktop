// TransportTest.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4c (plan section 7): zip output for transport and
// decrypting a zip that holds a PGP message (Android #31, 4.4.1 audit item 9), and the animated
// multi-part QR (Android 4.4.1 audit item 10, the 4.5.1 density).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.io.path.name
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TransportTest {

    private fun setup(): Triple<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository, Path> {
        val dir = Files.createTempDirectory("pgpony-transport-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Triple(db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))), dir)
    }

    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            for ((name, bytes) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private fun entryNames(file: Path): List<String> = ZipInputStream(Files.newInputStream(file)).use { zip ->
        generateSequence { zip.nextEntry }.map { it.name }.toList()
    }

    private fun leftovers(dir: Path): List<String> =
        Files.list(dir).use { s -> s.map { it.name }.filter { it.startsWith(".pgpony") }.toList() }

    // ── Zip ──

    @Test
    fun aZippedFileRoundTripsAndLeavesNothingBehind() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.generateKey("Zip", "zip@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val ops = FileCryptoOps(repo)
        val payload = Random(31).nextBytes(120_000)
        val work = Files.createDirectories(dir.resolve("work"))
        val original = work.resolve("report.pdf")
        Files.write(original, payload)

        val enc = ops.encryptFile(original, listOf(key.fingerprint), null, null, armor = false, zip = true)
        assertTrue(enc.ok, enc.detail)
        assertEquals("report.pdf.gpg.zip", enc.output!!.name)
        assertTrue(ZipTransport.looksLikeZip(enc.output!!))
        assertEquals(listOf("report.pdf.gpg"), entryNames(enc.output!!), "one entry, the ciphertext")
        Files.delete(original)

        val dec = ops.decryptFile(enc.output!!, null)
        assertTrue(dec.ok, dec.detail)
        assertEquals(enc.output, dec.input)
        assertEquals(work.resolve("report.pdf"), dec.output, "lands beside the zip under its own name")
        assertContentEquals(payload, Files.readAllBytes(dec.output!!))
        assertEquals(emptyList(), leftovers(work), "no scratch folder or temp file left")
        db.close()
    }

    @Test
    fun aZippedFolderRoundTrips() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.generateKey("Folder", "folder@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val ops = FileCryptoOps(repo)
        val work = Files.createDirectories(dir.resolve("work"))
        val folder = Files.createDirectories(work.resolve("docs"))
        Files.writeString(folder.resolve("a.txt"), "alpha")
        Files.writeString(folder.resolve("b.txt"), "beta")

        val enc = ops.encryptFolder(folder, listOf(key.fingerprint), null, null, armor = true, zip = true)
        assertTrue(enc.ok, enc.detail)
        assertEquals("docs.tar.asc.zip", enc.output!!.name)

        val dec = ops.decryptFile(enc.output!!, null)
        assertTrue(dec.ok, dec.detail)
        val out = assertNotNull(dec.output)
        assertTrue(Files.isDirectory(out))
        // The archive keeps the folder's own name as its top entry (TarStreamer.archive).
        assertEquals("alpha", Files.readString(out.resolve("docs").resolve("a.txt")))
        assertEquals("beta", Files.readString(out.resolve("docs").resolve("b.txt")))
        assertEquals(emptyList(), leftovers(work))
        db.close()
    }

    @Test
    fun zipsWithoutExactlyOneMessageAreReportedAndEntryNamesStayInside() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.generateKey("Names", "names@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        val ops = FileCryptoOps(repo)
        val work = Files.createDirectories(dir.resolve("work"))

        val none = work.resolve("none.zip").also { Files.write(it, zipOf("notes.txt" to "hi".toByteArray())) }
        val r1 = ops.decryptFile(none, null)
        assertFalse(r1.ok)
        assertEquals(tr("decrypt_zip_no_pgp"), r1.detail)

        val two = work.resolve("two.zip").also {
            Files.write(it, zipOf("a.gpg" to byteArrayOf(1), "b.asc" to byteArrayOf(2)))
        }
        val r2 = ops.decryptFile(two, null)
        assertFalse(r2.ok)
        assertEquals(tr("decrypt_zip_multiple"), r2.detail)

        val armored = repo.encryptText("inside", listOf(repo.loadPublicKeyRing(key.fingerprint)!!), null, null)
        val hostile = work.resolve("hostile.zip").also {
            Files.write(it, zipOf("../../escape.txt.asc" to armored.toByteArray()))
        }
        val r3 = ops.decryptFile(hostile, null)
        assertTrue(r3.ok, r3.detail)
        assertEquals(work, r3.output!!.parent, "the entry's path is dropped")
        assertEquals("inside", Files.readString(r3.output!!).trim())
        assertFalse(Files.exists(dir.resolve("escape.txt")))
        assertEquals(emptyList(), leftovers(work))
        db.close()
    }

    @Test
    fun theRouterOpensAMessageZipToDecryptAndOtherZipsToEncrypt() {
        val msg = zipOf("letter.txt.gpg" to byteArrayOf(0x85.toByte(), 1, 2))
        assertIs<OpenAction.DecryptFile>(DesktopFileRouter.classifyBytes(msg, Path.of("letter.zip")))
        val docx = zipOf("[Content_Types].xml" to "<x/>".toByteArray(), "word/document.xml" to "<w/>".toByteArray())
        assertIs<OpenAction.EncryptFile>(DesktopFileRouter.classifyBytes(docx, Path.of("report.docx")))
        val two = zipOf("a.gpg" to byteArrayOf(1), "b.gpg" to byteArrayOf(2))
        assertIs<OpenAction.EncryptFile>(DesktopFileRouter.classifyBytes(two, Path.of("two.zip")))
    }

    @Test
    fun zipEntryNamesAreReducedToABaseName() {
        assertEquals("evil.gpg", ZipTransport.safeEntryName("../../evil.gpg"))
        assertEquals("evil.gpg", ZipTransport.safeEntryName("C:\\temp\\evil.gpg"))
        assertEquals("encrypted.gpg", ZipTransport.safeEntryName(null))
        val out = ByteArrayOutputStream()
        ZipTransport.writeSingleEntry(out, "../up.gpg") { it.write(byteArrayOf(7)) }
        val found = ZipTransport.extractSinglePgpEntry(out.toByteArray().inputStream(), ByteArrayOutputStream())
        assertEquals("up.gpg", assertIs<ZipTransport.Found.One>(found).name)
    }

    // ── Animated QR ──

    private fun fakeArmor(chars: Int): String {
        val body = java.util.Base64.getEncoder().encodeToString(Random(9).nextBytes(chars * 3 / 4))
        return "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: a: b: c\n\n" +
            body.chunked(64).joinToString("\n") + "\n-----END PGP PUBLIC KEY BLOCK-----\n"
    }

    @Test
    fun framesMatchAndroidsFormat() {
        val short = fakeArmor(600)
        assertEquals(listOf(short), QrChunking.split(short), "a small key stays one plain symbol")

        val text = fakeArmor(4_500)
        val frames = assertNotNull(QrChunking.split(text))
        assertEquals((text.length + 999) / 1000, frames.size)
        val id = QrChunking.idFor(text)
        frames.forEachIndexed { i, f -> assertTrue(f.startsWith("PGPONY1:${i + 1}:${frames.size}:$id:"), f.take(40)) }

        val collector = QrChunking.Collector()
        var last: QrChunking.Outcome? = null
        for (f in frames.reversed() + frames.first()) last = collector.offer(f)
        assertEquals(text, assertIs<QrChunking.Outcome.Complete>(last).text, "any order, colons in the armor survive")

        assertNull(QrChunking.split("x".repeat(QrChunking.PAYLOAD_MAX * QrChunking.MAX_FRAMES + 1)))
        assertNull(QrChunking.parse("PGPONY1:3:2:0123abcd:x"), "seq past total")
        assertNull(QrChunking.parse("PGPONY1:1:2:XYZ:x"), "bad id")
    }

    @Test
    fun aPostQuantumKeyRoundTripsThroughFramedImages() = runBlocking {
        val (db, repo, dir) = setup()
        val key = repo.generateKey("PQ QR", "pqqr@pgpony.app", KeyAlgorithm.MLDSA65_ED25519_V6, null)
        val armor = assertNotNull(repo.exportArmoredPublicKeyForSharing(key.fingerprint))
        assertTrue(armor.length > QrChunking.SINGLE_MAX, "large enough to split")
        val pngs = assertNotNull(QrCode.encodeFrames(armor), "fits in the frame ceiling")
        assertTrue(pngs.size > 1)

        val files = pngs.mapIndexed { i, png -> dir.resolve("part$i.png").also { Files.write(it, png) }.toFile() }
        val texts = files.flatMap { QrCode.decodeAllFromImage(it) }
        assertEquals(armor, assertIs<QrCode.Import.Key>(QrCode.importFrom(texts)).armored)

        val partial = QrCode.importFrom(texts.drop(1))
        assertEquals(QrCode.Import.Partial(pngs.size - 1, pngs.size), partial)
        db.close()
    }

    @Test
    fun importTellsKeysFromEverythingElse() {
        assertEquals(QrCode.Import.Empty, QrCode.importFrom(emptyList()))
        assertEquals(QrCode.Import.NotAKey, QrCode.importFrom(listOf("https://example.com")))
        val single = fakeArmor(400)
        assertEquals(QrCode.Import.Key(single), QrCode.importFrom(listOf(single)))
        val a = assertNotNull(QrChunking.split(fakeArmor(3_000)))
        val b = assertNotNull(QrChunking.split(fakeArmor(3_000) + "\n"))
        assertEquals(QrCode.Import.Mixed, QrCode.importFrom(a.dropLast(1) + b.dropLast(1)))
    }
}
