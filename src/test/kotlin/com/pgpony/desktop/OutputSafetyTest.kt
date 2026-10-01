// OutputSafetyTest.kt
// 3.0.0: decrypted outputs are created new (a link at the name is never followed), readable by
// the owner only on every path, named from a plain base name valid on every desktop OS, and
// nothing is left behind when a decrypt fails after the plaintext was written. Also the zip
// transport's expansion bound and the decrypt signature reading (FILES-2, FILES-5, FILES-6,
// FILES-7, FILES-8, ENGINE-2).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.mime.MimeAttachment
import com.pgpony.android.crypto.mime.MimeBuilder
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Date
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Keys and hand-built messages shared by the B1 tests. */
internal object B1Fixtures {

    class Env(val db: com.pgpony.android.data.PGPDatabase, val repo: DesktopKeyRepository, val dir: Path) {
        fun close() = db.close()
    }

    fun env(): Env {
        val dir = Files.createTempDirectory("pgpony-b1")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Env(db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))), dir)
    }

    suspend fun key(repo: DesktopKeyRepository, name: String) =
        repo.generateKey(name, "${name.lowercase().filter { it.isLetter() }}@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)

    suspend fun pub(repo: DesktopKeyRepository, fp: String): PGPPublicKeyRing = repo.loadPublicKeyRing(fp)!!
    suspend fun sec(repo: DesktopKeyRepository, fp: String): PGPSecretKeyRing = repo.loadSecretKeyRing(fp)!!

    /** An ordinary encrypted message with literal filename [name]. */
    fun encrypt(to: PGPPublicKeyRing, data: ByteArray, name: String?, armor: Boolean, signer: PGPSecretKeyRing? = null): ByteArray {
        val out = ByteArrayOutputStream()
        PGPCryptoService.shared.encryptStream(
            input = data.inputStream(), output = out, recipientPublicKeys = listOf(to),
            signingSecretKey = signer, filename = name, armor = armor
        )
        return out.toByteArray()
    }

    fun literal(data: ByteArray, name: String): ByteArray {
        val bo = ByteArrayOutputStream()
        PGPLiteralDataGenerator().open(bo, PGPLiteralData.BINARY, name, data.size.toLong(), Date()).use { it.write(data) }
        return bo.toByteArray()
    }

    /** One-pass, literal and signature packets by [signer]; the signature covers [signedOver]. */
    fun signedParts(signer: PGPSecretKeyRing, data: ByteArray, signedOver: ByteArray = data): ByteArray {
        val sk = PGPCryptoService.shared.pickSigningSecretKey(signer)!!
        val priv = sk.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)))
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(sk.publicKey.algorithm, HashAlgorithmTags.SHA256), sk.publicKey)
        gen.init(PGPSignature.BINARY_DOCUMENT, priv)
        val sp = PGPSignatureSubpacketGenerator()
        sp.setIssuerFingerprint(false, sk.publicKey)
        sp.setSignatureCreationTime(false, Date())
        gen.setHashedSubpackets(sp.generate())
        val ops = ByteArrayOutputStream().also { gen.generateOnePassVersion(false).encode(it) }.toByteArray()
        gen.update(signedOver)
        val sig = ByteArrayOutputStream().also { gen.generate().encode(it) }.toByteArray()
        return ops + literal(data, "signed.txt") + sig
    }

    /** [plainPackets] encrypted as they are (SEIPDv1 with MDC) to [to]. */
    fun encryptRaw(plainPackets: ByteArray, to: PGPPublicKeyRing): ByteArray {
        val bo = ByteArrayOutputStream()
        val g = PGPEncryptedDataGenerator(BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true))
        val ek = to.publicKeys.asSequence().first { it.isEncryptionKey && !it.isMasterKey }
        g.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(ek))
        g.open(bo, plainPackets.size.toLong()).use { it.write(plainPackets) }
        return bo.toByteArray()
    }

    val posix: Boolean get() = FileSystems.getDefault().supportedFileAttributeViews().contains("posix")

    fun perms(p: Path): String =
        PosixFilePermissions.toString(Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS))

    fun leftovers(dir: Path): List<String> = Files.list(dir).use { s ->
        s.map { it.fileName.toString() }.filter { it.startsWith(".pgpony") }.toList()
    }
}

class OutputSafetyTest {

    @Test
    fun files2ArmoredDecryptDoesNotFollowADanglingLinkAtTheOutputName() = runBlocking {
        val env = B1Fixtures.env()
        val k = B1Fixtures.key(env.repo, "Victim")
        val share = Files.createDirectories(env.dir.resolve("share"))
        val elsewhere = Files.createDirectories(env.dir.resolve("elsewhere"))
        val planted = elsewhere.resolve("planted.txt")
        val link = runCatching { Files.createSymbolicLink(share.resolve("report.txt"), planted) }.getOrNull()
            ?: return@runBlocking env.close()
        val msg = share.resolve("report.txt.asc")
        Files.write(msg, B1Fixtures.encrypt(B1Fixtures.pub(env.repo, k.fingerprint), "payload".toByteArray(), "report.txt", armor = true))

        val dec = FileCryptoOps(env.repo).decryptFile(msg, null)
        assertTrue(dec.ok, dec.detail)
        assertFalse(Files.exists(planted, LinkOption.NOFOLLOW_LINKS), "nothing was written through the link")
        assertTrue(Files.isSymbolicLink(link), "the link itself is untouched")
        assertEquals("report-1.txt", dec.output!!.fileName.toString())
        assertEquals("payload", Files.readString(dec.output))
        env.close()
    }

    @Test
    fun files2StreamingDecryptDoesNotReplaceOrFollowALink() = runBlocking {
        val env = B1Fixtures.env()
        val k = B1Fixtures.key(env.repo, "Victim")
        val share = Files.createDirectories(env.dir.resolve("share"))
        val planted = env.dir.resolve("planted.bin")
        val link = runCatching { Files.createSymbolicLink(share.resolve("data.bin"), planted) }.getOrNull()
            ?: return@runBlocking env.close()
        val msg = share.resolve("data.bin.gpg")
        Files.write(msg, B1Fixtures.encrypt(B1Fixtures.pub(env.repo, k.fingerprint), ByteArray(70_000) { 7 }, "data.bin", armor = false))

        val dec = FileCryptoOps(env.repo).decryptFile(msg, null)
        assertTrue(dec.ok, dec.detail)
        assertFalse(Files.exists(planted, LinkOption.NOFOLLOW_LINKS))
        assertTrue(Files.isSymbolicLink(link))
        assertEquals("data-1.bin", dec.output!!.fileName.toString())
        assertEquals(emptyList(), B1Fixtures.leftovers(share))
        env.close()
    }

    @Test
    fun files8EveryDecryptPathWritesOwnerOnlyOutput() = runBlocking {
        if (!B1Fixtures.posix) return@runBlocking
        val env = B1Fixtures.env()
        val k = B1Fixtures.key(env.repo, "Owner")
        val pub = B1Fixtures.pub(env.repo, k.fingerprint)
        val ops = FileCryptoOps(env.repo)

        val armored = env.dir.resolve("a.txt.asc").also { Files.write(it, B1Fixtures.encrypt(pub, "a".toByteArray(), "a.txt", armor = true)) }
        val binary = env.dir.resolve("b.txt.gpg").also { Files.write(it, B1Fixtures.encrypt(pub, "b".toByteArray(), "b.txt", armor = false)) }
        val bundleBytes = MimeBuilder.buildMixed("hello", listOf(MimeAttachment("x.bin", "application/octet-stream", byteArrayOf(1, 2))))
        val bundle = env.dir.resolve("mail.asc").also { Files.write(it, B1Fixtures.encrypt(pub, bundleBytes, null, armor = true)) }
        val folder = Files.createDirectories(env.dir.resolve("src/tree/sub"))
        Files.writeString(folder.resolve("f.txt"), "inside")
        val encFolder = ops.encryptFolder(env.dir.resolve("src/tree"), listOf(k.fingerprint), null, null, armor = false)
        assertTrue(encFolder.ok, encFolder.detail)
        val tarMsg = Files.move(encFolder.output!!, Files.createDirectories(env.dir.resolve("in")).resolve("tree.tar.gpg"))

        for (f in listOf(armored, binary)) {
            val d = ops.decryptFile(f, null)
            assertTrue(d.ok, d.detail)
            assertEquals("rw-------", B1Fixtures.perms(d.output!!), f.toString())
        }
        val b = ops.decryptFile(bundle, null)
        assertTrue(b.ok, b.detail)
        assertEquals("rwx------", B1Fixtures.perms(b.output!!))
        Files.list(b.output).use { s -> s.forEach { assertEquals("rw-------", B1Fixtures.perms(it), it.toString()) } }

        val t = ops.decryptFile(tarMsg, null)
        assertTrue(t.ok, t.detail)
        assertEquals("rwx------", B1Fixtures.perms(t.output!!))
        assertEquals("rwx------", B1Fixtures.perms(t.output.resolve("tree/sub")))
        assertEquals("rw-------", B1Fixtures.perms(t.output.resolve("tree/sub/f.txt")))
        assertEquals("inside", Files.readString(t.output.resolve("tree/sub/f.txt")))
        env.close()
    }

    @Test
    fun files7ANameTooLongForTheFileSystemFallsBackAndLeavesNoTempBehind() = runBlocking {
        val env = B1Fixtures.env()
        val k = B1Fixtures.key(env.repo, "Long")
        val pub = B1Fixtures.pub(env.repo, k.fingerprint)
        val ops = FileCryptoOps(env.repo)
        // 253 UTF-8 bytes: fits a literal packet (255 at most) but not NAME_MAX once numbered.
        val cjk = "\u6587".repeat(83) + ".txt"
        // Where file names are not UTF-8 (sun.jnu.encoding), the name cannot be used at all and
        // the default name is the answer; elsewhere a shortened name is.
        runCatching {
            Files.writeString(Files.createDirectories(env.dir.resolve("box-false")).resolve("\u6587".repeat(65) + ".txt"), "taken")
        }
        for (armor in listOf(false, true)) {
            val box = Files.createDirectories(env.dir.resolve("box-$armor"))
            val msg = box.resolve(if (armor) "m.asc" else "m.gpg")
            Files.write(msg, B1Fixtures.encrypt(pub, "long".toByteArray(), cjk, armor))
            val dec = ops.decryptFile(msg, null)
            assertTrue(dec.ok, dec.detail)
            val name = dec.output!!.fileName.toString()
            assertTrue(name.toByteArray(Charsets.UTF_8).size <= 210, name)
            assertTrue(name.endsWith(".txt") || name == "m", name)
            assertEquals("long", Files.readString(dec.output))
            assertEquals(emptyList(), B1Fixtures.leftovers(box))
        }
        env.close()
    }

    @Test
    fun files5WindowsDriveAndDeviceNamesStayInTheFolder() = runBlocking {
        val env = B1Fixtures.env()
        val k = B1Fixtures.key(env.repo, "Win")
        val pub = B1Fixtures.pub(env.repo, k.fingerprint)
        val ops = FileCryptoOps(env.repo)
        val box = Files.createDirectories(env.dir.resolve("box"))

        val msg = box.resolve("x.gpg").also { Files.write(it, B1Fixtures.encrypt(pub, "d".toByteArray(), "D:payload.exe", armor = false)) }
        val d = ops.decryptFile(msg, null)
        assertTrue(d.ok, d.detail)
        assertEquals(box, d.output!!.parent)
        assertEquals("D_payload.exe", d.output.fileName.toString())

        val mime = MimeBuilder.buildMixed(
            null,
            listOf(
                MimeAttachment("C:evil.exe", "application/octet-stream", byteArrayOf(1)),
                MimeAttachment("AUX.txt", "text/plain", byteArrayOf(2)),
                MimeAttachment("..\\..\\up.txt", "text/plain", byteArrayOf(3))
            )
        )
        val bundle = box.resolve("mail.asc").also { Files.write(it, B1Fixtures.encrypt(pub, mime, null, armor = true)) }
        val b = ops.decryptFile(bundle, null)
        assertTrue(b.ok, b.detail)
        val names = Files.list(b.output!!).use { s -> s.map { it.fileName.toString() }.toList() }.toSet()
        assertEquals(setOf("C_evil.exe", "_AUX.txt", "up.txt"), names)
        env.close()
    }

    @Test
    fun engine2AnUnsignedLiteralAroundASignedOneFailsAndLeavesNothing() = runBlocking {
        val env = B1Fixtures.env()
        val alice = B1Fixtures.key(env.repo, "Alice")
        val bob = B1Fixtures.key(env.repo, "Bob")
        val box = Files.createDirectories(env.dir.resolve("box"))
        val signed = B1Fixtures.signedParts(B1Fixtures.sec(env.repo, alice.fingerprint), "release notes".toByteArray())
        val evil = B1Fixtures.literal("EVIL".toByteArray(), "evil.txt")
        for ((label, packets) in listOf("prefix" to (evil + signed), "suffix" to (signed + evil))) {
            val msg = box.resolve("$label.gpg")
            Files.write(msg, B1Fixtures.encryptRaw(packets, B1Fixtures.pub(env.repo, bob.fingerprint)))
            val d = FileCryptoOps(env.repo).decryptFile(msg, null)
            assertFalse(d.ok, "$label: ${d.detail}")
            assertEquals(null, d.output)
        }
        assertEquals(setOf("prefix.gpg", "suffix.gpg"), Files.list(box).use { s -> s.map { it.fileName.toString() }.toList() }.toSet())
        env.close()
    }

    @Test
    fun files6ADeflateBombInAZipIsRefusedAndTheScratchFolderGoes() = runBlocking {
        val env = B1Fixtures.env()
        B1Fixtures.key(env.repo, "Zip")
        val box = Files.createDirectories(env.dir.resolve("box"))
        val zip = box.resolve("report.zip")
        ZipOutputStream(Files.newOutputStream(zip)).use { z ->
            z.putNextEntry(ZipEntry("x.gpg"))
            val zeros = ByteArray(1 shl 20)
            repeat(80) { z.write(zeros) }
            z.closeEntry()
        }
        assertTrue(Files.size(zip) < 1_000_000, "the bomb is small")
        val d = FileCryptoOps(env.repo).decryptFile(zip, null)
        assertFalse(d.ok, d.detail)
        assertTrue(d.detail.contains("expands"), d.detail)
        assertEquals(listOf("report.zip"), Files.list(box).use { s -> s.map { it.fileName.toString() }.toList() })
        env.close()
    }

    @Test
    fun files6ZipCopyAllowsOrdinaryCiphertextAndStopsExpansion() {
        val random = ByteArray(3 shl 20).also { java.util.Random(1).nextBytes(it) }
        val zipped = ByteArrayOutputStream().also { bo ->
            ZipTransport.writeSingleEntry(bo, "big.gpg") { it.write(random) }
        }.toByteArray()
        val out = ByteArrayOutputStream()
        val found = ZipTransport.extractSinglePgpEntry(zipped.inputStream(), out)
        assertTrue(found is ZipTransport.Found.One)
        assertContentEquals(random, out.toByteArray())

        val sink = java.io.OutputStream.nullOutputStream()
        val big = object : java.io.InputStream() {
            var left = 200L shl 20
            override fun read(): Int = if (left-- > 0) 0 else -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (left <= 0) return -1
                val n = minOf(len.toLong(), left).toInt()
                java.util.Arrays.fill(b, off, off + n, 0)
                left -= n
                return n
            }
        }
        val error = runCatching { ZipTransport.copyToCapped(big, sink, Long.MAX_VALUE) { 1L shl 20 } }.exceptionOrNull()
        assertNotNull(error)
        assertTrue(error.message!!.contains("expands"), error.message)
    }

    @Test
    fun aFileDecryptSignedByAHeldKeyThatDidNotPassReadsInvalid() = runBlocking {
        val env = B1Fixtures.env()
        val alice = B1Fixtures.key(env.repo, "Alice")
        val bob = B1Fixtures.key(env.repo, "Bob")
        val packets = B1Fixtures.signedParts(
            B1Fixtures.sec(env.repo, alice.fingerprint), "content".toByteArray(), signedOver = "different".toByteArray()
        )
        val msg = env.dir.resolve("bad.gpg").also { Files.write(it, B1Fixtures.encryptRaw(packets, B1Fixtures.pub(env.repo, bob.fingerprint))) }
        val d = FileCryptoOps(env.repo).decryptFile(msg, null)
        assertTrue(d.ok, d.detail)
        assertTrue(d.detail.endsWith(tr("d_file_sig_invalid")), d.detail)
        env.close()
    }

    @Test
    fun files6ABareArmoredMessageIsRecognizedForTheStream() {
        assertTrue(FileCryptoOps.startsWithArmor("\n\n-----BEGIN PGP MESSAGE-----\n\nhQ"))
        assertFalse(FileCryptoOps.startsWithArmor("From: a@b\n-----BEGIN PGP MESSAGE-----\n"))
    }

    @Test
    fun files2NewOutputsSkipTakenNamesIncludingDanglingLinks() {
        val dir = Files.createTempDirectory("pgpony-safefiles")
        val taken = runCatching { Files.createSymbolicLink(dir.resolve("a.txt"), dir.resolve("missing")) }.getOrNull()
        Files.createDirectory(dir.resolve("a-1.txt"))
        val p = SafeFiles.writeNew(dir, "a.txt", "x".toByteArray(), ownerOnly = true)
        assertEquals(if (taken != null) "a-2.txt" else "a.txt", p.fileName.toString())
        assertFalse(Files.exists(dir.resolve("missing")))
        val sub = SafeFiles.createNewDir(dir, "a-1.txt", ownerOnly = true)
        assertEquals("a-1-1.txt", sub.fileName.toString())
        assertEquals(null, SafeFiles.plainName(".."))
        assertEquals("x_y", SafeFiles.plainName("x:y"))
        assertEquals("evil", SafeFiles.plainName("../../evil"))
    }
}
