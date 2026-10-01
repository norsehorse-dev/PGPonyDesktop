// B2HardeningTest.kt
// Desktop verification display, local IPC and SOP:
//   SOP-1 / ENGINE-4  composite (ML-DSA) signatures are graded: a revoked or expired signer, or a
//                     creation time outside the hashed area, never verifies (SOP, GUI, CLI, shim);
//   SOP-2             the SOP scratch keyring is owner-only, deleted on close, and stale ones swept;
//   SOP-3             a SOP line pairs the signing key with its own certificate's primary;
//   LOCAL-IPC-1       the git shim reports the key that verified and its trust only;
//   LOCAL-IPC-4       a squatted single-instance port neither blocks forwarding nor starts a
//                     second instance;
//   GAP-1             the card decrypt banner reads the engine's grade like the software path;
//   GAP-3             the Verify banner shows the key that verified, not the issuer subpacket.

package com.pgpony.desktop

import com.pgpony.android.crypto.CertificateBindings
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.SecretKeyUnlock
import com.pgpony.android.crypto.SignerStatus
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.crypto.card.CardDecryptResult
import com.pgpony.android.crypto.pqc.CompositeDocumentSigner
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositePrimaryKeyGen
import com.pgpony.android.crypto.pqc.CompositeSigHash
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.crypto.pqc.CompositeSigner
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.channels.FileChannel
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.Date
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class B2HardeningTest {

    private lateinit var dir: Path
    private val data = "release-1.2.3.tar.gz contents\n".toByteArray()
    private val rnd = SecureRandom()
    private val day = 24L * 60 * 60 * 1000

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("pgpony-b2-test")
        KeyUsePolicy.forced = false
    }

    @AfterTest
    fun tearDown() {
        KeyUsePolicy.forced = null
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private class Run(val code: Int, val out: ByteArray, val err: String) {
        val text: String get() = String(out, Charsets.UTF_8)
    }

    private fun sop(vararg args: String, input: ByteArray = ByteArray(0)): Run {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = Sop.run(args.toList(), ByteArrayInputStream(input), out, PrintStream(err, true)) { null }
        return Run(code, out.toByteArray(), err.toString(Charsets.UTF_8))
    }

    private fun file(name: String, bytes: ByteArray): String = dir.resolve(name).also { Files.write(it, bytes) }.toString()

    private fun repo(): Pair<PGPDatabase, DesktopKeyRepository> {
        val d = Files.createTempDirectory("pgpony-b2-repo")
        val db = Db.open(d.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(d.resolve("keys")))
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    private val suite = CompositeSignSuite.MLDSA65_ED25519

    private class PqKey(val raw: ByteArray, val secret: ByteArray, val fp: ByteArray, val pubBody: ByteArray) {
        val fpHex: String get() = fp.joinToString("") { "%02X".format(it) }
        val publicCert: ByteArray get() = CompositeKeyFacade.publicRingOf(raw)
    }

    private fun pqKey(created: Date = Date(System.currentTimeMillis() - 10 * day), expirySeconds: Long? = null): PqKey {
        val raw = CompositePrimaryKeyGen.assemble("Signer <signer@example.test>", suite, rnd, created, expirySeconds)
        val info = CompositeKeyFacade.parse(raw)
        val primary = CertificateBindings.packets(raw).first()
        return PqKey(raw, info.compositeSecret!!, info.fingerprint, CertificateBindings.publicPart(primary.tag, primary.body)!!)
    }

    private fun u32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    private fun sub(type: Int, body: ByteArray): ByteArray = byteArrayOf((body.size + 1).toByte(), type.toByte()) + body
    private fun createdSub(ms: Long) = sub(2 or 0x80, u32(ms / 1000))
    private fun issuerSub(k: PqKey) = sub(33, byteArrayOf(6) + k.fp)

    /** A v6 composite signature body over [signed] with the given hashed and unhashed areas. */
    private fun sigBody(k: PqKey, type: Int, signed: ByteArray, hashed: ByteArray, unhashed: ByteArray = ByteArray(0)): ByteArray {
        val salt = ByteArray(16).also { rnd.nextBytes(it) }
        val digest = CompositeSigHash.v6DocumentDigest(
            hashAlgorithm = 8, salt = salt, data = signed, signatureType = type,
            publicKeyAlgorithm = suite.algId, hashedSubpacketBody = hashed
        )
        val sig = CompositeSigner.sign(suite, k.secret, digest, rnd)
        return ByteArrayOutputStream().apply {
            write(6); write(type); write(suite.algId); write(8)
            write(u32(hashed.size.toLong())); write(hashed)
            write(u32(unhashed.size.toLong())); write(unhashed)
            write(digest[0].toInt() and 0xFF); write(digest[1].toInt() and 0xFF)
            write(salt.size); write(salt)
            write(sig)
        }.toByteArray()
    }

    /** [cert] (public) with a hard "key compromised" revocation by [k] made now. */
    private fun revoked(k: PqKey, cert: ByteArray): ByteArray {
        val frame = byteArrayOf(0x9B.toByte()) + u32(k.pubBody.size.toLong()) + k.pubBody
        val hashed = createdSub(System.currentTimeMillis()) + sub(29, byteArrayOf(2) + "compromised".toByteArray()) + issuerSub(k)
        val rev = CompositeSigPacket.packet(2, sigBody(k, 0x20, frame, hashed))
        val pkts = CertificateBindings.packets(cert)
        val out = ByteArrayOutputStream()
        out.write(CertificateBindings.frame(pkts[0].tag, pkts[0].body))
        out.write(rev)
        for (p in pkts.drop(1)) out.write(CertificateBindings.frame(p.tag, p.body))
        return out.toByteArray()
    }

    /** A classical detached signature by [sec]'s primary, optionally naming another key in the unhashed area. */
    private fun classicalSig(sec: PGPSecretKeyRing, unhashedIssuer: Long? = null): PGPSignature {
        val key = sec.secretKey
        val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(key.publicKey.algorithm, HashAlgorithmTags.SHA256), key.publicKey)
        gen.init(PGPSignature.BINARY_DOCUMENT, SecretKeyUnlock.extract(key, null))
        val h = PGPSignatureSubpacketGenerator()
        h.setSignatureCreationTime(false, Date())
        gen.setHashedSubpackets(h.generate())
        gen.update(data)
        val sig = gen.generate()
        if (unhashedIssuer == null) return sig
        val b = CertificateBindings.packets(sig.encoded).first().body
        val hLen = ((b[4].toInt() and 0xFF) shl 8) or (b[5].toInt() and 0xFF)
        val uAt = 6 + hLen
        val uLen = ((b[uAt].toInt() and 0xFF) shl 8) or (b[uAt + 1].toInt() and 0xFF)
        val issuer = byteArrayOf(9, 16) + ByteArray(8) { i -> (unhashedIssuer ushr (56 - 8 * i)).toByte() }
        val body = b.copyOfRange(0, uAt) + byteArrayOf(0, issuer.size.toByte()) + issuer + b.copyOfRange(uAt + 2 + uLen, b.size)
        val list = org.bouncycastle.openpgp.bc.BcPGPObjectFactory(CertificateBindings.frame(2, body)).nextObject()
            as org.bouncycastle.openpgp.PGPSignatureList
        return list[0]
    }

    // ── SOP-1 ───────────────────────────────────────────────────────────────

    @Test
    fun sop1ARevokedCompositeSignerDoesNotVerifyInSop() {
        val k = pqKey()
        val sig = file("pq.sig", CompositeDocumentSigner.signDetached(suite, k.secret, k.fp, data, random = rnd))
        val good = file("pq.cert", k.publicCert)
        val bad = file("pq-revoked.cert", revoked(k, k.publicCert))

        val ok = sop("verify", sig, good, input = data)
        assertEquals(0, ok.code, ok.err)
        assertTrue(ok.text.contains("${k.fpHex} ${k.fpHex} mode:binary"), ok.text)
        assertEquals(SopExit.NO_SIGNATURE, sop("verify", sig, bad, input = data).code, "revoked: no verification")

        val inline = CompositeDocumentSigner.signInline(suite, k.secret, k.fp, data, random = rnd)
        assertEquals(0, sop("inline-verify", good, input = inline).code)
        assertEquals(SopExit.NO_SIGNATURE, sop("inline-verify", bad, input = inline).code, "revoked: inline too")
    }

    @Test
    fun sop1DecryptVerifyWithIgnoresARevokedCompositeSigner() {
        val k = pqKey()
        val keyFile = file("pq-signer.key", k.raw)
        val recipient = sop("generate-key", "--profile=rfc9580", "Reader <reader@example.test>")
        assertEquals(0, recipient.code, recipient.err)
        val recipientKey = file("reader.key", recipient.out)
        val recipientCert = file("reader.cert", sop("extract-cert", input = recipient.out).out)
        val ct = sop("encrypt", "--sign-with=$keyFile", recipientCert, input = data)
        assertEquals(0, ct.code, ct.err)

        fun verifications(cert: ByteArray, name: String): List<String> {
            val out = dir.resolve("$name.verifications").toString()
            val r = sop("decrypt", "--verify-with=${file("$name.cert", cert)}", "--verifications-out=$out", recipientKey, input = ct.out)
            assertEquals(0, r.code, r.err)
            return Files.readAllLines(Path.of(out)).filter { it.isNotBlank() }
        }
        assertEquals(1, verifications(k.publicCert, "pq-good").size)
        assertEquals(0, verifications(revoked(k, k.publicCert), "pq-revoked").size, "a revoked signer gives no verification")
    }

    @Test
    fun sop1AnExpiredCompositeSignerDoesNotVerifyInSop() {
        val k = pqKey(expirySeconds = 24L * 60 * 60)
        val sig = file("pq-expired.sig", CompositeDocumentSigner.signDetached(suite, k.secret, k.fp, data, random = rnd))
        assertEquals(SopExit.NO_SIGNATURE, sop("verify", sig, file("pq-expired.cert", k.publicCert), input = data).code)
    }

    @Test
    fun sop1TheCreationTimeComesFromTheHashedAreaOnly() {
        val k = pqKey()
        val now = System.currentTimeMillis()
        val unhashedOnly = CompositeSigPacket.packet(2, sigBody(k, 0, data, issuerSub(k), unhashed = createdSub(now)))
        assertNull(SopSigInfo.parse(unhashedOnly)!!.created, "an unhashed creation time is not read")
        val sig = file("pq-unhashed.sig", unhashedOnly)
        assertEquals(SopExit.NO_SIGNATURE, sop("verify", sig, file("pq-u.cert", k.publicCert), input = data).code)

        val hashed = CompositeSigPacket.packet(2, sigBody(k, 0, data, createdSub(now) + issuerSub(k), unhashed = createdSub(now - 30 * day)))
        assertEquals(now / 1000, SopSigInfo.parse(hashed)!!.created!!.time / 1000, "the hashed one wins over an unhashed one")
    }

    // ── ENGINE-4 / SOP-1 in the app: DesktopCompositeVerify ─────────────────

    @Test
    fun engine4TheAppGradesCompositeSignersToo() = runBlocking {
        val k = pqKey()
        val armored = CompositeDocumentSigner.signDetachedArmored(suite, k.secret, k.fp, data, random = rnd)

        val (db1, plain) = repo()
        plain.importBytes(k.publicCert)
        val v = assertIs<VerificationResult.Verified>(DesktopCompositeVerify.verifyDetached(plain, armored, data))
        assertEquals(k.fpHex, v.signerFingerprint)
        assertEquals(k.fpHex, v.signingKeyFingerprint)
        db1.close()

        val (db2, withRevocation) = repo()
        withRevocation.importBytes(revoked(k, k.publicCert))
        val r = DesktopCompositeVerify.verifyDetached(withRevocation, armored, data)
        val invalid = assertIs<VerificationResult.Invalid>(r, "a revoked signer is never Verified")
        assertEquals(SignerStatus.REVOKED_KEY, invalid.signerStatus)
        val line = SignatureSummary.verifyLine(withRevocation, invalid)
        assertEquals(SignatureSummary.Tone.BAD, line.tone)
        // The git shim says REVKEYSIG, never GOODSIG.
        val status = ByteArrayOutputStream()
        val code = GpgShim.report(invalid, PrintStream(ByteArrayOutputStream(), true), PrintStream(status, true)) { null }
        assertEquals(1, code)
        assertTrue(status.toString().contains("[GNUPG:] REVKEYSIG"), status.toString())
        assertFalse(status.toString().contains("GOODSIG"))
        db2.close()
    }

    // ── SOP-2 ───────────────────────────────────────────────────────────────

    @Test
    fun sop2TheScratchKeyringIsPrivateAndGoesOnClose() {
        val k = SopKeyring.open()
        val scratch = k.dir
        assertTrue(Files.isDirectory(scratch))
        if ("posix" in FileSystems.getDefault().supportedFileAttributeViews()) {
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(scratch)))
        }
        Files.writeString(scratch.resolve("keys").also { Files.createDirectories(it) }.resolve("x.sec.asc"), "secret")
        k.close()
        assertFalse(Files.exists(scratch), "deleted on close")
        k.close() // twice is harmless
    }

    @Test
    fun sop2StaleScratchFoldersAreSweptAndLiveOnesKept() {
        val tmp = Files.createTempDirectory("pgpony-b2-tmp")
        val own = Files.createDirectory(tmp.resolve("pgpony-sop-own"))

        fun scratch(name: String, withLock: Boolean): Path {
            val d = Files.createDirectory(tmp.resolve(name))
            Files.createDirectories(d.resolve("keys"))
            Files.writeString(d.resolve("keys").resolve("abc.sec.asc"), "-----BEGIN PGP PRIVATE KEY BLOCK-----")
            Files.writeString(d.resolve("sop.db"), "db")
            if (withLock) Files.createFile(d.resolve(".lock"))
            return d
        }

        val dead = scratch("pgpony-sop-dead", withLock = true)
        val live = scratch("pgpony-sop-live", withLock = true)
        val liveLock = FileChannel.open(live.resolve(".lock"), StandardOpenOption.WRITE)
        val held = liveLock.tryLock()
        assertNotNull(held)
        val oldUnlocked = scratch("pgpony-sop-old", withLock = false)
        Files.setLastModifiedTime(oldUnlocked, FileTime.fromMillis(System.currentTimeMillis() - 2 * 60 * 60 * 1000))
        val recentUnlocked = scratch("pgpony-sop-recent", withLock = false)
        val unrelated = scratch("unrelated-folder", withLock = true)
        val outside = Files.createTempDirectory("pgpony-b2-outside")
        Files.writeString(outside.resolve("keep.txt"), "keep")
        val link = runCatching { Files.createSymbolicLink(tmp.resolve("pgpony-sop-link"), outside) }.getOrNull()
        // Everything above is a few minutes old, except one folder whose invocation has just
        // created it and not yet taken its lock: that one is kept.
        val minutesAgo = FileTime.fromMillis(System.currentTimeMillis() - 5 * 60 * 1000)
        for (d in listOf(dead, live, recentUnlocked, unrelated)) Files.setLastModifiedTime(d, minutesAgo)
        val starting = scratch("pgpony-sop-starting", withLock = true)

        try {
            SopKeyring.sweepStale(tmp, own)
            assertFalse(Files.exists(dead), "a folder no running process holds is swept")
            assertTrue(Files.exists(live.resolve("keys").resolve("abc.sec.asc")), "a running invocation's folder is kept")
            assertFalse(Files.exists(oldUnlocked), "an old folder from a version without the lock is swept")
            assertTrue(Files.exists(recentUnlocked), "a recent one is left alone")
            assertTrue(Files.exists(starting.resolve("keys").resolve("abc.sec.asc")), "a folder just created is left alone")
            assertTrue(Files.exists(unrelated))
            assertTrue(Files.exists(own))
            if (link != null) assertTrue(Files.exists(outside.resolve("keep.txt")), "a link is never followed")
        } finally {
            runCatching { held.release() }
            liveLock.close()
        }
    }

    // ── SOP-3 and LOCAL-IPC-1 / GAP-3: the key that verified ────────────────

    @Test
    fun localIpc1TheShimAndTheVerifyBannerNameTheKeyThatVerified() = runBlocking {
        val (db, repo) = repo()
        val a = repo.generateKey("Mallory", "mallory@example.test", KeyAlgorithm.ED25519_CV25519, null)
        val b = repo.generateKey("Alice", "alice@example.test", KeyAlgorithm.ED25519_CV25519, null)
        repo.updateTrustLevel(b.fingerprint, TrustLevel.ULTIMATE)
        repo.updateTrustLevel(a.fingerprint, TrustLevel.UNKNOWN)
        val aSec = repo.loadSecretKeyRing(a.fingerprint)!!
        val aPub = repo.loadPublicKeyRing(a.fingerprint)!!
        val bPub = repo.loadPublicKeyRing(b.fingerprint)!!
        val sig = classicalSig(aSec, unhashedIssuer = bPub.publicKey.keyID)
        assertEquals(bPub.publicKey.keyID, sig.keyID, "precondition: the signature names Alice's key")

        val result = VerifyService.shared.verifyDetached(sig.encoded, data, listOf(bPub, aPub))
        val v = assertIs<VerificationResult.Verified>(result)

        // The git shim: GOODSIG and VALIDSIG name Mallory's key, trust is Mallory's (none).
        val status = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = GpgShim.report(v, PrintStream(err, true), PrintStream(status, true)) { fp -> runBlocking { repo.byFingerprint(fp) } }
        assertEquals(0, code)
        val lines = status.toString().lines().filter { it.isNotBlank() }
        val aId = String.format("%016X", aPub.publicKey.keyID)
        val bId = String.format("%016X", bPub.publicKey.keyID)
        assertTrue(lines.any { it.startsWith("[GNUPG:] GOODSIG $aId ") }, lines.toString())
        assertFalse(status.toString().contains(bId), "Alice's key ID appears nowhere")
        val validsig = lines.single { it.startsWith("[GNUPG:] VALIDSIG ") }.split(' ')
        assertEquals(hex(aPub.publicKey.fingerprint), validsig[2], "the signing key first")
        assertEquals(hex(aPub.publicKey.fingerprint), validsig[11], "the primary as field 10, as gpg writes it")
        assertTrue(lines.contains("[GNUPG:] TRUST_UNDEFINED 0 pgp"), "never Alice's ULTIMATE")
        assertTrue(err.toString().contains("WARNING"), "an unconfirmed key is said to be one")

        // The Verify tab: Mallory's key fingerprint, amber, never Alice's ID.
        val line = SignatureSummary.verifyLine(repo, v)
        assertEquals(SignatureSummary.Tone.WARN, line.tone)
        assertTrue(line.text.contains(hex(aPub.publicKey.fingerprint).chunked(4).joinToString(" ")), line.text)
        assertFalse(line.text.contains(bId))

        // SOP: the line pairs Mallory's key with Mallory's primary.
        val pair = SopCrypto.verifyClassical(listOf(bPub, aPub), sig.encoded, data)
        assertEquals(hex(aPub.publicKey.fingerprint) to hex(aPub.publicKey.fingerprint), pair)
        assertNull(SopCrypto.verifyClassical(listOf(bPub), sig.encoded, data), "without the signer's certificate, no line")
        db.close()
    }

    @Test
    fun localIpc1RevokedExpiredAndBadSignaturesNeverReadGood() {
        val fp = "AB".repeat(20)
        fun statusOf(r: VerificationResult): Pair<Int, String> {
            val out = ByteArrayOutputStream()
            val code = GpgShim.report(r, PrintStream(ByteArrayOutputStream(), true), PrintStream(out, true)) { null }
            return code to out.toString()
        }
        for ((st, word) in listOf(
            SignerStatus.REVOKED_KEY to "REVKEYSIG",
            SignerStatus.EXPIRED_KEY to "EXPKEYSIG",
            SignerStatus.EXPIRED_SIGNATURE to "EXPSIG",
            SignerStatus.NOT_SIGNING_KEY to "BADSIG"
        )) {
            val (code, text) = statusOf(VerificationResult.Invalid("no", fp.take(16), null, st, fp, fp))
            assertEquals(1, code)
            assertTrue(text.contains("[GNUPG:] $word "), "$st: $text")
            assertFalse(text.contains("GOODSIG"))
        }
        val (code, text) = statusOf(VerificationResult.Invalid("bad", null, null))
        assertEquals(1, code)
        assertTrue(text.contains("[GNUPG:] BADSIG 0000000000000000"))
    }

    @Test
    fun localIpc1AHyphenIsTheStdinOperand() {
        val err = ByteArrayOutputStream()
        val code = GpgShim.run(
            listOf("--status-fd=1", "--verify", dir.resolve("missing.sig").toString(), "-"),
            ByteArrayInputStream(data), ByteArrayOutputStream(), PrintStream(err, true)
        )
        assertEquals(2, code)
        assertTrue(err.toString().contains("cannot read signature"), "'-' is accepted as the data operand: $err")
    }

    // ── GAP-1: the card banner reads the engine's grade ─────────────────────

    @Test
    fun gap1TheCardBannerFollowsTheSoftwareRules() = runBlocking {
        val (db, repo) = repo()
        val k = repo.generateKey("Bob Smith", "bob@example.com", KeyAlgorithm.ED25519_CV25519, null)
        repo.updateTrustLevel(k.fingerprint, TrustLevel.UNKNOWN)
        fun card(status: SignerStatus, primary: String? = k.fingerprint.uppercase(), weak: String? = null) = CardDecryptResult(
            data = "Pay Bob".toByteArray(), filename = null, hadSignature = true, signerKnown = true,
            signatureVerified = status == SignerStatus.VERIFIED, signerKeyID = k.longKeyId,
            signerStatus = status, signerWeakKey = weak,
            signingKeyFingerprint = primary, signerPrimaryFingerprint = primary
        )

        val unconfirmed = SignatureSummary.decryptLine(SignatureSummary.ofCard(repo, card(SignerStatus.VERIFIED)), onCard = true)
        assertEquals(SignatureSummary.Tone.WARN, unconfirmed.tone, "a key nobody confirmed reads amber on the card path too")

        repo.updateTrustLevel(k.fingerprint, TrustLevel.VERIFIED)
        assertEquals(SignatureSummary.Tone.GOOD, SignatureSummary.decryptLine(SignatureSummary.ofCard(repo, card(SignerStatus.VERIFIED)), onCard = true).tone)

        val weak = SignatureSummary.decryptLine(SignatureSummary.ofCard(repo, card(SignerStatus.VERIFIED, weak = "RSA 1024")), onCard = true)
        assertTrue(weak.text.contains("RSA 1024"), "the weak-key note: ${weak.text}")

        val revoked = SignatureSummary.decryptLine(SignatureSummary.ofCard(repo, card(SignerStatus.REVOKED_KEY)), onCard = true)
        assertEquals(SignatureSummary.Tone.BAD, revoked.tone)

        val unbound = SignatureSummary.ofCard(repo, card(SignerStatus.VERIFIED, primary = null))
        assertEquals(SignatureSummary.State.UNCONFIRMED, unbound.state, "no certificate validly holds the key")

        val unknown = SignatureSummary.ofCard(repo, card(SignerStatus.UNKNOWN_SIGNER, primary = null))
        assertEquals(SignatureSummary.State.UNHELD, unknown.state)
        db.close()
    }

    // ── LOCAL-IPC-4: the single-instance channel ────────────────────────────

    @Test
    fun localIpc4AnIdleSquatterDoesNotStopForwardingOrStartASecondInstance() {
        val appDir = Files.createTempDirectory("pgpony-b2-instance")
        val delivered = CopyOnWriteArrayList<OpenRequest>()
        AppOpen.setHandler { delivered += it }
        assertTrue(SingleInstance.acquire(appDir, OpenRequest(emptyList())), "the first launch is primary")
        val port = Files.readString(appDir.resolve(".instance.port")).trim().substringBefore(' ').toInt()

        val idle = (1..24).map { java.net.Socket(java.net.InetAddress.getLoopbackAddress(), port) }
        try {
            var notAnswering = false
            val file = appDir.resolve("message.asc").also { Files.writeString(it, "x") }
            assertFalse(SingleInstance.acquire(appDir, OpenRequest(listOf(file))) { notAnswering = true }, "never a second primary")
            assertFalse(notAnswering)
            val deadline = System.currentTimeMillis() + 5_000
            while (delivered.none { file in it.paths } && System.currentTimeMillis() < deadline) Thread.sleep(50)
            assertTrue(delivered.any { file in it.paths }, "the file reached the running instance")
        } finally {
            idle.forEach { runCatching { it.close() } }
        }
    }

    @Test
    fun localIpc4AnUnreachablePrimaryIsReportedNotDuplicated() {
        val appDir = Files.createTempDirectory("pgpony-b2-instance-dead")
        val lockChannel = FileChannel.open(appDir.resolve(".instance.lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        val lock = lockChannel.tryLock()
        Files.writeString(appDir.resolve(".instance.port"), "1 ${"0".repeat(64)}\n")
        try {
            var notAnswering = false
            val file = appDir.resolve("message.asc").also { Files.writeString(it, "x") }
            assertFalse(SingleInstance.acquire(appDir, OpenRequest(listOf(file))) { notAnswering = true })
            assertTrue(notAnswering, "the user is told; no second window starts")
        } finally {
            runCatching { lock?.release() }
            lockChannel.close()
        }
    }
}
