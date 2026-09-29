// SopCrypto.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5a: the SOP subcommands that touch keys, on the
// engine the app uses. See Sop.kt for the shape and SopKeyring below for the scratch keyring.
//
// Verification lines (VERIFICATIONS): each signature packet is checked on its own through the
// engine (VerifyService for classical signatures, CompositeDocumentVerifier for ML-DSA), and a
// good one is reported as "<creation time> <signing key fp> <primary key fp> mode:<binary|text>".
// The engine grades the signer too (revoked, expired, not a signing key), as it does in the app.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoError
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.crypto.pqc.CompositeDocumentSigner
import com.pgpony.android.crypto.pqc.CompositeDocumentVerifier
import com.pgpony.android.crypto.pqc.CompositeKeyFacade
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.crypto.pqc.CompositeSignSuite
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Date

/**
 * The scratch keyring one SOP invocation works in: a database and key store in a new
 * owner-only temporary folder, deleted on close.
 */
internal class SopKeyring private constructor(private val dir: Path, private val db: PGPDatabase) : AutoCloseable {

    val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    private val crypto = PGPCryptoService.shared

    companion object {
        fun open(): SopKeyring {
            val dir = if ("posix" in FileSystems.getDefault().supportedFileAttributeViews()) {
                Files.createTempDirectory("pgpony-sop", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            } else {
                Files.createTempDirectory("pgpony-sop")
            }
            return SopKeyring(dir, Db.open(dir.resolve("sop.db")))
        }
    }

    override fun close() {
        runCatching { db.close() }
        runCatching {
            Files.walk(dir).use { walk -> walk.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
        }
    }

    /** Every key or certificate in [data], loaded, in input order. BAD_DATA when there is none. */
    suspend fun load(data: ByteArray, what: String): List<PGPKeyEntity> {
        val out = mutableListOf<PGPKeyEntity>()
        for (block in blocks(data)) {
            repo.importBytes(block)
            val fp = fingerprintOf(block) ?: continue
            val e = repo.byFingerprint(fp) ?: continue
            if (out.none { it.fingerprint == e.fingerprint }) out += e
        }
        if (out.isEmpty()) throw SopException(SopExit.BAD_DATA, "no OpenPGP $what found")
        return out.map { repo.byFingerprint(it.fingerprint) ?: it }
    }

    private fun isRawComposite(raw: ByteArray): Boolean = runCatching {
        CompositeKeyFacade.isCompositePrimary(raw) || CompositeKeyFacade.hasV4Algo35Subkey(raw)
    }.getOrDefault(false)

    private fun blocks(data: ByteArray): List<ByteArray> {
        if (SopArmor.isArmored(data)) {
            val text = String(data, Charsets.UTF_8)
            val armored = Regex("-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----[\\s\\S]*?-----END PGP \\1 KEY BLOCK-----")
                .findAll(text).map { it.value.toByteArray(Charsets.UTF_8) }.toList()
            return armored.flatMap { explodeOrWhole(it) }
        }
        return explodeOrWhole(data)
    }

    private fun explodeOrWhole(block: ByteArray): List<ByteArray> {
        val raw = runCatching { SopArmor.binary(block) }.getOrNull() ?: return emptyList()
        if (isRawComposite(raw)) return listOf(block)
        val exploded = runCatching { crypto.explodeToArmoredKeys(block) }.getOrDefault(emptyList())
        return if (exploded.isEmpty()) listOf(block) else exploded.map { it.toByteArray(Charsets.UTF_8) }
    }

    private fun fingerprintOf(block: ByteArray): String? {
        val raw = runCatching { SopArmor.binary(block) }.getOrNull() ?: return null
        runCatching {
            if (CompositeKeyFacade.isCompositePrimary(raw)) return CompositeKeyFacade.parse(raw).fingerprintHex
        }
        runCatching {
            if (CompositeKeyFacade.hasV4Algo35Subkey(raw)) {
                CompositeKeyFacade.v4Algo35BaseBytes(raw)?.let { return crypto.importKeyData(it).fingerprint }
            }
        }
        return runCatching { crypto.importKeyData(raw).fingerprint }.getOrNull()
    }

    /** A classical public ring to verify with, the v4 interop key's Ed25519 base included. */
    suspend fun verifyRing(e: PGPKeyEntity): PGPPublicKeyRing? {
        repo.loadPublicKeyRing(e.fingerprint)?.let { return it }
        val raw = repo.rawPublicBytes(e.fingerprint) ?: return null
        if (!runCatching { CompositeKeyFacade.hasV4Algo35Subkey(raw) }.getOrDefault(false)) return null
        val base = CompositeKeyFacade.v4Algo35BaseBytes(raw) ?: return null
        return runCatching { PGPPublicKeyRing(base, BcKeyFingerprintCalculator()) }.getOrNull()
    }
}

/** An inclusive creation-time window for signatures (--not-before, --not-after). */
internal data class SopWindow(val notBefore: Date?, val notAfter: Date?) {
    fun contains(d: Date): Boolean =
        (notBefore == null || !d.before(notBefore)) && (notAfter == null || !d.after(notAfter))

    companion object {
        /** "-" is unbounded, "now" is now; otherwise an ISO 8601 date or time (UTC when no zone). */
        fun parse(notBefore: String?, notAfter: String?): SopWindow =
            SopWindow(notBefore?.let { date(it, endOfDay = false) }, date(notAfter ?: "now", endOfDay = true))

        private fun date(s: String, endOfDay: Boolean): Date? {
            if (s == "-") return null
            if (s == "now") return Date()
            val instant = runCatching { Instant.parse(s) }.getOrNull()
                ?: runCatching { OffsetDateTime.parse(s).toInstant() }.getOrNull()
                ?: runCatching { LocalDateTime.parse(s).toInstant(ZoneOffset.UTC) }.getOrNull()
                ?: runCatching {
                    OffsetDateTime.parse(s, DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmssX")).toInstant()
                }.getOrNull()
                ?: runCatching {
                    val day = LocalDate.parse(s).atStartOfDay().toInstant(ZoneOffset.UTC)
                    if (endOfDay) day.plus(1, ChronoUnit.DAYS).minusSeconds(1) else day
                }.getOrNull()
                ?: throw SopException(SopExit.UNSUPPORTED_OPTION, "not a date: $s")
            return Date.from(instant)
        }
    }
}

internal object SopCrypto {

    private val crypto = PGPCryptoService.shared

    private val HASH_NAMES = mapOf(
        2 to "sha1", 8 to "sha256", 9 to "sha384", 10 to "sha512", 11 to "sha224", 12 to "sha3-256", 14 to "sha3-512"
    )

    // ── Shared helpers ──────────────────────────────────────────────────────

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02X".format(it) }

    private fun concat(parts: List<ByteArray>): ByteArray = parts.fold(ByteArray(0)) { acc, b -> acc + b }

    /** Line endings as CRLF, for a text signature made or checked outside BouncyCastle. */
    private fun canonicalText(data: ByteArray): ByteArray =
        String(data, Charsets.UTF_8).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n").toByteArray(Charsets.UTF_8)

    private fun requireText(data: ByteArray) {
        if (SopIo.decodeUtf8(data) == null) throw SopException(SopExit.EXPECTED_TEXT, "the input is not UTF-8 text")
    }

    private fun keyPasswords(a: SopArgs, io: SopIo): List<String?> =
        (listOf<String?>(null) + a.all("--with-key-password").flatMap { io.passwordsForReading(it) }).distinct()

    private fun requireSigner(k: PGPKeyEntity) {
        if (!k.isKeyPair) throw SopException(SopExit.BAD_DATA, "${k.fingerprint} is a certificate, not a key")
        if (k.isRevoked || KeyUsePolicy.isExpired(k)) {
            throw SopException(SopExit.KEY_CANNOT_SIGN, "key ${k.fingerprint} is revoked or expired")
        }
    }

    private fun parseAs(value: String?, allowed: Set<String>): String {
        val v = value ?: "binary"
        if (v !in allowed) throw SopException(SopExit.UNSUPPORTED_OPTION, "unsupported --as=$v")
        return v
    }

    /** Try [attempt] with each password; a passphrase failure moves on, then KEY_IS_PROTECTED. */
    private inline fun <T> withKeyPasswords(passwords: List<String?>, protected: Boolean, attempt: (String?) -> T): T {
        for (p in passwords) {
            try {
                return attempt(p)
            } catch (_: SigningError.PassphraseRequired) {
                // next
            } catch (_: SigningError.InvalidPassphrase) {
                // next
            } catch (e: SigningError.NoSigningKey) {
                throw SopException(SopExit.KEY_CANNOT_SIGN, e.message ?: "no signing key")
            } catch (e: PGPCryptoError.SigningFailed) {
                if (!protected) throw e
            }
        }
        throw SopException(SopExit.KEY_IS_PROTECTED, "the key is protected; give its password with --with-key-password")
    }

    private fun unlockComposite(r: SopKeyring, k: PGPKeyEntity, passwords: List<String?>): CompositeKeyFacade.Info {
        for (p in passwords) {
            val info = runCatching { r.repo.loadCompositeKeyInfo(k.fingerprint, p?.toCharArray()) }.getOrNull() ?: continue
            if (info.compositeSecret != null) return info
        }
        throw SopException(SopExit.KEY_IS_PROTECTED, "the key is protected; give its password with --with-key-password")
    }

    // ── generate-key, extract-cert ──────────────────────────────────────────

    fun generateKey(rest: List<String>, io: SopIo, out: OutputStream): Int {
        val a = SopArgs(rest, setOf("--with-key-password", "--profile"), setOf("--no-armor", "--signing-only"))
        val profile = a.value("--profile")?.takeUnless { it == "default" } ?: Sop.KEY_PROFILES.keys.first()
        val algorithm = Sop.KEY_PROFILES[profile]?.second
            ?: throw SopException(SopExit.UNSUPPORTED_PROFILE, "unknown profile $profile")
        val pass = a.value("--with-key-password")?.let { io.passwordForWriting(it) }?.ifEmpty { null }
        val uids = a.positionals
        if (uids.isEmpty()) throw SopException(SopExit.UNSUPPORTED_OPTION, "this build makes keys with at least one User ID")
        val signingOnly = a.flag("--signing-only")
        if (signingOnly && algorithm != KeyAlgorithm.V6_ED25519) {
            throw SopException(SopExit.UNSUPPORTED_OPTION, "--signing-only is available with the rfc9580 profile")
        }
        val armored = SopKeyring.open().use { r ->
            runBlocking {
                val (name, email) = PGPKeyEntity.parseUserID(uids.first())
                val e = if (signingOnly) r.repo.generateGranularKey(name, email, false, emptyList(), pass)
                else r.repo.generateKey(name, email, algorithm, pass)
                val edits = DesktopKeyEdits(r.repo)
                uids.drop(1).forEach { edits.addUserId(e.fingerprint, it, false, pass) }
                r.repo.exportArmoredPrivateKey(e.fingerprint)
                    ?: throw SopException(SopExit.BAD_DATA, "the new key could not be exported")
            }
        }
        out.write(SopArmor.output(SopArmor.binary(armored.toByteArray(Charsets.UTF_8)), SopArmor.PRIVATE_KEY, a.flag("--no-armor")))
        return SopExit.OK
    }

    fun extractCert(rest: List<String>, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(rest, emptySet(), setOf("--no-armor"))
        if (a.positionals.isNotEmpty()) throw SopException(SopExit.UNSUPPORTED_OPTION, "extract-cert takes no arguments")
        val data = stdin.readBytes()
        val certs = SopKeyring.open().use { r ->
            runBlocking {
                r.load(data, "key").map { k ->
                    if (!k.isKeyPair) throw SopException(SopExit.BAD_DATA, "the input holds a certificate, not a key")
                    val armored = r.repo.exportArmoredPublicKey(k.fingerprint)
                        ?: throw SopException(SopExit.BAD_DATA, "no certificate for ${k.fingerprint}")
                    SopArmor.binary(armored.toByteArray(Charsets.UTF_8))
                }
            }
        }
        out.write(SopArmor.output(concat(certs), SopArmor.PUBLIC_KEY, a.flag("--no-armor")))
        return SopExit.OK
    }

    // ── sign, verify ────────────────────────────────────────────────────────

    private suspend fun signOne(r: SopKeyring, k: PGPKeyEntity, data: ByteArray, text: Boolean, passwords: List<String?>): ByteArray {
        requireSigner(k)
        if (k.algorithm.isCompositeSign) {
            val info = unlockComposite(r, k, passwords)
            return CompositeSigPacket.buildDocumentSignature(
                info.suite, info.compositeSecret!!,
                if (text) CompositeSigPacket.TYPE_TEXT else CompositeSigPacket.TYPE_BINARY,
                if (text) canonicalText(data) else data,
                info.fingerprint, (System.currentTimeMillis() / 1000L).toInt()
            )
        }
        val ring = r.repo.loadSecretKeyRing(k.fingerprint) ?: throw SopException(SopExit.BAD_DATA, "key ${k.fingerprint} could not be loaded")
        val protected = crypto.isPassphraseProtected(ring)
        return withKeyPasswords(passwords, protected) { p ->
            SigningService.shared.signDetached(data, ring, p, armor = false, textMode = text)
        }
    }

    fun sign(rest: List<String>, io: SopIo, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(rest, setOf("--as", "--micalg-out", "--with-key-password"), setOf("--no-armor"))
        val text = parseAs(a.value("--as"), setOf("binary", "text")) == "text"
        a.value("--micalg-out")?.let { io.checkOutput(it) }
        if (a.positionals.isEmpty()) throw SopException(SopExit.MISSING_ARG, "sign needs at least one key")
        val passwords = keyPasswords(a, io)
        val data = stdin.readBytes()
        if (text) requireText(data)
        val packets = SopKeyring.open().use { r ->
            runBlocking {
                val keys = a.positionals.flatMap { r.load(io.read(it), "key") }
                keys.map { signOne(r, it, data, text, passwords) }
            }
        }
        a.value("--micalg-out")?.let { dest ->
            val names = packets.mapNotNull { SopSigInfo.parse(it)?.hashAlgo }.map { HASH_NAMES[it] }.distinct()
            val micalg = names.singleOrNull()?.let { "pgp-$it" } ?: ""
            io.write(dest, micalg.toByteArray(Charsets.UTF_8))
        }
        out.write(SopArmor.output(concat(packets), SopArmor.SIGNATURE, a.flag("--no-armor")))
        return SopExit.OK
    }

    /** One VERIFICATIONS line per good signature in [packets] over [data]. */
    internal suspend fun verifyPackets(
        r: SopKeyring,
        certs: List<PGPKeyEntity>,
        packets: List<ByteArray>,
        data: ByteArray,
        window: SopWindow
    ): List<String> {
        val rings = certs.mapNotNull { r.verifyRing(it) }
        val out = LinkedHashSet<String>()
        for (packet in packets) {
            val info = SopSigInfo.parse(packet) ?: continue
            if (info.type != 0x00 && info.type != 0x01) continue
            val created = info.created ?: continue
            if (!window.contains(created)) continue
            val hit = if (CompositeSignSuite.forAlgId(info.pkAlgo) != null) {
                verifyComposite(r, certs, info, packet, data)
            } else {
                verifyClassical(rings, packet, data)
            }
            hit?.let { (signing, primary) ->
                val time = created.toInstant().truncatedTo(ChronoUnit.SECONDS)
                out += "$time $signing $primary mode:${if (info.isText) "text" else "binary"}"
            }
        }
        return out.toList()
    }

    private fun verifyClassical(rings: List<PGPPublicKeyRing>, packet: ByteArray, data: ByteArray): Pair<String, String>? {
        val verdict = runCatching { VerifyService.shared.verifyDetached(packet, data, rings) }.getOrNull()
        val good = verdict as? VerificationResult.Verified ?: return null
        // The engine reports the key the signature verified under, which is not
        // always the one its issuer subpacket names (5d-1).
        val signing = good.signingKeyFingerprint ?: run {
            val sig = runCatching { (JcaPGPObjectFactory(packet).nextObject() as PGPSignatureList)[0] }.getOrNull() ?: return null
            rings.firstNotNullOfOrNull { it.getPublicKey(sig.keyID) }?.let { hex(it.fingerprint) } ?: return null
        }
        return signing.uppercase() to good.signerFingerprint.uppercase()
    }

    private suspend fun verifyComposite(
        r: SopKeyring,
        certs: List<PGPKeyEntity>,
        info: SopSigInfo,
        packet: ByteArray,
        data: ByteArray
    ): Pair<String, String>? {
        val issuer = info.issuerFingerprint ?: return null
        for (e in certs.filter { it.algorithm.isCompositeSign }) {
            val publicInfo = r.repo.loadCompositePublicInfo(e.fingerprint) ?: continue
            val c = publicInfo.compositeSigners.firstOrNull { it.fingerprintHex.equals(issuer, ignoreCase = true) } ?: continue
            val doc = if (info.isText) canonicalText(data) else data
            val ok = runCatching { CompositeDocumentVerifier.verifyDetached(c.publicMaterial, packet, doc).valid }.getOrDefault(false)
            return if (ok) c.fingerprintHex.uppercase() to e.fingerprint.uppercase() else null
        }
        return null
    }

    fun verify(rest: List<String>, io: SopIo, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(rest, setOf("--not-before", "--not-after"), emptySet())
        if (a.positionals.size < 2) throw SopException(SopExit.MISSING_ARG, "verify needs SIGNATURES and at least one CERTS")
        val window = SopWindow.parse(a.value("--not-before"), a.value("--not-after"))
        val packets = SopPackets.signatures(SopArmor.binary(io.read(a.positionals[0])))
        if (packets.isEmpty()) throw SopException(SopExit.BAD_DATA, "no signatures in ${a.positionals[0]}")
        val data = stdin.readBytes()
        val lines = SopKeyring.open().use { r ->
            runBlocking {
                val certs = a.positionals.drop(1).flatMap { r.load(io.read(it), "certificate") }
                verifyPackets(r, certs, packets, data, window)
            }
        }
        if (lines.isEmpty()) throw SopException(SopExit.NO_SIGNATURE, "no valid signature")
        out.write(lines.joinToString("") { "$it\n" }.toByteArray(Charsets.UTF_8))
        return SopExit.OK
    }

    // ── inline-sign, inline-verify ──────────────────────────────────────────

    fun inlineSign(rest: List<String>, io: SopIo, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(rest, setOf("--as", "--with-key-password"), setOf("--no-armor"))
        val mode = parseAs(a.value("--as"), setOf("binary", "text", "clearsigned"))
        val noArmor = a.flag("--no-armor")
        if (mode == "clearsigned" && noArmor) {
            throw SopException(SopExit.INCOMPATIBLE_OPTIONS, "--as=clearsigned is always armored")
        }
        if (a.positionals.isEmpty()) throw SopException(SopExit.MISSING_ARG, "inline-sign needs a key")
        val passwords = keyPasswords(a, io)
        val data = stdin.readBytes()
        if (mode != "binary") requireText(data)
        val result = SopKeyring.open().use { r ->
            runBlocking {
                val keys = a.positionals.flatMap { r.load(io.read(it), "key") }
                if (keys.size != 1) throw SopException(SopExit.UNSUPPORTED_OPTION, "inline-sign with more than one key is not supported")
                val k = keys.single()
                requireSigner(k)
                if (k.algorithm.isCompositeSign) {
                    val info = unlockComposite(r, k, passwords)
                    val secret = info.compositeSecret!!
                    when (mode) {
                        "clearsigned" -> CompositeDocumentSigner.signCleartext(
                            info.suite, secret, info.fingerprint, String(data, Charsets.UTF_8)
                        ).toByteArray(Charsets.UTF_8)
                        "text" -> throw SopException(SopExit.UNSUPPORTED_OPTION, "inline text signatures with ML-DSA keys are not supported")
                        else -> SopArmor.output(
                            CompositeDocumentSigner.signInline(info.suite, secret, info.fingerprint, data), SopArmor.MESSAGE, noArmor
                        )
                    }
                } else {
                    val ring = r.repo.loadSecretKeyRing(k.fingerprint)
                        ?: throw SopException(SopExit.BAD_DATA, "key ${k.fingerprint} could not be loaded")
                    val protected = crypto.isPassphraseProtected(ring)
                    withKeyPasswords(passwords, protected) { p ->
                        if (mode == "clearsigned") {
                            SigningService.shared.signClear(String(data, Charsets.UTF_8), ring, p).toByteArray(Charsets.UTF_8)
                        } else {
                            crypto.sign(data, ring, p ?: "", detached = false, armor = !noArmor, textMode = mode == "text")
                        }
                    }
                }
            }
        }
        out.write(result)
        return SopExit.OK
    }

    /** The signature packets of a decrypted or signed-only message, composite ones included. */
    private fun packetsOf(result: com.pgpony.android.crypto.DecryptResult): List<ByteArray> {
        val composite = result.compositeInlineBytes?.takeIf { result.compositeInline }?.let {
            runCatching { SopPackets.signatures(CompositeDocumentVerifier.decompress(it)) }.getOrDefault(emptyList())
        }.orEmpty()
        return result.signaturePackets + composite
    }

    private fun isCompositeInline(input: ByteArray): Boolean = runCatching {
        CompositeDocumentVerifier.isCompositeInline(SopArmor.binary(input))
    }.getOrDefault(false)

    fun inlineVerify(rest: List<String>, io: SopIo, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(rest, setOf("--not-before", "--not-after", "--verifications-out"), emptySet())
        val verOut = a.value("--verifications-out")
        verOut?.let { io.checkOutput(it) }
        if (a.positionals.isEmpty()) throw SopException(SopExit.MISSING_ARG, "inline-verify needs at least one CERTS")
        val window = SopWindow.parse(a.value("--not-before"), a.value("--not-after"))
        val input = stdin.readBytes()
        val head = String(input, 0, minOf(input.size, 4096), Charsets.ISO_8859_1)
        val (content, lines) = SopKeyring.open().use { r ->
            runBlocking {
                val certs = a.positionals.flatMap { r.load(io.read(it), "certificate") }
                if (head.contains("-----BEGIN PGP SIGNED MESSAGE-----")) {
                    val parsed = com.pgpony.android.crypto.ClearSignedParser.parse(String(input, Charsets.UTF_8))
                        ?: throw SopException(SopExit.BAD_DATA, "a malformed cleartext signed message")
                    val packets = SopPackets.signatures(SopArmor.binary(parsed.signatureBlock.toByteArray(Charsets.UTF_8)))
                    val signed = CompositeSigPacket.canonicalizeCleartext(parsed.cleartext)
                    parsed.cleartext.toByteArray(Charsets.UTF_8) to verifyPackets(r, certs, packets, signed, window)
                } else if (isCompositeInline(input)) {
                    // An ML-DSA signed message: BouncyCastle cannot parse its one-pass packet.
                    val raw = SopArmor.binary(input)
                    val content = CompositeDocumentVerifier.inlineContent(raw)
                        ?: throw SopException(SopExit.BAD_DATA, "a malformed signed message")
                    val packets = SopPackets.signatures(CompositeDocumentVerifier.decompress(raw))
                    content to verifyPackets(r, certs, packets, content, window)
                } else {
                    val rings = certs.mapNotNull { r.verifyRing(it) }
                    val result = try {
                        crypto.decrypt(input, emptyList(), null, rings)
                    } catch (e: Exception) {
                        throw SopException(SopExit.BAD_DATA, "not a signed message: ${e.message}")
                    }
                    result.data to verifyPackets(r, certs, packetsOf(result), result.data, window)
                }
            }
        }
        if (lines.isEmpty()) throw SopException(SopExit.NO_SIGNATURE, "no valid signature")
        out.write(content)
        verOut?.let { io.write(it, lines.joinToString("") { l -> "$l\n" }.toByteArray(Charsets.UTF_8)) }
        return SopExit.OK
    }

    // ── encrypt, decrypt ────────────────────────────────────────────────────

    fun encrypt(rest: List<String>, io: SopIo, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(
            rest, setOf("--as", "--with-password", "--sign-with", "--with-key-password", "--profile"), setOf("--no-armor")
        )
        val text = parseAs(a.value("--as"), setOf("binary", "text")) == "text"
        a.value("--profile")?.let { p ->
            if (p != "default" && p !in Sop.ENCRYPT_PROFILES) throw SopException(SopExit.UNSUPPORTED_PROFILE, "unknown profile $p")
        }
        val noArmor = a.flag("--no-armor")
        val passwords = a.all("--with-password").map { io.passwordForWriting(it) }
        val signerArgs = a.all("--sign-with")
        val certArgs = a.positionals
        if (certArgs.isEmpty() && passwords.isEmpty()) throw SopException(SopExit.MISSING_ARG, "encrypt needs a certificate or a password")
        if (passwords.isNotEmpty() && (certArgs.isNotEmpty() || signerArgs.isNotEmpty())) {
            throw SopException(SopExit.UNSUPPORTED_OPTION, "a password together with certificates or signing is not supported")
        }
        if (passwords.size > 1) throw SopException(SopExit.UNSUPPORTED_OPTION, "one --with-password at a time")
        if (text && signerArgs.isNotEmpty()) throw SopException(SopExit.UNSUPPORTED_OPTION, "text-mode signatures inside encryption are not supported")
        val data = stdin.readBytes()
        if (text) requireText(data)

        if (passwords.isNotEmpty()) {
            out.write(crypto.encryptSymmetric(data, passwords.single(), armor = !noArmor))
            return SopExit.OK
        }
        val keyPasswords = keyPasswords(a, io)
        val ciphertext = SopKeyring.open().use { r ->
            runBlocking {
                val recipients = certArgs.flatMap { r.load(io.read(it), "certificate") }
                val signers = signerArgs.flatMap { r.load(io.read(it), "key") }
                if (signers.size > 1) throw SopException(SopExit.UNSUPPORTED_OPTION, "signing with more than one key is not supported")
                val signer = signers.singleOrNull()?.also { requireSigner(it) }
                val ops = EncryptOps(r.repo)
                var last: Exception? = null
                for (p in if (signer == null) listOf<String?>(null) else keyPasswords) {
                    try {
                        val plan = ops.plan(recipients.map { it.fingerprint }, signer, p, compositeInV1Decision = true)
                        return@runBlocking ops.encryptBytes(plan, data, p, armor = !noArmor)
                    } catch (e: RecipientLoadException) {
                        throw SopException(SopExit.CERT_CANNOT_ENCRYPT, "no usable encryption key: ${e.message}")
                    } catch (e: ExpiredKeyException) {
                        throw SopException(SopExit.CERT_CANNOT_ENCRYPT, e.message ?: "expired certificate")
                    } catch (e: Exception) {
                        if (signer == null) throw e
                        last = e
                    }
                }
                if (signer != null && DesktopKeyEdits(r.repo).isPassphraseProtected(signer.fingerprint)) {
                    throw SopException(SopExit.KEY_IS_PROTECTED, "the signing key is protected; give its password with --with-key-password")
                }
                throw last ?: SopException(SopExit.BAD_DATA, "encryption failed")
            }
        }
        out.write(ciphertext)
        return SopExit.OK
    }

    fun decrypt(rest: List<String>, io: SopIo, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(
            rest,
            setOf(
                "--session-key-out", "--with-session-key", "--with-password", "--with-key-password",
                "--verifications-out", "--verify-out", "--verify-with", "--verify-not-before", "--verify-not-after"
            ),
            emptySet()
        )
        if (a.value("--session-key-out") != null || a.all("--with-session-key").isNotEmpty()) {
            throw SopException(SopExit.UNSUPPORTED_OPTION, "session keys are not supported")
        }
        val verOut = a.value("--verifications-out") ?: a.value("--verify-out")
        verOut?.let { io.checkOutput(it) }
        val verifyWith = a.all("--verify-with")
        if (verOut != null && verifyWith.isEmpty()) {
            throw SopException(SopExit.INCOMPATIBLE_OPTIONS, "--verifications-out needs --verify-with")
        }
        val keyArgs = a.positionals
        val passwordArgs = a.all("--with-password")
        if (keyArgs.isEmpty() && passwordArgs.isEmpty()) throw SopException(SopExit.MISSING_ARG, "decrypt needs a key or a password")
        val window = SopWindow.parse(a.value("--verify-not-before"), a.value("--verify-not-after"))
        val passwords = passwordArgs.flatMap { io.passwordsForReading(it) }
        val keyPasswords = a.all("--with-key-password").flatMap { io.passwordsForReading(it) }

        val ciphertext = stdin.readBytes()
        val tag = com.pgpony.android.crypto.MessageGrammar.firstSignificantTag(SopArmor.binary(ciphertext))
        if (tag !in setOf(1, 3, 9, 18, 20)) throw SopException(SopExit.BAD_DATA, "not an encrypted message")

        val (plaintext, lines) = SopKeyring.open().use { r ->
            runBlocking {
                val keys = keyArgs.flatMap { r.load(io.read(it), "key") }
                keys.forEach { if (!it.isKeyPair) throw SopException(SopExit.BAD_DATA, "${it.fingerprint} is a certificate, not a key") }
                val certs = verifyWith.flatMap { r.load(io.read(it), "certificate") }
                val secretRings = keys.mapNotNull { r.repo.secretRingForDecrypt(it) }
                val compositeRings = keys.mapNotNull { r.repo.compositeDecryptRing(it) }
                val verifyRings = certs.mapNotNull { r.verifyRing(it) }
                var last: Exception? = null
                var needsPassword = false
                for (p in (listOf<String?>(null) + keyPasswords + passwords).distinct()) {
                    val result = try {
                        crypto.decrypt(ciphertext, secretRings, p, verifyRings, compositeRings)
                    } catch (e: PGPCryptoError.PassphraseRequired) {
                        needsPassword = true
                        last = e
                        continue
                    } catch (e: PGPCryptoError.InvalidPassphrase) {
                        needsPassword = true
                        last = e
                        continue
                    } catch (e: Exception) {
                        last = e
                        continue
                    }
                    val lines = if (verOut != null) verifyPackets(r, certs, packetsOf(result), result.data, window) else emptyList()
                    return@runBlocking result.data to lines
                }
                val edits = DesktopKeyEdits(r.repo)
                val anyProtected = keys.any { runCatching { edits.isPassphraseProtected(it.fingerprint) }.getOrDefault(false) }
                when {
                    (needsPassword || anyProtected) && keyPasswords.isEmpty() && passwords.isEmpty() ->
                        throw SopException(SopExit.KEY_IS_PROTECTED, "the key is protected; give its password with --with-key-password")
                    last is PGPCryptoError.ResourceLimitExceeded ->
                        throw SopException(SopExit.BAD_DATA, last.message ?: "message too large")
                    else -> throw SopException(SopExit.CANNOT_DECRYPT, last?.message ?: "cannot decrypt")
                }
            }
        }
        out.write(plaintext)
        verOut?.let { io.write(it, lines.joinToString("") { l -> "$l\n" }.toByteArray(Charsets.UTF_8)) }
        return SopExit.OK
    }
}
