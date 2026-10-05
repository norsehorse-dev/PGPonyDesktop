// SopCrypto.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5a: the SOP subcommands that touch keys, on the
// engine the app uses. See Sop.kt for the shape and SopKeyring below for the scratch keyring.
//
// Verification lines (VERIFICATIONS): each signature packet is checked on its own through the
// engine (VerifyService for classical signatures, CompositeSignerGate for ML-DSA), and a good
// one is reported as "<creation time> <signing key fp> <primary key fp> mode:<binary|text>".
// Both grade the signer (revoked, expired, not a signing key, unbound, older than the key) and
// the signature's own policy, so only a signature the app would show as verified gets a line.
// The creation time comes from the hashed area only, the part the signature covers.

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
import com.pgpony.android.crypto.pqc.CompositeSignerGate
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import org.bouncycastle.openpgp.PGPPublicKeyRing
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
 * owner-only temporary folder, deleted on close. A shutdown hook deletes it too when the process
 * is stopped (SIGTERM, SIGINT, Ctrl+C), and the next invocation sweeps folders that a killed or
 * crashed process left behind (it holds a lock on .lock while alive, so a running one is spared).
 */
internal class SopKeyring private constructor(
    internal val dir: Path,
    private val db: PGPDatabase,
    private val liveLock: java.nio.channels.FileChannel?
) : AutoCloseable {

    val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    private val crypto = PGPCryptoService.shared

    private val hook = Thread({ release() }, "pgpony-sop-cleanup")
    @Volatile private var released = false

    companion object {
        internal const val PREFIX = "pgpony-sop"
        private const val LOCK_NAME = ".lock"

        // A folder from a version without the lock file is swept only once it is this old.
        private const val UNLOCKED_STALE_MS = 60L * 60 * 1000

        // A folder this new is never swept: its invocation may not have taken its lock yet.
        private const val FRESH_MS = 60L * 1000

        @Volatile private var swept = false

        fun open(): SopKeyring {
            val dir = createPrivateDir()
            val lock = runCatching {
                val ch = java.nio.channels.FileChannel.open(
                    dir.resolve(LOCK_NAME),
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE
                )
                if (ch.tryLock() == null) { ch.close(); null } else ch
            }.getOrNull()
            if (!swept) {
                swept = true
                runCatching { sweepStale(dir.parent, dir) }
            }
            val keyring = try {
                SopKeyring(dir, Db.open(dir.resolve("sop.db")), lock)
            } catch (t: Throwable) {
                runCatching { lock?.close() }
                wipe(dir)
                throw t
            }
            runCatching { Runtime.getRuntime().addShutdownHook(keyring.hook) }
            return keyring
        }

        /** A new temporary folder only this account can open. */
        private fun createPrivateDir(): Path {
            if ("posix" in FileSystems.getDefault().supportedFileAttributeViews()) {
                return Files.createTempDirectory(PREFIX, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            }
            val dir = Files.createTempDirectory(PREFIX)
            // Windows: %TEMP% is per user already; also give the folder an ACL naming only its
            // owner, inherited by everything created inside it.
            runCatching {
                val view = Files.getFileAttributeView(dir, java.nio.file.attribute.AclFileAttributeView::class.java)
                if (view != null) {
                    val entry = java.nio.file.attribute.AclEntry.newBuilder()
                        .setType(java.nio.file.attribute.AclEntryType.ALLOW)
                        .setPrincipal(view.owner)
                        .setPermissions(java.nio.file.attribute.AclEntryPermission.values().toSet())
                        .setFlags(
                            java.nio.file.attribute.AclEntryFlag.FILE_INHERIT,
                            java.nio.file.attribute.AclEntryFlag.DIRECTORY_INHERIT
                        )
                        .build()
                    view.acl = listOf(entry)
                }
            }
            return dir
        }

        /**
         * Delete [dir]: the secret key files first (overwritten, then deleted), then everything
         * else, each file on its own so one that cannot be deleted never leaves the rest behind.
         * Symbolic links are deleted, never followed.
         */
        internal fun wipe(dir: Path) {
            val keys = dir.resolve("keys")
            runCatching {
                Files.newDirectoryStream(keys).use { stream ->
                    for (f in stream) {
                        if (f.fileName.toString().endsWith(".sec.asc") &&
                            Files.isRegularFile(f, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                        ) {
                            runCatching {
                                val size = Files.size(f).toInt().coerceIn(0, 16 * 1024 * 1024)
                                Files.write(f, ByteArray(size), java.nio.file.StandardOpenOption.WRITE)
                            }
                        }
                        runCatching { Files.deleteIfExists(f) }
                    }
                }
            }
            val rest = runCatching {
                Files.walk(dir).use { walk -> walk.sorted(Comparator.reverseOrder()).toList() }
            }.getOrDefault(listOf(dir))
            for (p in rest) runCatching { Files.deleteIfExists(p) }
        }

        /** [sweepStale] over the temporary directory, for a caller with no scratch folder (app start). */
        fun sweepStaleNow() {
            val probe = Files.createTempFile("pgpony-owner", ".tmp")
            try {
                sweepStale(probe.parent, probe)
            } finally {
                runCatching { Files.deleteIfExists(probe) }
            }
        }

        /**
         * Delete scratch folders in [tmp] that an earlier invocation left behind: folders named
         * [PREFIX]*, owned by this account (the owner of [own], the folder just created), real
         * directories (not links), and not held by a running process.
         */
        internal fun sweepStale(tmp: Path, own: Path, nowMs: Long = System.currentTimeMillis()) {
            val nofollow = java.nio.file.LinkOption.NOFOLLOW_LINKS
            val me = Files.getOwner(own, nofollow)
            Files.newDirectoryStream(tmp, "$PREFIX*").use { stream ->
                for (d in stream) {
                    if (d == own) continue
                    runCatching {
                        if (!Files.isDirectory(d, nofollow) || Files.isSymbolicLink(d)) return@runCatching
                        if (Files.getOwner(d, nofollow) != me) return@runCatching
                        val age = nowMs - Files.getLastModifiedTime(d, nofollow).toMillis()
                        if (age < FRESH_MS) return@runCatching
                        val lockFile = d.resolve(LOCK_NAME)
                        if (Files.exists(lockFile, nofollow)) {
                            if (!Files.isRegularFile(lockFile, nofollow)) return@runCatching
                            val ch = java.nio.channels.FileChannel.open(lockFile, java.nio.file.StandardOpenOption.WRITE)
                            val held = try {
                                ch.tryLock()
                            } catch (_: java.nio.channels.OverlappingFileLockException) {
                                null
                            } catch (_: java.io.IOException) {
                                null
                            }
                            if (held == null) {
                                ch.close()
                                return@runCatching
                            }
                            // Nobody holds it: the process that made it is gone. Let go of the
                            // lock first (Windows cannot delete a locked file), then delete.
                            runCatching { held.release() }
                            ch.close()
                            wipe(d)
                        } else if (age >= UNLOCKED_STALE_MS) {
                            wipe(d)
                        }
                    }
                }
            }
        }

    }

    /** Close the database and delete the folder; safe to call more than once. */
    private fun release() {
        synchronized(this) {
            if (released) return
            released = true
        }
        runCatching { db.close() }
        runCatching { liveLock?.close() }
        wipe(dir)
    }

    override fun close() {
        release()
        runCatching { Runtime.getRuntime().removeShutdownHook(hook) }
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
        val anyComposite = packets.any { p -> SopSigInfo.parse(p)?.let { CompositeSignSuite.forAlgId(it.pkAlgo) != null } == true }
        val rawCerts = if (anyComposite) certs.mapNotNull { r.repo.rawPublicBytes(it.fingerprint) } else emptyList()
        val out = LinkedHashSet<String>()
        for (packet in packets) {
            val info = SopSigInfo.parse(packet) ?: continue
            if (info.type != 0x00 && info.type != 0x01) continue
            // Hashed creation time only (SopSigInfo): a signature without one is not reported.
            val created = info.created ?: continue
            if (!window.contains(created)) continue
            val hit = if (CompositeSignSuite.forAlgId(info.pkAlgo) != null) {
                verifyComposite(rawCerts, packet, data, created)
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

    /**
     * A classical signature through VerifyService, which grades the signer by the exact key that
     * verified. The line pairs that key with its own certificate's primary: when the engine's
     * answer does not name a certificate among [rings] that holds the signing key, no line.
     */
    internal fun verifyClassical(rings: List<PGPPublicKeyRing>, packet: ByteArray, data: ByteArray): Pair<String, String>? {
        val verdict = runCatching { VerifyService.shared.verifyDetached(packet, data, rings) }.getOrNull()
        val good = verdict as? VerificationResult.Verified ?: return null
        val signing = good.signingKeyFingerprint?.uppercase() ?: return null
        val primary = good.signerFingerprint.uppercase()
        val owner = rings.firstOrNull { hex(it.publicKey.fingerprint).equals(primary, ignoreCase = true) } ?: return null
        val holds = owner.publicKeys.asSequence().any { hex(it.fingerprint).equals(signing, ignoreCase = true) }
        return if (holds) signing to primary else null
    }

    /**
     * A composite (ML-DSA) signature through the engine's CompositeSignerGate: the math against
     * the supplied certificates, the signature's own policy, and the signer at [created]. Only a
     * VERIFIED grade gives a line, and only when the gate read the same creation time.
     */
    internal fun verifyComposite(
        rawCerts: List<ByteArray>,
        packet: ByteArray,
        data: ByteArray,
        created: Date
    ): Pair<String, String>? {
        val g = runCatching { CompositeSignerGate.verifyDetached(rawCerts, packet, data) }.getOrNull() ?: return null
        if (!g.verified) return null
        if (g.createdMs == null || g.createdMs / 1000 != created.time / 1000) return null
        val signing = g.signingKeyFingerprint ?: return null
        val primary = g.signerPrimaryFingerprint ?: return null
        return signing.uppercase() to primary.uppercase()
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
                keys.forEach { requireSigner(it) }
                // 3.0.0 (5d-4): several keys, a cleartext signature from a classical key and a text
                // signature from an ML-DSA key are built here from detached signatures (SopInline,
                // SopCleartext); one classical or ML-DSA key otherwise keeps the engine's own path.
                val single = keys.singleOrNull()
                val enginePath = single != null &&
                    if (single.algorithm.isCompositeSign) mode != "text" else mode != "clearsigned"
                if (!enginePath) {
                    return@runBlocking if (mode == "clearsigned") {
                        val signed = SopCleartext.signedOctetsOf(data)
                        SopCleartext.write(data, keys.map { signOne(r, it, signed, true, passwords) })
                    } else {
                        val text = mode == "text"
                        SopArmor.output(
                            SopInline.build(keys.map { signOne(r, it, data, text, passwords) }, data, text),
                            SopArmor.MESSAGE, noArmor
                        )
                    }
                }
                val k = single!!
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
        // Clear-signed only when the first non-blank line is the framing line, as the engine
        // decides it; the same text inside an armor header does not count.
        val clearSigned = head.lineSequence().firstOrNull { it.isNotBlank() }?.trim() == "-----BEGIN PGP SIGNED MESSAGE-----"
        val (content, lines) = SopKeyring.open().use { r ->
            runBlocking {
                val certs = a.positionals.flatMap { r.load(io.read(it), "certificate") }
                if (clearSigned) {
                    // 3.0.0 (5d-4): SopCleartext keeps the text as signed, final line ending included.
                    val parsed = SopCleartext.parse(input)
                    val packets = SopPackets.signatures(SopArmor.binary(parsed.signatureBlock))
                    parsed.text to verifyPackets(r, certs, packets, parsed.signed, window)
                } else if (isCompositeInline(input)) {
                    // An ML-DSA signed message: BouncyCastle cannot parse its one-pass packet.
                    val raw = SopArmor.binary(input)
                    val inner = runCatching { CompositeDocumentVerifier.decompress(raw) }.getOrNull()
                        ?: throw SopException(SopExit.BAD_DATA, "a malformed signed message")
                    // Exactly one literal: the content written out is the content verified.
                    val literals = runCatching { CompositeDocumentVerifier.packetsOf(inner).count { it.first == 11 } }.getOrDefault(0)
                    if (literals != 1) throw SopException(SopExit.BAD_DATA, "a malformed signed message")
                    val content = CompositeDocumentVerifier.inlineContent(raw)
                        ?: throw SopException(SopExit.BAD_DATA, "a malformed signed message")
                    val packets = SopPackets.signatures(inner)
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
        val data = stdin.readBytes()
        if (text) requireText(data)

        if (passwords.isNotEmpty()) {
            // 3.0.0 (5d-4): the rfc9580 profile gives a password its RFC 9580 form (SKESKv6,
            // SEIPDv2 with Argon2); the default stays SKESKv4 and SEIPDv1 for older readers.
            val rfc9580 = a.value("--profile") == "rfc9580"
            out.write(crypto.encryptSymmetric(data, passwords.single(), armor = !noArmor, useAead = rfc9580, useArgon2 = rfc9580))
            return SopExit.OK
        }
        val keyPasswords = keyPasswords(a, io)
        val ciphertext = SopKeyring.open().use { r ->
            runBlocking {
                val recipients = certArgs.flatMap { r.load(io.read(it), "certificate") }
                val signers = signerArgs.flatMap { r.load(io.read(it), "key") }
                signers.forEach { requireSigner(it) }
                // 3.0.0 (5d-4): several signing keys, or a text signature, are signed here and the
                // finished signed message is encrypted as it stands.
                if (signers.size > 1 || (text && signers.isNotEmpty())) {
                    val packets = signers.map { signOne(r, it, data, text, keyPasswords) }
                    val plan = try {
                        EncryptOps(r.repo).plan(recipients.map { it.fingerprint }, null, null, compositeInV1Decision = true)
                    } catch (e: RecipientLoadException) {
                        throw SopException(SopExit.CERT_CANNOT_ENCRYPT, "no usable encryption key: ${e.message}")
                    } catch (e: ExpiredKeyException) {
                        throw SopException(SopExit.CERT_CANNOT_ENCRYPT, e.message ?: "expired certificate")
                    }
                    return@runBlocking EncryptOps(r.repo).encryptBytes(
                        plan, data, null, armor = !noArmor, presignedInline = SopInline.build(packets, data, text)
                    )
                }
                val signer = signers.singleOrNull()
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
        // 3.0.2 (#10): the two only make sense together. Either one alone fails with
        // INCOMPLETE_VERIFICATION, as the SOP decrypt section requires; before, --verify-with
        // alone decrypted an unsigned message and exited 0, and --verifications-out alone gave 83.
        if ((verOut == null) != verifyWith.isEmpty()) {
            throw SopException(
                SopExit.INCOMPLETE_VERIFICATION,
                if (verOut == null) "--verify-with needs --verifications-out" else "--verifications-out needs --verify-with"
            )
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
