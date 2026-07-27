// Cli.kt
// PGPony Desktop — D10: the `pgpony` command-line face. One binary, two faces (RelayPony
// pattern): a bare launch opens the GUI, a verb runs here. NOT a gpg-compatible shim — its own
// small, documented surface: encrypt · decrypt · sign · verify · import · export · list-keys ·
// gen-key. Shares the SAME keyring + config as the GUI (Config.dbFile / keysDir), so a key
// generated in the app is usable from the shell and vice-versa.
//
// Conventions: input is a file argument or stdin; output is --output/-o or stdout; --armor/-a
// selects ASCII armor for binary-capable verbs. Passphrases come from --passphrase-env,
// --passphrase-fd, or an interactive prompt (never a plain flag — it would leak into `ps` and
// shell history). Exit codes are stable (see ExitCode).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SignedInputType
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path

/** Stable process exit codes — scripts can branch on them. */
object ExitCode {
    const val OK = 0
    const val USAGE = 1
    const val NOT_FOUND = 2       // key or file not found / ambiguous selector
    const val FAILED = 3          // crypto or I/O failure
    const val UNVERIFIED = 4      // `verify` — signature invalid / unsigned / unknown signer
}

object Cli {

    private val crypto get() = PGPCryptoService.shared

    /** Entry point — args[0] is the verb. Returns the process exit code. */
    fun run(args: Array<String>): Int {
        val verb = args.firstOrNull() ?: return usage()
        val rest = args.drop(1)
        // Handled before withRepo on purpose: a diagnostic must not need the keyring, and must
        // still answer while the GUI is running and holding the database.
        if (verb == "card-info") return cardInfo()
        return try {
            withRepo { repo ->
                when (verb) {
                    "encrypt" -> encrypt(repo, rest)
                    "decrypt" -> decrypt(repo, rest)
                    "sign" -> sign(repo, rest)
                    "verify" -> verify(repo, rest)
                    "import" -> importKeys(repo, rest)
                    "export" -> export(repo, rest)
                    "list-keys" -> listKeys(repo, rest)
                    "gen-key" -> genKey(repo, rest)
                    else -> usage()
                }
            }
        } catch (e: CliError) {
            err(e.message ?: "error")
            e.code
        } catch (t: Throwable) {
            err(t.message ?: t::class.simpleName ?: "error")
            ExitCode.FAILED
        }
    }

    // ── Verbs ───────────────────────────────────────────────────────────

    private fun encrypt(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val armor = o.flag("--armor", "-a")
        val symmetric = o.flag("--symmetric", "-c")
        val recipients = o.all("--recipient", "-r")
        val signAs = o.value("--sign-as", "-u")
        val input = o.value("--input", "-i") ?: o.positional()
        val outPath = o.value("--output", "-o")

        if (!symmetric && recipients.isEmpty()) {
            throw CliError(ExitCode.USAGE, "encrypt: at least one --recipient (or --symmetric)")
        }
        val bytes = readAll(input)

        val out = if (symmetric) {
            val pass = requirePassphrase(o, "Passphrase for symmetric encryption: ")
            // Conservative posture (AES-256 CFB + iterated-salted S2K, no AEAD/Argon2) so any
            // reasonably recent gpg can `gpg -d` the result — the D6 backup rationale.
            crypto.encryptSymmetric(bytes, pass, armor = armor, useAead = false, useArgon2 = false)
        } else {
            val rings = recipients.map { sel ->
                val e = resolveOne(repo, sel, requireSecret = false)
                repo.loadPublicKeyRing(e.fingerprint)
                    ?: throw CliError(ExitCode.FAILED, "no public key material for ${e.shortFingerprint}")
            }
            val signerRing = signAs?.let { sel ->
                val e = resolveOne(repo, sel, requireSecret = true)
                repo.loadSecretKeyRing(e.fingerprint)
                    ?: throw CliError(ExitCode.FAILED, "signing key ${e.shortFingerprint} could not be loaded")
            }
            val pass = if (signerRing != null) passphraseOrNull(o) else null
            val bout = java.io.ByteArrayOutputStream()
            crypto.encryptStream(
                input = bytes.inputStream(), output = bout,
                recipientPublicKeys = rings, signingSecretKey = signerRing,
                passphrase = pass, filename = fileName(input), armor = armor
            )
            bout.toByteArray()
        }
        writeAll(outPath, out)
        ExitCode.OK
    }

    private fun decrypt(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val input = o.value("--input", "-i") ?: o.positional()
        val outPath = o.value("--output", "-o")
        val all = repo.allKeys()
        val secretRings = all.filter { it.isKeyPair }.mapNotNull { repo.loadSecretKeyRing(it.fingerprint) }
        val publicRings = all.mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
        val pass = passphraseOrNull(o)

        outStream(outPath).use { output ->
            val result = crypto.decryptStream(readAll(input).inputStream(), output, secretRings, pass, publicRings)
            reportSignature(result.signatureVerified, result.hasSignature, result.signerKeyID, result.signatureKeyIDRaw, all)
        }
        ExitCode.OK
    }

    private fun sign(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val detached = o.flag("--detach-sign", "-b")
        val armor = o.flag("--armor", "-a")
        val signAs = o.value("--sign-as", "-u")
            ?: repo.allKeys().firstOrNull { it.isDefault && it.isKeyPair }?.fingerprint
            ?: throw CliError(ExitCode.USAGE, "sign: --sign-as <key> (no default signing key set)")
        val input = o.value("--input", "-i") ?: o.positional()
        val outPath = o.value("--output", "-o")

        val e = resolveOne(repo, signAs, requireSecret = true)
        val ring = repo.loadSecretKeyRing(e.fingerprint)
            ?: throw CliError(ExitCode.FAILED, "signing key ${e.shortFingerprint} could not be loaded")
        val pass = passphraseOrNull(o)

        val out: ByteArray = if (detached) {
            SigningService.shared.signDetachedStream(readAll(input).inputStream(), ring, pass, armor = armor)
        } else {
            // Clear-sign is text-oriented.
            SigningService.shared.signClear(String(readAll(input), Charsets.UTF_8), ring, pass)
                .toByteArray(Charsets.UTF_8)
        }
        writeAll(outPath, out)
        ExitCode.OK
    }

    private fun verify(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val sigFile = o.value("--signature", "-s")
        val input = o.value("--input", "-i") ?: o.positional()
        val publicRings = repo.allKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }

        val result: VerificationResult = if (sigFile != null) {
            val sigBytes = Files.readAllBytes(Path.of(sigFile))
            readAll(input).inputStream().use { content ->
                VerifyService.shared.verifyDetachedStream(sigBytes, content, publicRings)
            }
        } else {
            val text = String(readAll(input), Charsets.UTF_8)
            when (VerifyService.shared.detectInputType(text)) {
                SignedInputType.CLEAR_SIGNED -> VerifyService.shared.verifyClearSigned(text, publicRings)
                SignedInputType.DETACHED_SIGNATURE ->
                    throw CliError(ExitCode.USAGE, "verify: detached signature — pass the signed file with --signature")
                SignedInputType.ENCRYPTED ->
                    throw CliError(ExitCode.USAGE, "verify: this is an encrypted message — use `pgpony decrypt`")
                SignedInputType.UNKNOWN ->
                    throw CliError(ExitCode.USAGE, "verify: no PGP signature found in the input")
            }
        }
        when (result) {
            is VerificationResult.Verified -> {
                out("Good signature — ${result.signerName ?: ""} <${result.signerEmail ?: "?"}> · ${result.signerKeyID}")
                ExitCode.OK
            }
            is VerificationResult.Invalid -> { err("BAD signature — ${result.reason}"); ExitCode.UNVERIFIED }
            is VerificationResult.UnknownSigner -> {
                err("Signature by an unknown key — ${result.signerKeyID} (import the signer's public key to verify)")
                ExitCode.UNVERIFIED
            }
            is VerificationResult.Unsigned -> { err("No signature found"); ExitCode.UNVERIFIED }
        }
    }

    private fun importKeys(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val input = o.value("--input", "-i") ?: o.positional()
        val report = repo.importBytes(readAll(input))
        out("Import — ${report.summary()}")
        if (report.total == 0 || report.failed == report.total) ExitCode.FAILED else ExitCode.OK
    }

    private fun export(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val secret = o.flag("--secret")
        val selector = o.positional() ?: throw CliError(ExitCode.USAGE, "export: <key selector>")
        val outPath = o.value("--output", "-o")
        val e = resolveOne(repo, selector, requireSecret = secret)
        val armor = if (secret) repo.exportArmoredPrivateKey(e.fingerprint)
        else repo.exportArmoredPublicKeyForSharing(e.fingerprint)
        armor ?: throw CliError(ExitCode.NOT_FOUND, "no ${if (secret) "secret" else "public"} material for ${e.shortFingerprint}")
        writeAll(outPath, armor.toByteArray(Charsets.UTF_8))
        ExitCode.OK
    }

    private fun listKeys(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val secretOnly = o.flag("--secret")
        val keys = repo.allKeys().filter { !secretOnly || it.isKeyPair }
        if (keys.isEmpty()) { out("(no keys)"); return@runBlocking ExitCode.OK }
        keys.forEach { k ->
            val flags = buildList {
                if (k.isKeyPair) add("sec") else add("pub")
                if (k.isCardBacked) add("card")
                if (k.isDefault) add("default")
                if (k.isRevoked) add("revoked")
                if (k.isExpired) add("expired")
            }.joinToString(",")
            out("${k.fingerprint.uppercase()}  ${k.algorithm.displayName.padEnd(20)}  [$flags]  ${k.userID}")
        }
        ExitCode.OK
    }

    private fun genKey(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val name = o.value("--name") ?: throw CliError(ExitCode.USAGE, "gen-key: --name <name>")
        val email = o.value("--email") ?: throw CliError(ExitCode.USAGE, "gen-key: --email <email>")
        val algo = parseAlgorithm(o.value("--algo") ?: "ed25519")
        val expiresDays = o.value("--expires")?.toLongOrNull()
        val expirationSeconds = expiresDays?.let { it * 24 * 60 * 60 }
        val pass = requirePassphrase(o, "Passphrase for the new key (empty for none): ", allowEmpty = true)
            .ifEmpty { null }
        val entity = repo.generateKey(name, email, algo, pass, expirationSeconds)
        out("Generated ${entity.userID}")
        out(entity.fingerprint.uppercase())
        ExitCode.OK
    }

    // ── Key resolution ──────────────────────────────────────────────────

    /** Resolve a selector (fingerprint / key id / email / name substring) to exactly one key. */
    private suspend fun resolveOne(
        repo: DesktopKeyRepository,
        selector: String,
        requireSecret: Boolean
    ): PGPKeyEntity {
        val matches = matchKeys(repo.allKeys(), selector).let {
            if (requireSecret) it.filter { k -> k.isKeyPair } else it
        }
        return when {
            matches.isEmpty() -> throw CliError(ExitCode.NOT_FOUND, "no ${if (requireSecret) "secret " else ""}key matches \"$selector\"")
            matches.size > 1 -> throw CliError(
                ExitCode.NOT_FOUND,
                "\"$selector\" is ambiguous — matches ${matches.size} keys; use a fingerprint. " +
                    matches.joinToString(", ") { it.shortFingerprint }
            )
            else -> matches.first()
        }
    }

    internal fun matchKeys(keys: List<PGPKeyEntity>, selector: String): List<PGPKeyEntity> {
        val s = selector.trim()
        val hex = s.replace(" ", "")
        val looksHex = hex.length >= 8 && hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
        if (looksHex) {
            val u = hex.uppercase()
            val byFp = keys.filter { it.fingerprint.uppercase().endsWith(u) || it.fingerprint.uppercase().startsWith(u) }
            if (byFp.isNotEmpty()) return byFp
            val byId = keys.filter { it.longKeyId.equals(u, ignoreCase = true) }
            if (byId.isNotEmpty()) return byId
        }
        val byEmail = keys.filter { it.userEmail.equals(s, ignoreCase = true) }
        if (byEmail.isNotEmpty()) return byEmail
        return keys.filter { it.userID.contains(s, ignoreCase = true) || it.userEmail.contains(s, ignoreCase = true) }
    }

    internal fun parseAlgorithm(name: String): KeyAlgorithm = when (name.lowercase().replace("_", "-")) {
        "ed25519", "ed25519-cv25519", "default" -> KeyAlgorithm.ED25519_CV25519
        "rsa2048", "rsa-2048" -> KeyAlgorithm.RSA_2048
        "rsa4096", "rsa-4096", "rsa" -> KeyAlgorithm.RSA_4096
        "v6-ed25519", "ed25519-v6" -> KeyAlgorithm.V6_ED25519
        "v6-x25519", "x25519-v6" -> KeyAlgorithm.V6_X25519
        "v6-ed448" -> KeyAlgorithm.V6_ED448
        "v6-x448" -> KeyAlgorithm.V6_X448
        "mlkem", "mlkem-v6", "pqc" -> KeyAlgorithm.MLKEM768_X25519_V6
        "mlkem-librepgp", "mlkem-v5" -> KeyAlgorithm.MLKEM768_X25519_LIBREPGP
        else -> throw CliError(
            ExitCode.USAGE,
            "gen-key: unknown --algo \"$name\" (ed25519, rsa2048, rsa4096, v6-ed25519, v6-x25519, " +
                "v6-ed448, v6-x448, mlkem-v6, mlkem-librepgp)"
        )
    }

    // ── Signature reporting (decrypt) ───────────────────────────────────

    private fun reportSignature(
        verified: Boolean, has: Boolean, signerKeyID: String?, raw: Long?, keys: List<PGPKeyEntity>
    ) {
        when {
            verified -> {
                val who = keys.firstOrNull { it.longKeyId.equals(signerKeyID, ignoreCase = true) }?.userID
                err("Good signature" + (who?.let { " — $it" } ?: (signerKeyID?.let { " — $it" } ?: "")))
            }
            has -> err("Signed by an unheld key" + (raw?.let { " (${String.format("%016X", it)})" } ?: "") + " — not verified")
            else -> err("No signature")
        }
    }

    // ── I/O ─────────────────────────────────────────────────────────────

    private fun readAll(input: String?): ByteArray =
        if (input == null || input == "-") System.`in`.readBytes()
        else Files.readAllBytes(Path.of(input).also {
            if (!Files.exists(it)) throw CliError(ExitCode.NOT_FOUND, "input file not found: $input")
        })

    private fun outStream(outPath: String?): OutputStream =
        if (outPath == null || outPath == "-") UncloseableStream(System.out)
        else Files.newOutputStream(Path.of(outPath))

    private fun writeAll(outPath: String?, bytes: ByteArray) {
        if (outPath == null || outPath == "-") { System.out.write(bytes); System.out.flush() }
        else Files.write(Path.of(outPath), bytes)
    }

    private fun fileName(input: String?): String? =
        input?.takeIf { it != "-" }?.let { Path.of(it).fileName?.toString() }

    /** Keep System.out open when a stream consumer calls close(). */
    private class UncloseableStream(private val delegate: OutputStream) : OutputStream() {
        override fun write(b: Int) = delegate.write(b)
        override fun write(b: ByteArray, off: Int, len: Int) = delegate.write(b, off, len)
        override fun flush() = delegate.flush()
        override fun close() { delegate.flush() } // do NOT close stdout
    }

    // ── Passphrase ──────────────────────────────────────────────────────

    /** Passphrase from --passphrase-env / --passphrase-fd, or null (no interactive prompt). */
    private fun passphraseOrNull(o: Options): String? {
        o.value("--passphrase-env")?.let { return System.getenv(it) }
        o.value("--passphrase-fd")?.let { fd ->
            return runCatching { File("/dev/fd/$fd").readText().trimEnd('\n', '\r') }.getOrNull()
        }
        // Interactive only if a console is attached (not piped).
        val console = System.console() ?: return null
        val chars = console.readPassword("Passphrase (empty if none): ")
        return chars?.concatToString()?.ifEmpty { null }
    }

    private fun requirePassphrase(o: Options, prompt: String, allowEmpty: Boolean = false): String {
        o.value("--passphrase-env")?.let { return System.getenv(it) ?: "" }
        o.value("--passphrase-fd")?.let { fd ->
            return runCatching { File("/dev/fd/$fd").readText().trimEnd('\n', '\r') }.getOrElse { "" }
        }
        val console = System.console()
            ?: throw CliError(ExitCode.USAGE, "no terminal for a passphrase prompt — use --passphrase-env or --passphrase-fd")
        val first = console.readPassword(prompt).concatToString()
        if (!allowEmpty && first.isEmpty()) throw CliError(ExitCode.USAGE, "passphrase required")
        if (allowEmpty && first.isEmpty()) return ""
        // Confirm on a fresh secret (gen-key / symmetric encrypt).
        val second = console.readPassword("Confirm passphrase: ").concatToString()
        if (first != second) throw CliError(ExitCode.USAGE, "passphrases did not match")
        return first
    }

    // ── Repository lifecycle ────────────────────────────────────────────

    private fun withRepo(block: (DesktopKeyRepository) -> Int): Int {
        val db = Db.open(Config.dbFile)
        return try {
            val repo = DesktopKeyRepository(db, KeyMaterialStore(Config.keysDir))
            runBlocking { repo.migrateLegacyJson(Config.legacyKeyringFile) }
            block(repo)
        } finally {
            db.close()
        }
    }

    // ── Output helpers ──────────────────────────────────────────────────

    /**
     * `pgpony card-info` — what the PC/SC layer can see, and why it cannot see anything.
     *
     * Exists because a Windows "no reader detected" report was undiagnosable without walking the
     * user through PowerShell. Deliberately English and unlocalized like the rest of the CLI, so
     * a pasted diagnostic reads the same in every bug report.
     */
    private fun cardInfo(): Int {
        val readers = DesktopCardReader.listReaders()
        val failure = DesktopCardReader.lastListError
        out("os        ${System.getProperty("os.name")} ${System.getProperty("os.version")} (${System.getProperty("os.arch")})")
        out("java       ${System.getProperty("java.version")} (${System.getProperty("java.vendor")})")
        // If java.smartcardio is missing from a packaged runtime, listReaders() fails here rather
        // than at startup — so report whether the module resolved at all, which is otherwise only
        // discoverable by grepping the jlink image's release file.
        val moduleOk = runCatching { Class.forName("javax.smartcardio.TerminalFactory") }.isSuccess
        out("smartcardio ${if (moduleOk) "present" else "MISSING from this runtime"}")
        if (failure != null) {
            err("PC/SC unavailable: $failure")
            return ExitCode.FAILED
        }
        // A recovered transient is the evidence that matters for the intermittent Windows PC/SC
        // fault: the app carried on, so nothing else records that anything went wrong.
        DesktopCardReader.lastRecovery?.let { out("pcsc       $it") }
        if (readers.isEmpty()) {
            out("readers    none attached")
            return ExitCode.OK
        }
        out("readers    ${readers.size}")
        readers.forEach { r ->
            out("  ${r.name}  [${if (r.cardPresent) "card present" else "empty"}]")
        }
        return ExitCode.OK
    }

    private fun out(msg: String) = println(msg)
    private fun err(msg: String) = System.err.println("pgpony: $msg")

    private fun usage(): Int {
        err(
            """
            pgpony — OpenPGP on the command line (shares the app's keyring)

            Usage: pgpony <verb> [options] [file]

            Verbs:
              encrypt   -r <key> [-r …] [-u <key>] [-c] [-a] [-o out] [file|-]
              decrypt   [-o out] [file|-]
              sign      [-u <key>] [-b] [-a] [-o out] [file|-]
              verify    [-s <sigfile>] [file|-]
              import    [file|-]
              export    [--secret] [-a] [-o out] <key>
              list-keys [--secret]
              gen-key   --name <n> --email <e> [--algo ed25519] [--expires <days>]
              card-info                        report the PC/SC readers this build can see

            Common options:
              -a, --armor            ASCII-armored output
              -o, --output <file>    write to file (default: stdout)
              -r, --recipient <key>  recipient (fingerprint, key id, or email)
              -u, --sign-as <key>    signing key
              --passphrase-env VAR   read passphrase from an environment variable
              --passphrase-fd N      read passphrase from a file descriptor

            A key selector is a fingerprint, long key id, email, or a unique name substring.
            Exit codes: 0 ok · 1 usage · 2 not-found · 3 failed · 4 unverified.
            """.trimIndent()
        )
        return ExitCode.USAGE
    }
}

/** A CLI failure carrying its exit code. */
private class CliError(val code: Int, message: String) : Exception(message)

/**
 * A minimal option parser: --long / -short flags and values, plus one positional (the input
 * file). Values may be `--opt value` or `--opt=value`. Repeatable options via [all].
 */
internal class Options(args: List<String>) {
    private val flags = mutableSetOf<String>()

    // D10 (Fix1) — an ORDERED list of (name, value), not a map keyed by name. A map grouped the
    // values by option name, so `all("--recipient", "-r")` returned every long-form value before
    // every short-form one: `-r alice -r/--recipient bob` came back as [bob, alice]. Recipient
    // order (and any other repeatable option) must follow the COMMAND LINE, whichever alias
    // spelling the user reached for at each occurrence.
    private val values = mutableListOf<Pair<String, String>>()
    private val positionals = mutableListOf<String>()

    // Options that take a value (everything else is a boolean flag).
    private val valued = setOf(
        "--output", "-o", "--input", "-i", "--recipient", "-r", "--sign-as", "-u",
        "--signature", "-s", "--passphrase-env", "--passphrase-fd", "--name", "--email",
        "--algo", "--expires"
    )

    init {
        var i = 0
        while (i < args.size) {
            val a = args[i]
            when {
                a == "--" -> { positionals.addAll(args.drop(i + 1)); break }
                a.startsWith("--") && a.contains('=') -> {
                    val (k, v) = a.split('=', limit = 2)
                    values.add(k to v)
                }
                a in valued -> {
                    val v = args.getOrNull(i + 1)
                        ?: throw IllegalArgumentException("option $a needs a value")
                    values.add(a to v); i++
                }
                a.startsWith("-") && a != "-" -> flags.add(a)
                else -> positionals.add(a)
            }
            i++
        }
    }

    fun flag(vararg names: String): Boolean = names.any { it in flags }

    /** The FIRST occurrence on the command line among any of the alias spellings. */
    fun value(vararg names: String): String? = all(*names).firstOrNull()

    /** Every occurrence among the alias spellings, in command-line order. */
    fun all(vararg names: String): List<String> =
        values.filter { it.first in names }.map { it.second }

    fun positional(): String? = positionals.firstOrNull()
}
