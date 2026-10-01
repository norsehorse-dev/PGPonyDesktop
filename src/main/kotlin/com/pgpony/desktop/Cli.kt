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
//
// 3.0.0: decrypt holds its output until the message has passed every check. The plaintext goes
// to an owner-only temp file (in the --output folder, or a private temp folder for stdout) and
// is moved into place, or copied to stdout, only after the engine returned; a failed integrity
// or structure check leaves nothing behind and exits 3. A signature that is present but bad
// exits 4, as gpg exits non-zero for a bad signature. Outputs never write through a link at the
// destination. Text that comes from keys or messages (User IDs, file names, error details) is
// printed with control characters escaped, so it cannot drive the terminal.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SignedInputType
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import com.pgpony.android.crypto.pqc.CompositeDocumentSigner
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import java.io.File
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/** Stable process exit codes — scripts can branch on them. */
object ExitCode {
    const val OK = 0
    const val USAGE = 1
    const val NOT_FOUND = 2       // key or file not found / ambiguous selector
    const val FAILED = 3          // crypto or I/O failure
    const val UNVERIFIED = 4      // verify: signature bad, unknown or missing; decrypt: a bad signature, or a --require-* flag not met
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
                    "import-gnupg" -> importGnupg(repo, rest)
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
            // 3.0.0: EncryptOps settles recipients (every selected key must be usable, v4 algo-35
            // keys on their own channel), the expired-key rule and the signer, composite ML-DSA
            // included. The CLI cannot prompt, so a composite signature to a v4-only recipient is
            // kept and a warning goes to stderr (the "sign and warn" decision).
            val fps = recipients.map { sel -> resolveOne(repo, sel, requireSecret = false).fingerprint }
            val picked = signAs?.let { sel -> resolveOne(repo, sel, requireSecret = true) }
            // 3.0.0 (plan 3.8): the picked key's signing defaults, unless --no-signing-defaults.
            val signer = picked?.let { base ->
                if (o.flag("--no-signing-defaults")) base
                else repo.signerAfterDefaults(base, fps.mapNotNull { fp -> repo.byFingerprint(fp) }, signOnly = false)
                    .also { if (it.fingerprint != base.fingerprint) err("note: signing as ${it.shortFingerprint} (signing default of ${base.shortFingerprint})") }
            }
            val pass = if (signer != null) passphraseOrNull(o) else null
            val ops = EncryptOps(repo)
            val plan = try {
                ops.plan(fps, signer, pass, compositeInV1Decision = true)
            } catch (e: RecipientLoadException) {
                throw CliError(ExitCode.FAILED, e.message ?: "a recipient could not be loaded")
            } catch (e: ExpiredKeyException) {
                throw CliError(ExitCode.FAILED, e.message ?: "an expired key was selected")
            } catch (e: IllegalStateException) {
                throw CliError(ExitCode.FAILED, e.message ?: "the signing key could not be loaded")
            }
            if (plan.compositeInSeipdV1) {
                err("warning: the ML-DSA signature goes to a v4 recipient; PGPony reads it, GnuPG reports an error and Thunderbird cannot open the message")
            }
            if (plan.needsBuffering) {
                ops.encryptBytes(plan, bytes, pass, armor, fileName(input))
            } else {
                val bout = java.io.ByteArrayOutputStream()
                ops.encryptStream(plan, bytes.inputStream(), bout, pass, armor, fileName(input))
                bout.toByteArray()
            }
        }
        writeAll(outPath, out)
        ExitCode.OK
    }

    private fun decrypt(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val input = o.value("--input", "-i") ?: o.positional()
        val outPath = o.value("--output", "-o")
        val requireSignature = o.flag("--require-signature")
        val requireVerified = o.flag("--require-verified")
        // 3.0.0 (plan 3.7): --decrypt-with tries that key first, then its fallbacks, then the
        // rest unless the key is in strict mode (set in the app's Key Detail).
        val selected = o.value("--decrypt-with")?.let { sel -> resolveOne(repo, sel, requireSecret = true).fingerprint }
        val keys = repo.decryptKeys(selected)
        val pass = passphraseOrNull(o)

        withScratch { scratch ->
            val source = cipherSource(input, scratch)
            val target = DecryptTarget.open(outPath, scratch)
            try {
                val result = try {
                    Files.newInputStream(source).use { ins ->
                        target.stream().use { output ->
                            crypto.decryptStream(
                                ins, output, keys.secretRings, pass, keys.verificationRings, keys.compositeRings
                            )
                        }
                    }
                } catch (t: Throwable) {
                    // Same exit path as before (message to stderr, exit 3); only the text is sharper
                    // when a --decrypt-with key is not a recipient or its passphrase was wrong.
                    throw repo.explainDecryptFailure(
                        { Files.newInputStream(source).use { crypto.inspectEncryptedMessage(it).publicKeyIDs } },
                        selected, t
                    )
                }
                val summary = DecryptSignature.of(repo, result)
                reportSignature(summary, result.signerStatus)
                val unmet = when {
                    requireVerified && summary.state != SignatureSummary.State.VERIFIED ->
                        "--require-verified: no good signature from a verified key"
                    requireSignature && summary.state != SignatureSummary.State.VERIFIED &&
                        summary.state != SignatureSummary.State.UNCONFIRMED ->
                        "--require-signature: no good signature from a key in the keyring"
                    else -> null
                }
                if (unmet != null) {
                    err("$unmet; nothing was written")
                    return@withScratch ExitCode.UNVERIFIED
                }
                target.publish()
                if (summary.state == SignatureSummary.State.INVALID) ExitCode.UNVERIFIED else ExitCode.OK
            } finally {
                target.discard()
            }
        }
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

        val picked = resolveOne(repo, signAs, requireSecret = true)
        // 3.0.0 (plan 3.8): the sign-only signing default, unless --no-signing-defaults.
        val e = if (o.flag("--no-signing-defaults")) picked
        else repo.signerAfterDefaults(picked, emptyList(), signOnly = true)
            .also { if (it.fingerprint != picked.fingerprint) err("note: signing as ${it.shortFingerprint} (signing default of ${picked.shortFingerprint})") }
        if (!KeyUsePolicy.allowExpiredKeys() && KeyUsePolicy.isExpired(e)) {
            throw CliError(ExitCode.FAILED, "signing key ${e.shortFingerprint} has expired (turn on Allow expired keys in Settings to sign with it)")
        }
        if (e.algorithm.isCompositeSign) {
            val info = repo.loadCompositeKeyInfo(e.fingerprint, passphraseOrNull(o)?.toCharArray())
                ?: throw CliError(ExitCode.FAILED, "signing key ${e.shortFingerprint} could not be loaded")
            val secret = info.compositeSecret
                ?: throw CliError(ExitCode.FAILED, "signing key ${e.shortFingerprint} is passphrase-protected; give it with --passphrase-env or --passphrase-fd")
            val data = readAll(input)
            val out = if (detached)
                CompositeDocumentSigner.signDetachedArmored(info.suite, secret, info.fingerprint, data)
                    .toByteArray(Charsets.UTF_8)
            else
                CompositeDocumentSigner.signCleartext(info.suite, secret, info.fingerprint, String(data, Charsets.UTF_8))
                    .toByteArray(Charsets.UTF_8)
            writeAll(outPath, out)
            return@runBlocking ExitCode.OK
        }
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
            val data = readAll(input)
            DesktopCompositeVerify.verifyDetached(repo, String(sigBytes, Charsets.UTF_8), data)
                ?: data.inputStream().use { content ->
                    VerifyService.shared.verifyDetachedStream(sigBytes, content, publicRings)
                }
        } else {
            val text = String(readAll(input), Charsets.UTF_8)
            when (VerifyService.shared.detectInputType(text)) {
                SignedInputType.CLEAR_SIGNED ->
                    DesktopCompositeVerify.verifyText(repo, text)
                        ?: VerifyService.shared.verifyClearSigned(text, publicRings)
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
                val confirmed = SignatureSummary.fromVerification(repo, result).state == SignatureSummary.State.VERIFIED
                // The key ID and fingerprints are those of the key the signature verified under.
                out(
                    "Good signature: ${safe(result.signerName ?: "")} <${safe(result.signerEmail ?: "?")}> · ${safe(result.signerKeyID)}" +
                        (if (confirmed) "" else " (signer key not verified)") +
                        (result.signerWeakKey?.let { " (weak signing key: ${safe(it)})" } ?: "")
                )
                out("Signer fingerprint: ${safe(result.signerFingerprint.uppercase())}")
                result.signingKeyFingerprint?.takeIf { !it.equals(result.signerFingerprint, ignoreCase = true) }?.let {
                    out("Signing subkey: ${safe(it.uppercase())}")
                }
                if (!confirmed && o.flag("--require-verified")) {
                    err("--require-verified: the signer key is not verified")
                    ExitCode.UNVERIFIED
                } else ExitCode.OK
            }
            is VerificationResult.Invalid -> { err("BAD signature: ${safe(result.reason)}"); ExitCode.UNVERIFIED }
            is VerificationResult.UnknownSigner -> {
                err("Signature by an unknown key: ${safe(result.signerKeyID)} (import the signer's public key to verify)")
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

    // 3.0.0 (5b): the keys in a GnuPG home. Public keys always; trust unless --no-trust; secret
    // keys with --secret, through gpg, which asks for each passphrase with its own pinentry.
    // A folder that is not the user's own GnuPG home is only read, never handed to gpg: public
    // keys, plus trust only when asked for with --trust (the app's dialog leaves it unticked).
    private fun importGnupg(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val home = o.value("--homedir")?.let { Path.of(it) } ?: GnupgImport.defaultHome()
        if (!GnupgImport.looksLikeHome(home)) throw CliError(ExitCode.NOT_FOUND, "no GnuPG keyring in ${safe(home.toString())}")
        val scan = GnupgImport.scan(home)
        val withSecrets = o.flag("--secret")
        val withTrust = if (scan.isDefault) !o.flag("--no-trust") else o.flag("--trust") && !o.flag("--no-trust")
        when {
            !scan.isDefault -> err("not your GnuPG home: public keys and trust only, read from the files")
            scan.gpg == null -> err("gpg not found: public keys and trust only")
        }
        if (withSecrets && !scan.isDefault) err("secret keys are only read from your own GnuPG home; none will be imported")
        val plan = GnupgImport.prepare(scan)
        if (o.flag("--dry-run")) {
            val preview = GnupgImport.trustPreview(repo, plan, withSecrets)
            out("Keys in $home: ${plan.keys.size}")
            if (withTrust) {
                out("Trust that would change: ${preview.size}")
                preview.forEach { out("  " + trustLine(it)) }
            }
            plan.notes.forEach { err(safe(it)) }
            out("Dry run: nothing was imported")
            return@runBlocking ExitCode.OK
        }
        val result = GnupgImport.apply(repo, plan, withTrust, withSecrets)
        out("Import from ${safe(home.toString())}: ${result.report.summary()}")
        if (withTrust) {
            out("Trust raised on ${result.trustSet} key(s)")
            result.trustChanges.forEach { out("  " + trustLine(it)) }
        }
        if (withSecrets) out("Secret keys imported: ${result.secretsImported}")
        result.notes.forEach { err(safe(it)) }
        if (result.report.total > 0 && result.report.failed == result.report.total) ExitCode.FAILED else ExitCode.OK
    }

    private fun trustLine(c: GnupgImport.TrustChange): String =
        "${safe(c.userId)}  ${safe(c.fingerprint.uppercase().takeLast(16))}  ${c.from?.name ?: "new"} -> ${c.to.name}"

    private fun export(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val secret = o.flag("--secret")
        val gpgCompat = o.flag("--gpg-compat")
        val selector = o.positional() ?: throw CliError(ExitCode.USAGE, "export: <key selector>")
        val outPath = o.value("--output", "-o")
        val e = resolveOne(repo, selector, requireSecret = secret)
        val armor = if (secret) {
            // 3.0.0 (4d): the passphrase comes the way every other verb takes one (env, fd or a
            // prompt), never as a flag: a flag is visible to every process on the machine.
            if (gpgCompat) repo.exportArmoredPrivateKeyGpgCompat(e.fingerprint, passphraseOrNull(o))
            else repo.exportArmoredPrivateKey(e.fingerprint)
        } else repo.exportArmoredPublicKeyForSharing(e.fingerprint)
        armor ?: throw CliError(ExitCode.NOT_FOUND, "no ${if (secret) "secret" else "public"} material for ${e.shortFingerprint}")
        // 3.0.0 (4d): a secret key file is created readable by its owner only.
        if (secret && outPath != null && outPath != "-") OwnerOnlyFile.write(Path.of(outPath), armor)
        else writeAll(outPath, armor.toByteArray(Charsets.UTF_8))
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
            out("${safe(k.fingerprint.uppercase())}  ${k.algorithm.displayName.padEnd(20)}  [$flags]  ${safe(k.userID)}")
        }
        ExitCode.OK
    }

    private fun genKey(repo: DesktopKeyRepository, args: List<String>): Int = runBlocking {
        val o = Options(args)
        val name = o.value("--name") ?: throw CliError(ExitCode.USAGE, "gen-key: --name <name>")
        // 3.0.0 (Android 4.5.0 item 3): the email is optional, for a name-only User ID.
        val email = o.value("--email") ?: ""
        val algoName = o.value("--algo")
        val algo = parseAlgorithm(algoName ?: "ed25519")
        val expiresDays = o.value("--expires")?.toLongOrNull()
        val expirationSeconds = expiresDays?.let { it * 24 * 60 * 60 }
        // 3.0.0 (Android 4.5.0 item 7): --subkey composes a v6 Ed25519 key, as the app's granular mode.
        val subkeys = o.all("--subkey").map { parseSubkey(it) }
        val noDefaultEncryption = o.flag("--no-default-encryption")
        val granular = subkeys.isNotEmpty() || noDefaultEncryption
        val sshAuth = o.flag("--ssh-auth")
        if (granular && algoName != null) {
            throw CliError(ExitCode.USAGE, "gen-key: --subkey builds a v6 Ed25519 key; leave out --algo")
        }
        if (granular && sshAuth) {
            throw CliError(ExitCode.USAGE, "gen-key: with --subkey, add the SSH key as --subkey ed25519-auth")
        }
        val pass = requirePassphrase(o, "Passphrase for the new key (empty for none): ", allowEmpty = true)
            .ifEmpty { null }
        val entity = if (granular) {
            repo.generateGranularKey(
                name, email, !noDefaultEncryption,
                subkeys.map { com.pgpony.android.crypto.GranularSubkeySpec(it, expirationSeconds) },
                pass, expirationSeconds
            )
        } else {
            repo.generateKey(name, email, algo, pass, expirationSeconds)
        }
        // 3.0.0 (Android 4.6.0 item 16): the SSH authentication subkey. A failure keeps the key.
        if (sshAuth) {
            try {
                DesktopKeyEdits(repo).addSshAuthSubkeyAtGeneration(entity.fingerprint, algo, expirationSeconds, pass)
            } catch (t: Throwable) {
                err("warning: key created, but the SSH subkey could not be added: ${t.message ?: t::class.simpleName}")
            }
        }
        out("Generated ${safe(entity.userID)}")
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
            matches.isEmpty() -> throw CliError(ExitCode.NOT_FOUND, "no ${if (requireSecret) "secret " else ""}key matches \"${safe(selector)}\"")
            matches.size > 1 -> throw CliError(
                ExitCode.NOT_FOUND,
                "\"${safe(selector)}\" is ambiguous: matches ${matches.size} keys; use a fingerprint. " +
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
        "mlkem-v4", "mlkem-768-v4", "pqc-v4" -> KeyAlgorithm.MLKEM768_X25519_V4
        "mlkem-brainpool", "mlkem-bp256", "mlkem-bp256-v5" -> KeyAlgorithm.MLKEM768_BP256_LIBREPGP
        "mlkem-1024", "mlkem-1024-v6", "pqc-1024" -> KeyAlgorithm.MLKEM1024_X448_V6
        "mlkem-1024-librepgp", "mlkem-1024-v5" -> KeyAlgorithm.MLKEM1024_X448_LIBREPGP
        "mldsa", "mldsa-65", "ml-dsa", "pqc-sign" -> KeyAlgorithm.MLDSA65_ED25519_V6
        "mldsa-87", "ml-dsa-87", "pqc-sign-87" -> KeyAlgorithm.MLDSA87_ED448_V6
        else -> throw CliError(
            ExitCode.USAGE,
            "gen-key: unknown --algo \"$name\" (ed25519, rsa2048, rsa4096, v6-ed25519, v6-x25519, " +
                "v6-ed448, v6-x448, mlkem-v6, mlkem-v4, mlkem-librepgp, mlkem-1024, mlkem-1024-librepgp, " +
                "mlkem-brainpool, mldsa-65, mldsa-87)"
        )
    }

    /** 3.0.0: a `--subkey` kind, the Add Subkey list for a v6 key (AddSubkeyChoice). */
    internal fun parseSubkey(name: String): com.pgpony.android.crypto.AddSubkeyChoice {
        return when (name.lowercase().replace("_", "-")) {
            "ed25519-sign", "ed25519" -> com.pgpony.android.crypto.AddSubkeyChoice.Classical(com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN)
            "ed25519-auth", "ssh" -> com.pgpony.android.crypto.AddSubkeyChoice.Classical(com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_AUTH)
            "x25519", "x25519-encrypt" -> com.pgpony.android.crypto.AddSubkeyChoice.Classical(com.pgpony.android.crypto.ClassicalSubkeyGen.ClassicalSubkeyType.X25519_ENCRYPT)
            "mlkem-768", "mlkem" -> com.pgpony.android.crypto.AddSubkeyChoice.PqEncryption(com.pgpony.android.crypto.pqc.CompositeSuite.IETF_768)
            "mlkem-1024" -> com.pgpony.android.crypto.AddSubkeyChoice.PqEncryption(com.pgpony.android.crypto.pqc.CompositeSuite.IETF_1024)
            "mldsa-65", "mldsa" -> com.pgpony.android.crypto.AddSubkeyChoice.PqSigning(com.pgpony.android.crypto.pqc.CompositeSignSuite.MLDSA65_ED25519)
            "mldsa-87" -> com.pgpony.android.crypto.AddSubkeyChoice.PqSigning(com.pgpony.android.crypto.pqc.CompositeSignSuite.MLDSA87_ED448)
            else -> throw CliError(
                ExitCode.USAGE,
                "gen-key: unknown --subkey \"$name\" (ed25519-sign, ed25519-auth, x25519, mlkem-768, mlkem-1024, mldsa-65, mldsa-87)"
            )
        }
    }

    // ── Signature reporting (decrypt) ───────────────────────────────────

    private fun reportSignature(s: SignatureSummary.Summary, status: com.pgpony.android.crypto.SignerStatus) {
        val who = (s.signerLabel?.let { ": ${safe(it)}" } ?: "") +
            (s.keyIdHex?.takeIf { s.signer != null }?.let { " (${safe(it)})" } ?: "") +
            (s.weakKey?.let { " (weak signing key: ${safe(it)})" } ?: "")
        when (s.state) {
            SignatureSummary.State.VERIFIED -> err("Good signature$who")
            SignatureSummary.State.UNCONFIRMED -> err("Good signature$who (signer key not verified)")
            SignatureSummary.State.UNHELD -> err("Signed by a key not in the keyring" + (s.keyIdHex?.let { " (${safe(it)})" } ?: "") + ", not verified")
            SignatureSummary.State.INVALID -> {
                val reason = status.takeIf {
                    it != com.pgpony.android.crypto.SignerStatus.NONE && it != com.pgpony.android.crypto.SignerStatus.VERIFIED
                }?.let { " (${DecryptSignature.reason(it)})" } ?: ""
                err("BAD signature$who$reason")
            }
            SignatureSummary.State.NONE -> err("No signature")
        }
    }

    /**
     * [s] as one line of terminal text: control characters (C0, DEL, C1, line breaks included)
     * and the bidirectional overrides are shown as \xNN or \uNNNN instead of acting on the
     * terminal. For anything taken from a key or a message.
     */
    internal fun safe(s: String?): String {
        if (s == null) return ""
        val sb = StringBuilder(s.length)
        for (c in s) {
            val code = c.code
            when {
                code < 0x20 || code == 0x7F || code in 0x80..0x9F -> sb.append(String.format("\\x%02X", code))
                code == 0x061C || code == 0x200E || code == 0x200F || code in 0x202A..0x202E || code in 0x2066..0x2069 ->
                    sb.append(String.format("\\u%04X", code))
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }

    /** Like [safe], but keeps line breaks and tabs: the last guard on everything printed. */
    internal fun terminalText(s: String): String =
        s.split('\n').joinToString("\n") { line -> line.split('\t').joinToString("\t") { safe(it) } }

    // ── I/O ─────────────────────────────────────────────────────────────

    private fun readAll(input: String?): ByteArray =
        if (input == null || input == "-") System.`in`.readBytes()
        else Files.readAllBytes(Path.of(input).also {
            if (!Files.exists(it)) throw CliError(ExitCode.NOT_FOUND, "input file not found: ${safe(input)}")
        })

    /** A private (owner-only) temp folder for [block], removed with everything in it afterwards. */
    private inline fun <T> withScratch(block: (Path) -> T): T {
        val dir = Files.createTempDirectory("pgpony-cli", *SafeFiles.dirAttrs(ownerOnly = true))
        try {
            return block(dir)
        } finally {
            runCatching {
                Files.walk(dir).use { w -> w.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
            }
        }
    }

    /**
     * The ciphertext to decrypt, as a file: the input file itself, or stdin spooled into
     * [scratch]. 3.0.0 (Android #31): a .zip holding one PGP message decrypts as that message
     * (its entry streamed into [scratch], bounded); none, or several, is an error rather than a
     * guess.
     */
    private fun cipherSource(input: String?, scratch: Path): Path {
        val file = if (input == null || input == "-") {
            scratch.resolve("input").also { p ->
                Files.newOutputStream(p, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { System.`in`.copyTo(it) }
            }
        } else {
            Path.of(input).also {
                if (!Files.exists(it)) throw CliError(ExitCode.NOT_FOUND, "input file not found: ${safe(input)}")
            }
        }
        if (!ZipTransport.looksLikeZip(file)) return file
        val entry = scratch.resolve("entry")
        val found = Files.newInputStream(file).use { ins ->
            Files.newOutputStream(entry, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use {
                ZipTransport.extractSinglePgpEntry(ins, it)
            }
        }
        return when (found) {
            is ZipTransport.Found.One -> entry
            ZipTransport.Found.None -> throw CliError(ExitCode.FAILED, "decrypt: no encrypted message in this .zip")
            ZipTransport.Found.Several -> throw CliError(
                ExitCode.FAILED, "decrypt: this .zip holds several encrypted files; extract them and decrypt one at a time"
            )
        }
    }

    /**
     * Where decrypt writes. The plaintext first goes to an owner-only temp file, written and read
     * back through the handle that created it: beside the --output file (so the final move is a
     * rename on one file system), or in the private scratch folder for stdout and for an output
     * that is not a plain file (/dev/null, a pipe, a terminal). [publish] moves it into place or
     * copies it out; [discard] removes whatever was not published.
     */
    private class DecryptTarget(
        private val tmp: SafeFiles.OpenTemp,
        private val final: Path?,
        private val direct: Boolean
    ) {
        private var published = false

        fun stream(): OutputStream = java.io.BufferedOutputStream(tmp.output(), 1 shl 16)

        fun publish() {
            when {
                final == null -> {
                    tmp.input().copyTo(System.out)
                    System.out.flush()
                }
                direct -> writeThrough(final) { tmp.input().copyTo(it) }
                else -> {
                    tmp.close()
                    SafeFiles.replaceInto(tmp.path, final)
                }
            }
            published = true
        }

        fun discard() {
            runCatching { tmp.close() }
            if (!published || final == null || direct) runCatching { Files.deleteIfExists(tmp.path) }
        }

        companion object {
            fun open(outPath: String?, scratch: Path): DecryptTarget {
                if (outPath == null || outPath == "-") {
                    return DecryptTarget(SafeFiles.openTemp(scratch, ownerOnly = true), null, direct = false)
                }
                val final = outputPath(outPath)
                if (writesThrough(final)) {
                    return DecryptTarget(SafeFiles.openTemp(scratch, ownerOnly = true), final, direct = true)
                }
                val dir = final.parent ?: throw CliError(ExitCode.USAGE, "--output has no folder: ${safe(outPath)}")
                val tmp = try {
                    SafeFiles.openTemp(dir, ownerOnly = true)
                } catch (e: java.nio.file.AccessDeniedException) {
                    // A file the user may write in a folder they may not (/dev/stdout sent to a
                    // file): written in place once the message has passed.
                    if (!Files.isWritable(final)) throw e
                    return DecryptTarget(SafeFiles.openTemp(scratch, ownerOnly = true), final, direct = true)
                }
                return DecryptTarget(tmp, final, direct = false)
            }
        }
    }

    /** The absolute --output path; a folder there is a usage error. */
    private fun outputPath(outPath: String): Path {
        val final = Path.of(outPath).toAbsolutePath().normalize()
        if (Files.isDirectory(final, LinkOption.NOFOLLOW_LINKS)) {
            throw CliError(ExitCode.USAGE, "--output is a folder: ${safe(outPath)}")
        }
        return final
    }

    /**
     * An output that exists and is not a plain file or folder (/dev/null, /dev/stdout to a pipe
     * or terminal, a named pipe) is written in place; nothing can be renamed over it.
     */
    private fun writesThrough(final: Path): Boolean =
        Files.exists(final) && !Files.isRegularFile(final) && !Files.isDirectory(final)

    private inline fun writeThrough(final: Path, block: (OutputStream) -> Unit) {
        Files.newOutputStream(final, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING).use { out ->
            block(out)
            out.flush()
        }
    }

    /**
     * Write [bytes] to stdout, or to [outPath] through a temp file beside it that is then
     * renamed into place (a link at [outPath] is replaced, never written through). An output
     * that is not a plain file (/dev/null, a pipe) is written in place.
     */
    private fun writeAll(outPath: String?, bytes: ByteArray) {
        if (outPath == null || outPath == "-") { System.out.write(bytes); System.out.flush(); return }
        val final = outputPath(outPath)
        if (writesThrough(final)) { writeThrough(final) { it.write(bytes) }; return }
        val dir = final.parent ?: throw CliError(ExitCode.USAGE, "--output has no folder: ${safe(outPath)}")
        val tmp = try {
            SafeFiles.openTemp(dir, ownerOnly = false)
        } catch (e: java.nio.file.AccessDeniedException) {
            if (!Files.isWritable(final)) throw e
            writeThrough(final) { it.write(bytes) }
            return
        }
        try {
            tmp.output().write(bytes)
            tmp.close()
            SafeFiles.replaceInto(tmp.path, final)
        } catch (t: Throwable) {
            runCatching { tmp.close() }
            runCatching { Files.deleteIfExists(tmp.path) }
            throw t
        }
    }

    private fun fileName(input: String?): String? =
        input?.takeIf { it != "-" }?.let { Path.of(it).fileName?.toString() }

    // ── Passphrase ──────────────────────────────────────────────────────

    /**
     * 3.0.0 (4d): a named source that gives nothing is an error, not "no passphrase". A typo in
     * the variable name would otherwise make gen-key write an unprotected key without a word.
     */
    internal fun passphraseFromEnv(name: String): String =
        System.getenv(name) ?: throw CliError(ExitCode.USAGE, "environment variable $name is not set")

    internal fun passphraseFromFd(fd: String): String {
        val n = fd.trim().toIntOrNull()?.takeIf { it >= 0 }
            ?: throw CliError(ExitCode.USAGE, "--passphrase-fd wants a file descriptor number, not \"$fd\"")
        return runCatching { File("/dev/fd/$n").readText().trimEnd('\n', '\r') }.getOrElse {
            throw CliError(ExitCode.USAGE, "could not read a passphrase from file descriptor $n")
        }
    }

    /** Passphrase from --passphrase-env / --passphrase-fd, or null (no interactive prompt). */
    private fun passphraseOrNull(o: Options): String? {
        o.value("--passphrase-env")?.let { return passphraseFromEnv(it).ifEmpty { null } }
        o.value("--passphrase-fd")?.let { return passphraseFromFd(it).ifEmpty { null } }
        // Interactive only if a console is attached (not piped).
        val console = System.console() ?: return null
        val chars = console.readPassword("Passphrase (empty if none): ")
        return chars?.concatToString()?.ifEmpty { null }
    }

    private fun requireGiven(passphrase: String, allowEmpty: Boolean) {
        if (!allowEmpty && passphrase.isEmpty()) throw CliError(ExitCode.USAGE, "passphrase required")
    }

    private fun requirePassphrase(o: Options, prompt: String, allowEmpty: Boolean = false): String {
        o.value("--passphrase-env")?.let { return passphraseFromEnv(it).also { p -> requireGiven(p, allowEmpty) } }
        o.value("--passphrase-fd")?.let { return passphraseFromFd(it).also { p -> requireGiven(p, allowEmpty) } }
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

    /** Tests run the verbs against a keyring of their own. */
    internal var repoOverride: DesktopKeyRepository? = null

    private fun withRepo(block: (DesktopKeyRepository) -> Int): Int {
        repoOverride?.let { return block(it) }
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

    private fun out(msg: String) = println(terminalText(msg))
    private fun err(msg: String) = System.err.println("pgpony: " + terminalText(msg))

    private fun usage(): Int {
        err(
            """
            pgpony: OpenPGP on the command line (shares the app's keyring)

            Usage: pgpony <verb> [options] [file]

            Verbs:
              encrypt   -r <key> [-r ...] [-u <key>] [-c] [-a] [-o out] [file|-]
              decrypt   [--decrypt-with <key>] [--require-signature | --require-verified] [-o out] [file|-]
              sign      [-u <key>] [-b] [-a] [-o out] [file|-]
              verify    [-s <sigfile>] [--require-verified] [file|-]
              import    [file|-]
              import-gnupg [--homedir DIR] [--secret] [--no-trust | --trust] [--dry-run]
              export    [--secret] [-a] [-o out] <key>
              list-keys [--secret]
              gen-key   --name <n> [--email <e>] [--algo ed25519] [--expires <days>] [--ssh-auth]
                        [--subkey <kind> ...] [--no-default-encryption]
              card-info                        report the PC/SC readers this build can see

            Common options:
              -a, --armor            ASCII-armored output
              -o, --output <file>    write to file (default: stdout)
              -r, --recipient <key>  recipient (fingerprint, key id, or email)
              -u, --sign-as <key>    signing key
              --no-signing-defaults  sign with the -u key itself, not its signing default
              --decrypt-with <key>   try this key first, then its fallbacks
              --require-signature    decrypt: write nothing unless a key in the keyring made a good signature
              --require-verified     decrypt, verify: as above, and the signer key must be verified
              --passphrase-env VAR   read passphrase from an environment variable
              --passphrase-fd N      read passphrase from a file descriptor

            Decrypt writes nothing until the whole message has passed its integrity check; the
            output appears (or reaches stdout) only then, readable by you alone.

            import-gnupg: a folder other than your own GnuPG home is only read, never run through
            gpg; its trust is carried over only with --trust. --dry-run lists what would change.

            A key selector is a fingerprint, long key id, email, or a unique name substring.
            Exit codes:
              0  ok
              1  usage
              2  key or file not found
              3  failed (a message that fails its integrity check exits 3 and writes nothing)
              4  unverified: verify found a bad, unknown or missing signature; decrypt found a
                 signature that is present but bad (output written, as gpg does), or a
                 --require-signature / --require-verified condition was not met (nothing written)
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
        "--algo", "--expires", "--decrypt-with", "--subkey",
        "--homedir", // 3.0.0 (5b): `pgpony import-gnupg --homedir DIR`
        "--op" // D14 — `pgpony open --op <verb>` (Main.parseOpenArgs)
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

    /** Every positional, in order — `open` takes several files (D14); the D10 verbs take one. */
    fun allPositionals(): List<String> = positionals.toList()
}
