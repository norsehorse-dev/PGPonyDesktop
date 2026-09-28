// GpgShim.kt
// PGPony Desktop — D15 (2.0.0 §1b): the git signing shim, `pgpony-gpg`.
//
// git shells out to whatever `gpg.program` names and speaks a tiny, documented slice of gpg's
// interface. This serves EXACTLY that slice — commit/tag sign and verify — against the app
// keyring, so `git config --global gpg.program pgpony-gpg` gives verified badges with no
// GnuPG installed. It is NOT a gpg-compatible tool for anything else: unrecognized modes exit
// non-zero, the deliberate bounded version of "replace GnuPG" (2.0.0 §1c: no Assuan, no agent
// emulation).
//
// PASSPHRASES (3.0.0 stage 4b). The shim is its own short-lived process and keeps nothing: no
// passphrase, no copy of the session setting. A protected key is signed by the running app over
// ShimBridge (ShimBridge.kt), which prompts in its window or uses the passphrase it remembers
// for the session length in Settings. Without the app running, a protected key is refused with
// a message saying to open PGPony.
//
// DISPATCH. Not a third binary — a face of the one artifact (RelayPony pattern, like
// pgpony-cli). Reached two ways: argv[0] basename `pgpony-gpg` (how git invokes it, via a
// packaging launcher / jpackage.app-path), or the explicit `gpg-shim` verb (the spelling a
// script or a test can always reach without a symlink). Windows gets its own `pgpony-gpg.exe`
// from packaging, the pgpony-cli.exe precedent.
//
// STATUS FD. git runs `--status-fd=N` and reads machine-readable lines from fd N; the two
// PGPony cares about are SIG_CREATED (after signing) and GOODSIG/BADSIG/VALIDSIG/NO_PUBKEY
// (after verify). The bounded contract (2.0.0 §1b) pins N to 1 or 2 — git's own commit path —
// so the shim maps N onto stdout/stderr and treats any other fd as stderr best-effort rather
// than dup'ing an arbitrary inherited descriptor, which the JVM can't portably do anyway.
//
// The shim is pure over its streams — run(argv, stdin, stdout, stderr) : Int — so a test drives
// it with ByteArray streams and no process. Main.gpgShimMain wires the real fds and exits.

package com.pgpony.desktop

import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import kotlinx.coroutines.runBlocking
import org.bouncycastle.util.encoders.Hex
import java.io.InputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path

object GpgShim {

    /**
     * Run the shim over explicit streams. [args] is the argv git passes AFTER the program name
     * (so `--status-fd=2 -bsau KEY`). Returns the process exit code — 0 on a good sign or a
     * good verify, non-zero otherwise, matching gpg closely enough for git's `$? == 0` check.
     */
    fun run(
        args: List<String>,
        stdin: InputStream,
        stdout: OutputStream,
        stderr: PrintStream
    ): Int {
        // git always sets --status-fd; default to 1 if (a test) omits it. Only 1/2 are honored.
        val statusFd = args.firstOrNull { it.startsWith("--status-fd=") }
            ?.substringAfter('=')?.trim()?.toIntOrNull() ?: 1
        val status: PrintStream = if (statusFd == 1) PrintStream(stdout, true) else stderr

        return when {
            // -b detach, -s sign; -a armor, -u <user>. git's flags arrive clumped or split.
            args.any { it == "-bsau" || it == "--detach-sign" } ||
                (hasShort(args, 'b') && hasShort(args, 's')) ->
                sign(args, stdin, stdout, stderr, status)

            args.contains("--verify") -> verify(args, stderr, status)

            // git also calls `gpg --version` while probing gpg.program; answer plausibly.
            args.contains("--version") -> {
                PrintStream(stdout, true).println(VERSION_BANNER)
                0
            }

            else -> {
                stderr.println("pgpony-gpg: unsupported invocation (only commit/tag sign + verify)")
                2
            }
        }
    }

    // ── Sign ────────────────────────────────────────────────────────────────

    private fun sign(
        args: List<String>,
        stdin: InputStream,
        stdout: OutputStream,
        stderr: PrintStream,
        status: PrintStream
    ): Int {
        val selector = valueOf(args, "-u", "--local-user")
            ?: args.dropWhile { it != "-bsau" }.drop(1).firstOrNull() // `-bsau KEYID` positional
            ?: return fail(stderr, "sign: no signing key given (-u)")

        // 3.0.0 (4d): bounded. A commit or tag object is small; the running app takes no more.
        val payload = stdin.readNBytes(ShimBridge.MAX_PAYLOAD + 1)
        if (payload.size > ShimBridge.MAX_PAYLOAD) return fail(stderr, "sign: the data to sign is too large")
        return withRepo { repo ->
            val keys = runBlocking { repo.allKeys() }.filter { it.isKeyPair }
            val picked = Cli.matchKeys(keys, selector).firstOrNull()
                ?: return@withRepo fail(stderr, "sign: no secret key matches \"$selector\"")
            // 3.0.0 (plan 3.8): the key's sign-only signing default, as Android's OpenPGP API
            // provider applies it. SIG_CREATED below names the key that actually signed.
            val match = runBlocking { repo.signerAfterDefaults(picked, emptyList(), signOnly = true) }
            // 3.0.0 (Android 4.5.3): an expired key does not sign, here as everywhere else. A
            // commit signed by an expired key would show as bad on the other side anyway.
            if (!KeyUsePolicy.allowExpiredKeys() && KeyUsePolicy.isExpired(match)) {
                return@withRepo fail(stderr, "sign: key ${match.fingerprint} has expired " +
                    "(turn on Allow expired keys in PGPony's Settings to sign with it)")
            }

            // 3.0.0 stage 4b (plan section 7): the shim holds no passphrase and reads no session
            // setting. A key that signs without a passphrase signs here; a protected key is signed
            // by the running app through ShimBridge, which uses the passphrase it remembers under
            // the session policy or asks for it in its window. A composite ML-DSA key signs
            // through the composite signer; hosted forges show their own verdict for these, and
            // `git verify-commit` through this shim verifies them.
            val signed = when (val local = ShimSigner.sign(repo, match, payload, passphrase = null)) {
                is ShimSigner.Result.Signed -> local
                is ShimSigner.Result.Failed -> return@withRepo fail(stderr, "sign: ${local.message}")
                ShimSigner.Result.Locked, ShimSigner.Result.WrongPassphrase ->
                    when (val remote = ShimBridge.requestSignature(Config.dataDir, match.fingerprint, payload)) {
                        is ShimBridge.Reply.Signed -> ShimSigner.Result.Signed(remote.armored, remote.pkAlgo, remote.hashAlgo)
                        is ShimBridge.Reply.Refused -> return@withRepo fail(stderr, "sign: ${remote.message}")
                        ShimBridge.Reply.Unreachable -> return@withRepo fail(
                            stderr,
                            "sign: key ${match.fingerprint} is passphrase-protected; open PGPony and sign " +
                                "again, and the app will ask for the passphrase"
                        )
                    }
            }

            // gpg DETAILS SIG_CREATED fields: type(D) pk_algo hash_algo sig_class(00)
            // timestamp(0, informational) fpr. git only needs to see the line.
            val armored = signed.armored
            val pkAlgo = signed.pkAlgo
            val hashAlgo = signed.hashAlgo
            stdout.write(armored)
            stdout.flush()

            val fpr = match.fingerprint.uppercase()
            status.println("[GNUPG:] SIG_CREATED D $pkAlgo $hashAlgo 00 0 $fpr")
            0
        }
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    private fun verify(args: List<String>, stderr: PrintStream, status: PrintStream): Int {
        // git: `gpg --verify <sig-file> <signed-file>` — the two trailing non-option args.
        val files = args.filterNot { it.startsWith("-") }
        val sigPath = files.getOrNull(0) ?: return fail(stderr, "verify: no signature file")
        val dataPath = files.getOrNull(1) ?: return fail(stderr, "verify: no signed-data file")

        val sigBytes = try {
            Files.readAllBytes(Path.of(sigPath))
        } catch (e: Exception) {
            return fail(stderr, "verify: cannot read signature: ${e.message}")
        }
        val signed = try {
            Files.readAllBytes(Path.of(dataPath))
        } catch (e: Exception) {
            return fail(stderr, "verify: cannot read signed data: ${e.message}")
        }

        return withRepo { repo ->
            val rings = runBlocking {
                repo.allKeys().mapNotNull { repo.loadPublicKeyRing(it.fingerprint) }
            }
            // 3.0.0: composite ML-DSA signatures first (BouncyCastle cannot parse them).
            val result = runBlocking {
                DesktopCompositeVerify.verifyDetached(repo, String(sigBytes, Charsets.UTF_8), signed)
            } ?: VerifyService.shared.verifyDetached(sigBytes, signed, rings)
            when (val r = result) {
                is VerificationResult.Verified -> {
                    // 3.0.0 (4d): the name and email come from the signer's User ID, which the
                    // signer wrote. Escaped the way gpg escapes status lines, or a line break in a
                    // User ID would add a status line of its own (a second VALIDSIG, a TRUST_).
                    val who = statusText("${r.signerName ?: ""} <${r.signerEmail ?: ""}>".trim())
                    // git reads GOODSIG + VALIDSIG off the status fd; the human line is stderr.
                    status.println("[GNUPG:] GOODSIG ${r.signerKeyID} $who")
                    status.println("[GNUPG:] VALIDSIG ${r.signerFingerprint} 0 0 0 0 0 0 0 ${r.signerFingerprint}")
                    // 3.0.0 (Android 4.5.3, #57): the signer key's trust, the way gpg reports it,
                    // so `git log --show-signature` and %G? tell a good signature from an
                    // unconfirmed key ("U") apart from one from a key the user verified ("G").
                    val signer = runBlocking { repo.byFingerprint(r.signerFingerprint) ?: repo.findByKeyId(r.signerKeyID) }
                    status.println(
                        when (r.signerTrust ?: signer?.trustLevel) {
                            com.pgpony.android.data.TrustLevel.ULTIMATE -> "[GNUPG:] TRUST_ULTIMATE 0 pgp"
                            com.pgpony.android.data.TrustLevel.VERIFIED -> "[GNUPG:] TRUST_FULLY 0 pgp"
                            else -> "[GNUPG:] TRUST_UNDEFINED 0 pgp"
                        }
                    )
                    stderr.println("pgpony-gpg: Good signature from \"$who\" [${r.signerKeyID}]")
                    0
                }
                is VerificationResult.Invalid -> {
                    status.println("[GNUPG:] BADSIG ${r.signerKeyID ?: "0000000000000000"}")
                    stderr.println("pgpony-gpg: BAD signature: ${statusText(r.reason)}")
                    1
                }
                is VerificationResult.UnknownSigner -> {
                    status.println("[GNUPG:] NO_PUBKEY ${r.signerKeyID}")
                    stderr.println("pgpony-gpg: signer's public key is not in the keyring (${r.signerKeyID})")
                    1
                }
                is VerificationResult.Unsigned -> {
                    stderr.println("pgpony-gpg: no signature found")
                    1
                }
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private const val VERSION_BANNER =
        "gpg (PGPony shim) 2.0.0\nCompatible with the git commit/tag signing interface only."

    /**
     * Text from a signature for a status or message line: gpg's status-fd escaping, where a
     * control character or '%' becomes %XX, so the text can never end the line it is on.
     */
    internal fun statusText(raw: String): String = buildString {
        for (ch in raw) {
            if (ch < ' ' || ch == '%' || ch == '\u007F') append('%').append("%02X".format(ch.code))
            else append(ch)
        }
    }

    private fun hasShort(args: List<String>, c: Char): Boolean =
        args.any { it.length >= 2 && it[0] == '-' && it[1] != '-' && it.contains(c) }

    private fun valueOf(args: List<String>, vararg names: String): String? {
        for (i in args.indices) {
            val a = args[i]
            if (a in names) return args.getOrNull(i + 1)
            for (n in names) if (n.startsWith("--") && a.startsWith("$n=")) return a.substringAfter('=')
        }
        return null
    }

    private fun fail(stderr: PrintStream, msg: String): Int {
        stderr.println("pgpony-gpg: $msg")
        return 2
    }

    /** Same keyring open as Cli.withRepo (that one is private); shares the app's db + keys. */
    private fun <T> withRepo(block: (DesktopKeyRepository) -> T): T {
        val db = Db.open(Config.dbFile)
        return try {
            val repo = DesktopKeyRepository(db, KeyMaterialStore(Config.keysDir))
            runBlocking { repo.migrateLegacyJson(Config.legacyKeyringFile) }
            block(repo)
        } finally {
            db.close()
        }
    }
}
