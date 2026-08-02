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

import com.pgpony.android.crypto.SigningService
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

        val payload = stdin.readBytes()
        return withRepo { repo ->
            val keys = runBlocking { repo.allKeys() }.filter { it.isKeyPair }
            val match = Cli.matchKeys(keys, selector).firstOrNull()
                ?: return@withRepo fail(stderr, "sign: no secret key matches \"$selector\"")
            val ring = repo.loadSecretKeyRing(match.fingerprint)
                ?: return@withRepo fail(stderr, "sign: key ${match.fingerprint} could not be loaded")

            val armored = try {
                SigningService.shared.signDetached(payload, ring, passphrase = null, armor = true)
            } catch (e: Exception) {
                // A passphrase-protected key can't be served non-interactively — git has no way
                // to prompt through us. The GUI agent is the interactive path; say so.
                return@withRepo fail(stderr, "sign: ${e.message ?: "signing failed"} " +
                    "(protected keys are not available to the git shim)")
            }
            stdout.write(armored)
            stdout.flush()

            // git only needs to see SIG_CREATED to accept the signature. Fields per gpg's
            // DETAILS: type(D) pk_algo hash_algo sig_class(00) timestamp(0 — informational) fpr.
            val fpr = match.fingerprint.uppercase()
            status.println("[GNUPG:] SIG_CREATED D 22 8 00 0 $fpr")
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
            when (val r = VerifyService.shared.verifyDetached(sigBytes, signed, rings)) {
                is VerificationResult.Verified -> {
                    val who = "${r.signerName ?: ""} <${r.signerEmail ?: ""}>".trim()
                    // git reads GOODSIG + VALIDSIG off the status fd; the human line is stderr.
                    status.println("[GNUPG:] GOODSIG ${r.signerKeyID} $who")
                    status.println("[GNUPG:] VALIDSIG ${r.signerFingerprint} 0 0 0 0 0 0 0 ${r.signerFingerprint}")
                    stderr.println("pgpony-gpg: Good signature from \"$who\" [${r.signerKeyID}]")
                    0
                }
                is VerificationResult.Invalid -> {
                    status.println("[GNUPG:] BADSIG ${r.signerKeyID ?: "0000000000000000"}")
                    stderr.println("pgpony-gpg: BAD signature — ${r.reason}")
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
