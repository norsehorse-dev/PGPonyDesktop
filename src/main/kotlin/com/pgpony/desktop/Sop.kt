// Sop.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5a (plan F2, Android 4.7.0 #64): `pgpony-sop`, a
// Stateless OpenPGP command line (draft-dkg-openpgp-stateless-cli) over PGPony's engine, so
// PGPony can take part in the sequoia-pgp OpenPGP interoperability test suite.
//
// Stateless means no keyring: every key and certificate arrives as a file argument and nothing
// is kept. Internally each invocation loads what it was given into a scratch keyring in a
// private temporary folder (SopKeyring) so the same code paths the app uses (EncryptOps, the
// decrypt engine, composite ML-DSA and ML-KEM, v4 interop keys) do the work; the folder is
// deleted before the process ends. The user's own keyring, settings and passphrase cache are
// never read or written.
//
// Reached as `pgpony-sop` (argv0, like pgpony-gpg) or `pgpony sop <subcommand>`. Implemented:
// version, list-profiles, generate-key, extract-cert, sign, verify, encrypt, decrypt, armor,
// dearmor, inline-sign, inline-verify. Everything else answers UNSUPPORTED_SUBCOMMAND (69), and
// an option this build does not implement answers UNSUPPORTED_OPTION (37), as the spec asks.

package com.pgpony.desktop

import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path

/** SOP exit codes (draft-dkg-openpgp-stateless-cli, "Failure Modes"). */
object SopExit {
    const val OK = 0
    const val NO_SIGNATURE = 3
    const val UNSUPPORTED_ASYMMETRIC_ALGO = 13
    const val CERT_CANNOT_ENCRYPT = 17
    const val MISSING_ARG = 19
    const val INCOMPLETE_VERIFICATION = 23
    const val CANNOT_DECRYPT = 29
    const val PASSWORD_NOT_HUMAN_READABLE = 31
    const val UNSUPPORTED_OPTION = 37
    const val BAD_DATA = 41
    const val EXPECTED_TEXT = 53
    const val OUTPUT_EXISTS = 59
    const val MISSING_INPUT = 61
    const val KEY_IS_PROTECTED = 67
    const val UNSUPPORTED_SUBCOMMAND = 69
    const val UNSUPPORTED_SPECIAL_PREFIX = 71
    const val AMBIGUOUS_INPUT = 73
    const val KEY_CANNOT_SIGN = 79
    const val INCOMPATIBLE_OPTIONS = 83
    const val UNSUPPORTED_PROFILE = 89
}

class SopException(val code: Int, message: String) : Exception(message)

/**
 * The subcommand's arguments: options (`--name=value`, `--name value` for a valued option, or a
 * bare flag) and positionals. An option the subcommand does not know is UNSUPPORTED_OPTION.
 */
internal class SopArgs(args: List<String>, valued: Set<String>, flags: Set<String>) {
    private val values = mutableListOf<Pair<String, String>>()
    private val seenFlags = mutableSetOf<String>()
    val positionals = mutableListOf<String>()

    init {
        var i = 0
        var optionsDone = false
        while (i < args.size) {
            val a = args[i]
            when {
                optionsDone || !a.startsWith("--") || a == "-" -> positionals += a
                a == "--" -> optionsDone = true
                a.contains('=') -> {
                    val name = a.substringBefore('=')
                    if (name !in valued) throw SopException(SopExit.UNSUPPORTED_OPTION, "unsupported option $name")
                    values += name to a.substringAfter('=')
                }
                a in valued -> {
                    val v = args.getOrNull(i + 1) ?: throw SopException(SopExit.MISSING_ARG, "$a needs a value")
                    values += a to v
                    i++
                }
                a in flags -> seenFlags += a
                else -> throw SopException(SopExit.UNSUPPORTED_OPTION, "unsupported option $a")
            }
            i++
        }
    }

    fun flag(name: String): Boolean = name in seenFlags
    fun value(name: String): String? = values.lastOrNull { it.first == name }?.second
    fun all(name: String): List<String> = values.filter { it.first == name }.map { it.second }
}

/** Indirect inputs and outputs: a file name, `@ENV:NAME` or `@FD:n` (spec, "Special Designators"). */
internal class SopIo(private val env: (String) -> String?) {

    fun read(designator: String): ByteArray = when {
        designator.startsWith("@ENV:") ->
            env(designator.removePrefix("@ENV:"))?.toByteArray(Charsets.UTF_8)
                ?: throw SopException(SopExit.MISSING_INPUT, "environment variable ${designator.removePrefix("@ENV:")} is not set")
        designator.startsWith("@FD:") -> {
            val fd = fdNumber(designator)
            runCatching { File("/dev/fd/$fd").readBytes() }
                .getOrElse { throw SopException(SopExit.MISSING_INPUT, "cannot read file descriptor $fd") }
        }
        designator.startsWith("@") -> throw SopException(SopExit.UNSUPPORTED_SPECIAL_PREFIX, "unsupported designator $designator")
        else -> {
            val p = Path.of(designator)
            if (!Files.isRegularFile(p)) throw SopException(SopExit.MISSING_INPUT, "no such file: $designator")
            Files.readAllBytes(p)
        }
    }

    /** Checked before any work, so a refused output never follows an expensive operation. */
    fun checkOutput(designator: String) {
        when {
            designator.startsWith("@FD:") -> fdNumber(designator)
            designator.startsWith("@ENV:") || designator.startsWith("@") ->
                throw SopException(SopExit.UNSUPPORTED_SPECIAL_PREFIX, "unsupported output designator $designator")
            Files.exists(Path.of(designator)) -> throw SopException(SopExit.OUTPUT_EXISTS, "$designator already exists")
        }
    }

    fun write(designator: String, bytes: ByteArray) {
        checkOutput(designator)
        if (designator.startsWith("@FD:")) {
            FileOutputStream("/dev/fd/${fdNumber(designator)}").use { it.write(bytes) }
        } else {
            Files.write(Path.of(designator), bytes, java.nio.file.StandardOpenOption.CREATE_NEW)
        }
    }

    private fun fdNumber(designator: String): Int =
        designator.removePrefix("@FD:").toIntOrNull()?.takeIf { it >= 0 }
            ?: throw SopException(SopExit.UNSUPPORTED_SPECIAL_PREFIX, "bad file descriptor in $designator")

    /** A password for making something: it must be UTF-8 text. */
    fun passwordForWriting(designator: String): String {
        val bytes = read(designator)
        return decodeUtf8(bytes) ?: throw SopException(SopExit.PASSWORD_NOT_HUMAN_READABLE, "password is not UTF-8 text")
    }

    /** A password for opening something: as given, and with trailing whitespace trimmed (spec). */
    fun passwordsForReading(designator: String): List<String> {
        val bytes = read(designator)
        val text = decodeUtf8(bytes) ?: String(bytes, Charsets.ISO_8859_1)
        return listOf(text, text.trimEnd()).distinct().filter { it.isNotEmpty() }
    }

    companion object {
        fun decodeUtf8(bytes: ByteArray): String? = runCatching {
            Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        }.getOrNull()
    }
}

object Sop {

    const val SPEC = "~draft-dkg-openpgp-stateless-cli-11"

    /** Run one subcommand. [args] excludes the program name. Returns the exit code. */
    fun run(
        args: List<String>,
        stdin: InputStream,
        stdout: OutputStream,
        stderr: PrintStream,
        env: (String) -> String? = System::getenv
    ): Int {
        val sub = args.firstOrNull()
        val rest = args.drop(1)
        return try {
            val io = SopIo(env)
            val code = when (sub) {
                null -> throw SopException(SopExit.MISSING_ARG, "no subcommand; try `version`")
                "version" -> version(SopArgs(rest, emptySet(), setOf("--backend", "--extended", "--sop-spec")), stdout)
                "list-profiles" -> listProfiles(rest, stdout)
                "generate-key" -> SopCrypto.generateKey(rest, io, stdout)
                "extract-cert" -> SopCrypto.extractCert(rest, stdin, stdout)
                "sign" -> SopCrypto.sign(rest, io, stdin, stdout)
                "verify" -> SopCrypto.verify(rest, io, stdin, stdout)
                "inline-sign" -> SopCrypto.inlineSign(rest, io, stdin, stdout)
                "inline-verify" -> SopCrypto.inlineVerify(rest, io, stdin, stdout)
                "encrypt" -> SopCrypto.encrypt(rest, io, stdin, stdout)
                "decrypt" -> SopCrypto.decrypt(rest, io, stdin, stdout)
                "armor" -> SopArmor.armor(rest, stdin, stdout)
                "dearmor" -> SopArmor.dearmor(rest, stdin, stdout)
                else -> throw SopException(SopExit.UNSUPPORTED_SUBCOMMAND, "unsupported subcommand $sub")
            }
            stdout.flush()
            code
        } catch (e: SopException) {
            stderr.println("pgpony-sop: ${e.message}")
            e.code
        } catch (e: Exception) {
            stderr.println("pgpony-sop: ${e.message ?: e.javaClass.simpleName}")
            SopExit.BAD_DATA
        }
    }

    private fun version(a: SopArgs, out: OutputStream): Int {
        val backend = "PGPony engine ${AppVersion.VERSION} (Bouncy Castle ${bouncyCastleVersion()})"
        val text = when {
            a.flag("--backend") -> backend
            a.flag("--sop-spec") -> SPEC
            a.flag("--extended") -> "pgpony-sop ${AppVersion.VERSION}\n$backend\n$SPEC\nhttps://pgpony.app"
            else -> "pgpony-sop ${AppVersion.VERSION}"
        }
        out.write((text + "\n").toByteArray(Charsets.UTF_8))
        return SopExit.OK
    }

    private fun bouncyCastleVersion(): String = runCatching {
        org.bouncycastle.jce.provider.BouncyCastleProvider().versionStr
    }.getOrDefault("unknown")

    /** generate-key profiles, default first. Each maps to a key PGPony already makes. */
    internal val KEY_PROFILES = linkedMapOf(
        "draft-koch-eddsa-for-openpgp-00" to ("v4 Ed25519 with Cv25519 encryption, PGPony's default" to com.pgpony.android.crypto.KeyAlgorithm.ED25519_CV25519),
        "rfc9580" to ("v6 Ed25519 with X25519 encryption" to com.pgpony.android.crypto.KeyAlgorithm.V6_ED25519),
        "draft-ietf-openpgp-pqc" to ("v6 ML-DSA-65+Ed25519 with ML-KEM-768+X25519 encryption" to com.pgpony.android.crypto.KeyAlgorithm.MLDSA65_ED25519_V6),
        "rfc4880" to ("v4 RSA 3072" to com.pgpony.android.crypto.KeyAlgorithm.RSA_3072)
    )

    internal val ENCRYPT_PROFILES = linkedMapOf(
        "rfc9580" to "SEIPDv2 when every recipient supports it, else SEIPDv1; with a password, SKESKv6 and SEIPDv2"
    )

    private fun listProfiles(rest: List<String>, out: OutputStream): Int {
        val a = SopArgs(rest, emptySet(), emptySet())
        val sub = a.positionals.firstOrNull() ?: throw SopException(SopExit.MISSING_ARG, "list-profiles needs a subcommand")
        val lines = when (sub) {
            "generate-key" -> KEY_PROFILES.map { (name, v) -> "$name: ${v.first}" }
            "encrypt" -> ENCRYPT_PROFILES.map { (name, d) -> "$name: $d" }
            else -> throw SopException(SopExit.UNSUPPORTED_PROFILE, "$sub has no profiles")
        }
        out.write(lines.joinToString("\n", postfix = "\n").toByteArray(Charsets.UTF_8))
        return SopExit.OK
    }
}
