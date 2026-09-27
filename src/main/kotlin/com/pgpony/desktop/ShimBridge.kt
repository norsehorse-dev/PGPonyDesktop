// ShimBridge.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4b (plan section 7: "confirm the shim never holds a
// passphrase or setting itself and always asks the running app").
//
// pgpony-gpg is its own short-lived process, the shape of Android's #15 bug (a second process
// with a stale copy of the session setting). So the shim holds nothing: a key that signs without
// a passphrase signs in the shim as before, and a protected key is signed by the running app.
// The app uses the passphrase it remembers under SessionPolicy, or asks for it in its own window
// (the SSH agent's prompt), and remembers it for the session length. With the app not running,
// the shim says so and exits non-zero, as it did for every protected key before 3.0.0.
//
// The channel. The app listens on a loopback port and writes "<port> <token>" to
// dataDir/.shim-bridge, readable by the user only (0600 where the file system has POSIX
// permissions; the data directory is per-user on Windows). The token is 32 random bytes, new
// each launch, so another user on the machine cannot ask for a signature. A request is one line
// each of: the protocol name, the token, "SIGN <fingerprint>", the payload length; then the
// payload. The reply is "OK <pk algo> <hash algo> <length>" and the armored signature, or
// "ERR <message>". Only signing is served, two requests at a time, with bounded sizes.

package com.pgpony.desktop

import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Semaphore

object ShimBridge {

    internal const val FILE_NAME = ".shim-bridge"
    private const val PROTOCOL = "PGPONY-SHIM 1"
    internal const val MAX_PAYLOAD = 16 * 1024 * 1024
    private const val MAX_SIGNATURE = 1024 * 1024
    private const val MAX_LINE = 256
    private const val MAX_REPLY_LINE = 4096
    private const val MAX_CLIENTS = 2
    private const val REQUEST_TIMEOUT_MS = 10_000
    private const val CONNECT_TIMEOUT_MS = 2_000

    // Three passphrase prompts of 60 seconds each, and some room.
    private const val REPLY_TIMEOUT_MS = 200_000

    private val FINGERPRINT = Regex("[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}")

    sealed interface Reply {
        class Signed(val armored: ByteArray, val pkAlgo: Int, val hashAlgo: Int) : Reply
        class Refused(val message: String) : Reply
        data object Unreachable : Reply
    }

    fun interface Handler {
        fun sign(fingerprint: String, payload: ByteArray): Reply
    }

    internal sealed interface Request {
        class Sign(val fingerprint: String, val payload: ByteArray) : Request
        class Bad(val message: String) : Request
    }

    private val lock = Any()
    private var server: ServerSocket? = null
    private var endpointFile: Path? = null
    private var hooked = false

    // ── App side ────────────────────────────────────────────────────────────

    /** Start serving (the app's primary instance). True when listening. */
    fun start(dataDir: Path, handler: Handler): Boolean {
        synchronized(lock) {
            if (server != null) return true
            return startLocked(dataDir, handler)
        }
    }

    private fun startLocked(dataDir: Path, handler: Handler): Boolean =
        try {
            val socket = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
            val token = newToken()
            val file = dataDir.resolve(FILE_NAME)
            try {
                writePrivate(file, "${socket.localPort} $token\n")
            } catch (e: Exception) {
                socket.close()
                throw e
            }
            server = socket
            endpointFile = file
            if (!hooked) {
                hooked = true
                Runtime.getRuntime().addShutdownHook(Thread { stop() })
            }
            val slots = Semaphore(MAX_CLIENTS)
            Thread({ serve(socket, token, handler, slots) }, "pgpony-shim-bridge").apply {
                isDaemon = true
                start()
            }
            true
        } catch (_: Exception) {
            false
        }

    fun stop() {
        synchronized(lock) {
            runCatching { server?.close() }
            endpointFile?.let { f -> runCatching { Files.deleteIfExists(f) } }
            server = null
            endpointFile = null
        }
    }

    private fun serve(socket: ServerSocket, token: String, handler: Handler, slots: Semaphore) {
        while (!socket.isClosed) {
            val client = try {
                socket.accept()
            } catch (_: Exception) {
                break
            }
            if (!slots.tryAcquire()) {
                runCatching {
                    client.use { writeReply(it.getOutputStream(), Reply.Refused("PGPony is busy with another signing request")) }
                }
                continue
            }
            Thread({
                try {
                    client.use { handle(it, token, handler) }
                } catch (_: Exception) {
                    // A dropped or malformed connection ends with the connection.
                } finally {
                    slots.release()
                }
            }, "pgpony-shim-request").apply {
                isDaemon = true
                start()
            }
        }
    }

    private fun handle(client: Socket, token: String, handler: Handler) {
        client.soTimeout = REQUEST_TIMEOUT_MS
        val reply = when (val request = readRequest(BufferedInputStream(client.getInputStream()), token)) {
            is Request.Bad -> Reply.Refused(request.message)
            is Request.Sign -> handler.sign(request.fingerprint, request.payload)
        }
        writeReply(client.getOutputStream(), reply)
    }

    // ── Shim side ───────────────────────────────────────────────────────────

    /** Ask the running app to sign [payload] with [fingerprint]. */
    fun requestSignature(dataDir: Path, fingerprint: String, payload: ByteArray): Reply {
        if (payload.size > MAX_PAYLOAD) return Reply.Refused("the data to sign is too large")
        val (port, token) = readEndpoint(dataDir.resolve(FILE_NAME)) ?: return Reply.Unreachable
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), CONNECT_TIMEOUT_MS)
                s.soTimeout = REPLY_TIMEOUT_MS
                writeRequest(BufferedOutputStream(s.getOutputStream()), token, fingerprint, payload)
                readReply(BufferedInputStream(s.getInputStream()))
            }
        } catch (_: Exception) {
            Reply.Unreachable
        }
    }

    // ── Wire format (internal for tests) ────────────────────────────────────

    internal fun writeRequest(out: OutputStream, token: String, fingerprint: String, payload: ByteArray) {
        out.write("$PROTOCOL\n$token\nSIGN $fingerprint\n${payload.size}\n".toByteArray(Charsets.UTF_8))
        out.write(payload)
        out.flush()
    }

    internal fun readRequest(input: InputStream, token: String): Request {
        if (readLine(input, MAX_LINE) != PROTOCOL) return Request.Bad("unsupported request")
        val presented = readLine(input, MAX_LINE) ?: return Request.Bad("unsupported request")
        if (!MessageDigest.isEqual(presented.toByteArray(Charsets.UTF_8), token.toByteArray(Charsets.UTF_8))) {
            return Request.Bad("not authorized")
        }
        val sign = readLine(input, MAX_LINE) ?: return Request.Bad("unsupported request")
        if (!sign.startsWith("SIGN ")) return Request.Bad("unsupported request")
        val fingerprint = sign.removePrefix("SIGN ").trim()
        if (!FINGERPRINT.matches(fingerprint)) return Request.Bad("not a fingerprint")
        val length = readLine(input, MAX_LINE)?.trim()?.toIntOrNull()
            ?.takeIf { it in 0..MAX_PAYLOAD } ?: return Request.Bad("the data to sign is too large")
        val payload = input.readNBytes(length)
        if (payload.size != length) return Request.Bad("the request ended early")
        return Request.Sign(fingerprint, payload)
    }

    internal fun writeReply(out: OutputStream, reply: Reply) {
        when (reply) {
            is Reply.Signed -> {
                out.write("OK ${reply.pkAlgo} ${reply.hashAlgo} ${reply.armored.size}\n".toByteArray(Charsets.UTF_8))
                out.write(reply.armored)
            }
            is Reply.Refused -> out.write("ERR ${oneLine(reply.message)}\n".toByteArray(Charsets.UTF_8))
            Reply.Unreachable -> out.write("ERR unavailable\n".toByteArray(Charsets.UTF_8))
        }
        out.flush()
    }

    internal fun readReply(input: InputStream): Reply {
        val head = readLine(input, MAX_REPLY_LINE) ?: return Reply.Unreachable
        if (head.startsWith("ERR ")) return Reply.Refused(head.removePrefix("ERR "))
        val parts = head.split(' ')
        if (parts.size != 4 || parts[0] != "OK") return Reply.Unreachable
        val pkAlgo = parts[1].toIntOrNull() ?: return Reply.Unreachable
        val hashAlgo = parts[2].toIntOrNull() ?: return Reply.Unreachable
        val length = parts[3].toIntOrNull()?.takeIf { it in 1..MAX_SIGNATURE } ?: return Reply.Unreachable
        val body = input.readNBytes(length)
        if (body.size != length) return Reply.Unreachable
        return Reply.Signed(body, pkAlgo, hashAlgo)
    }

    /** One line without its newline, or null at the end of input or past [max] bytes. */
    internal fun readLine(input: InputStream, max: Int): String? {
        val buf = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0) return null
            if (b == '\n'.code) return buf.toString(Charsets.UTF_8)
            if (buf.size() >= max) return null
            buf.write(b)
        }
    }

    internal fun readEndpoint(file: Path): Pair<Int, String>? = runCatching {
        val parts = Files.readString(file).trim().split(' ')
        parts[0].toInt() to parts[1]
    }.getOrNull()?.takeIf { (port, token) -> port in 1..65535 && token.length == 64 }

    private fun oneLine(text: String) = text.replace('\r', ' ').replace('\n', ' ').take(MAX_REPLY_LINE - 8)

    private fun newToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /** Write [text] to [target] readable by the user only, replacing any old file whole. */
    private fun writePrivate(target: Path, text: String) {
        Files.createDirectories(target.parent)
        val tmp = target.resolveSibling("$FILE_NAME.tmp")
        Files.deleteIfExists(tmp)
        if ("posix" in FileSystems.getDefault().supportedFileAttributeViews()) {
            Files.createFile(tmp, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        } else {
            Files.createFile(tmp)
        }
        Files.writeString(tmp, text)
        try {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)
        }
    }
}

/** Signing a git payload, in the shim (no passphrase) and in the app (for ShimBridge). */
object ShimSigner {

    sealed interface Result {
        class Signed(val armored: ByteArray, val pkAlgo: Int, val hashAlgo: Int) : Result
        data object Locked : Result
        data object WrongPassphrase : Result
        class Failed(val message: String) : Result
    }

    /**
     * A detached armored signature by [key] over [payload]. Composite ML-DSA keys sign through
     * the composite signer. [Result.Locked] means the key needs a passphrase and none was given.
     */
    fun sign(repo: DesktopKeyRepository, key: PGPKeyEntity, payload: ByteArray, passphrase: String?): Result {
        val fp = key.fingerprint
        if (key.algorithm.isCompositeSign) {
            val info = try {
                repo.loadCompositeKeyInfo(fp, passphrase?.toCharArray())
            } catch (_: Exception) {
                return if (passphrase != null) Result.WrongPassphrase else Result.Failed("key $fp could not be loaded")
            } ?: return Result.Failed("key $fp could not be loaded")
            val secret = info.compositeSecret
                ?: return if (passphrase == null) Result.Locked else Result.WrongPassphrase
            val armored = com.pgpony.android.crypto.pqc.CompositeDocumentSigner
                .signDetachedArmored(info.suite, secret, info.fingerprint, payload)
                .toByteArray(Charsets.UTF_8)
            return Result.Signed(armored, info.primaryAlgId, if (info.primaryAlgId == 31) 14 else 12)
        }
        val ring = repo.loadSecretKeyRing(fp) ?: return Result.Failed("key $fp could not be loaded")
        return try {
            Result.Signed(SigningService.shared.signDetached(payload, ring, passphrase, armor = true), 22, 8)
        } catch (_: SigningError.PassphraseRequired) {
            Result.Locked
        } catch (_: SigningError.InvalidPassphrase) {
            if (passphrase == null) Result.Locked else Result.WrongPassphrase
        } catch (e: Exception) {
            Result.Failed(e.message ?: "signing failed")
        }
    }

    /**
     * The app's side of ShimBridge: sign with the remembered passphrase (SessionPolicy), else ask
     * through [prompt] up to three times and remember the one that works. Only the app's own
     * software key pairs sign, and an expired key only when Settings allows it.
     */
    fun signForShim(
        repo: DesktopKeyRepository,
        fingerprint: String,
        payload: ByteArray,
        prompt: (label: String) -> String? = { AgentPrompt.ask(it, "d_shim_unlock_message") }
    ): ShimBridge.Reply {
        val key = runBlocking { repo.byFingerprint(fingerprint) }
            ?.takeIf { it.isKeyPair && !it.isCardBacked }
            ?: return ShimBridge.Reply.Refused("no secret key $fingerprint in PGPony")
        if (!KeyUsePolicy.allowExpiredKeys() && KeyUsePolicy.isExpired(key)) {
            return ShimBridge.Reply.Refused("key $fingerprint has expired")
        }
        fun signed(r: Result.Signed) = ShimBridge.Reply.Signed(r.armored, r.pkAlgo, r.hashAlgo)

        when (val r = sign(repo, key, payload, PassphraseCache.get(fingerprint))) {
            is Result.Signed -> return signed(r)
            is Result.Failed -> return ShimBridge.Reply.Refused(r.message)
            Result.WrongPassphrase -> PassphraseCache.clear(fingerprint)
            Result.Locked -> Unit
        }
        val label = key.userEmail.ifBlank { key.userName }.ifBlank { key.shortFingerprint }
        repeat(3) {
            val pass = prompt(label) ?: return ShimBridge.Reply.Refused("the passphrase was not entered in PGPony")
            when (val r = sign(repo, key, payload, pass)) {
                is Result.Signed -> {
                    PassphraseCache.put(fingerprint, pass)
                    return signed(r)
                }
                is Result.Failed -> return ShimBridge.Reply.Refused(r.message)
                else -> Unit
            }
        }
        return ShimBridge.Reply.Refused("wrong passphrase")
    }
}
