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
// dataDir/.shim-bridge, readable by the user only (OwnerOnlyFile). The token is 32 random
// bytes, new each launch. Both sides prove they hold it before anything is signed or sent
// (4d): an HMAC handshake over fresh nonces, so the token never crosses the socket, another
// account on the machine cannot ask for a signature, and a port left behind by a crashed app
// cannot collect a commit. Then "SIGN <fingerprint>", the payload length and the payload; the
// reply is "OK <pk algo> <hash algo> <length>" and the armored signature, or "ERR <message>".
// Only signing is served, two requests at a time, sizes bounded, the request under one
// deadline.

package com.pgpony.desktop

import com.pgpony.android.crypto.SigningError
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Semaphore

object ShimBridge {

    internal const val FILE_NAME = ".shim-bridge"
    private const val PROTOCOL = "PGPONY-SHIM 2"
    internal const val MAX_PAYLOAD = 16 * 1024 * 1024
    private const val MAX_SIGNATURE = 1024 * 1024
    private const val MAX_LINE = 256
    private const val MAX_REPLY_LINE = 4096
    private const val MAX_CLIENTS = 2
    private const val CONNECT_TIMEOUT_MS = 2_000

    // The whole request, handshake and payload, arrives within this or the connection ends.
    private const val REQUEST_TIMEOUT_MS = 10_000L

    // Three passphrase prompts of 60 seconds each, and some room.
    private const val REPLY_TIMEOUT_MS = 200_000

    private val FINGERPRINT = Regex("[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}")
    private val NONCE = Regex("[0-9a-f]{64}")

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
            val token = LocalSecret.newToken()
            val file = dataDir.resolve(FILE_NAME)
            try {
                OwnerOnlyFile.write(file, "${socket.localPort} $token\n")
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
        client.soTimeout = REQUEST_TIMEOUT_MS.toInt()
        val input = DeadlineInputStream(BufferedInputStream(client.getInputStream()), REQUEST_TIMEOUT_MS)
        val out = client.getOutputStream()
        val reply = when (val request = serverExchange(input, out, token)) {
            is Request.Bad -> Reply.Refused(request.message)
            is Request.Sign -> handler.sign(request.fingerprint, request.payload)
        }
        writeReply(out, reply)
    }

    /**
     * The app's side of the handshake. The shim sends a nonce; the app answers with its own
     * nonce and a proof over the shim's (HMAC under the token), so the shim knows it is talking
     * to the app before it sends anything; the shim then proves itself over the app's nonce.
     * The token itself never crosses the socket.
     */
    internal fun serverExchange(input: InputStream, out: OutputStream, token: String): Request {
        if (readBoundedLine(input, MAX_LINE) != PROTOCOL) return Request.Bad("unsupported request")
        val clientNonce = readBoundedLine(input, MAX_LINE)?.takeIf { NONCE.matches(it) }
            ?: return Request.Bad("unsupported request")
        val serverNonce = LocalSecret.newToken()
        out.write("HELLO $serverNonce ${LocalSecret.proof(token, "server", clientNonce)}\n".toByteArray(Charsets.UTF_8))
        out.flush()
        val proof = readBoundedLine(input, MAX_LINE)
        if (!LocalSecret.sameText(proof, LocalSecret.proof(token, "client", serverNonce))) {
            return Request.Bad("not authorized")
        }
        return readSign(input)
    }

    /** After the handshake: "SIGN <fingerprint>", the payload length, then the payload. */
    internal fun readSign(input: InputStream): Request {
        val sign = readBoundedLine(input, MAX_LINE) ?: return Request.Bad("unsupported request")
        if (!sign.startsWith("SIGN ")) return Request.Bad("unsupported request")
        val fingerprint = sign.removePrefix("SIGN ").trim()
        if (!FINGERPRINT.matches(fingerprint)) return Request.Bad("not a fingerprint")
        val length = readBoundedLine(input, MAX_LINE)?.trim()?.toIntOrNull()
            ?.takeIf { it in 0..MAX_PAYLOAD } ?: return Request.Bad("the data to sign is too large")
        val payload = input.readNBytes(length)
        if (payload.size != length) return Request.Bad("the request ended early")
        return Request.Sign(fingerprint, payload)
    }

    // ── Shim side ───────────────────────────────────────────────────────────

    /** Ask the running app to sign [payload] with [fingerprint]. */
    fun requestSignature(dataDir: Path, fingerprint: String, payload: ByteArray): Reply {
        if (payload.size > MAX_PAYLOAD) return Reply.Refused("the data to sign is too large")
        val (port, token) = readEndpoint(dataDir.resolve(FILE_NAME)) ?: return Reply.Unreachable
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), CONNECT_TIMEOUT_MS)
                s.soTimeout = REQUEST_TIMEOUT_MS.toInt()
                clientExchange(
                    BufferedInputStream(s.getInputStream()), BufferedOutputStream(s.getOutputStream()),
                    token, fingerprint, payload
                ) { s.soTimeout = REPLY_TIMEOUT_MS }
            }
        } catch (_: Exception) {
            Reply.Unreachable
        }
    }

    /**
     * The shim's side. Nothing about the commit leaves until the listener has proved it holds
     * the token: a port left behind by a crashed app and taken by another account's process
     * gets a nonce and nothing else. [awaitingReply] runs once the request is sent.
     */
    internal fun clientExchange(
        input: InputStream,
        out: OutputStream,
        token: String,
        fingerprint: String,
        payload: ByteArray,
        awaitingReply: () -> Unit = {}
    ): Reply {
        val clientNonce = LocalSecret.newToken()
        out.write("$PROTOCOL\n$clientNonce\n".toByteArray(Charsets.UTF_8))
        out.flush()
        val hello = readBoundedLine(input, MAX_REPLY_LINE)?.split(' ') ?: return Reply.Unreachable
        if (hello.size != 3 || hello[0] != "HELLO" || !NONCE.matches(hello[1]) ||
            !LocalSecret.sameText(hello[2], LocalSecret.proof(token, "server", clientNonce))
        ) {
            return Reply.Unreachable
        }
        out.write("${LocalSecret.proof(token, "client", hello[1])}\nSIGN $fingerprint\n${payload.size}\n".toByteArray(Charsets.UTF_8))
        out.write(payload)
        out.flush()
        awaitingReply()
        return readReply(input)
    }

    // ── Replies (internal for tests) ────────────────────────────────────────

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
        val head = readBoundedLine(input, MAX_REPLY_LINE) ?: return Reply.Unreachable
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

    internal fun readEndpoint(file: Path): Pair<Int, String>? = runCatching {
        val parts = Files.readString(file).trim().split(' ')
        parts[0].toInt() to parts[1]
    }.getOrNull()?.takeIf { (port, token) -> port in 1..65535 && token.length == 64 }

    private fun oneLine(text: String) =
        text.filter { it >= ' ' && it != '\u007F' }.take(MAX_REPLY_LINE - 8)
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
