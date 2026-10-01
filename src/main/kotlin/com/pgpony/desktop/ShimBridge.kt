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
//
// 3.0.0 (hardening): the bridge is opt-in (Settings, Git signing; GitSigningPrefs), off by
// default like the SSH agent. It signs only git commits, tags and push certificates
// (GitPayload), uses a remembered passphrase only when it was entered to sign (a decrypt or ssh
// unlock alone never lets git sign silently), and posts a notification naming what it signed for
// every signature. A connection gets a short deadline to prove the token, from its own pool,
// and takes one of the two request slots only after it has; a peer that connects and says
// nothing cannot hold the signing slots.

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
import java.util.prefs.Preferences

object ShimBridge {

    internal const val FILE_NAME = ".shim-bridge"
    private const val PROTOCOL = "PGPONY-SHIM 2"
    internal const val MAX_PAYLOAD = 16 * 1024 * 1024
    private const val MAX_SIGNATURE = 1024 * 1024
    private const val MAX_LINE = 256
    private const val MAX_REPLY_LINE = 4096
    private const val MAX_CLIENTS = 2
    private const val CONNECT_TIMEOUT_MS = 2_000

    // Connections still proving the token. A connection that has not proved it within
    // PREAUTH_TIMEOUT_MS is dropped; one past the pool is closed at once.
    private const val MAX_PREAUTH = 32
    private const val PREAUTH_TIMEOUT_MS = 2_000L

    // After the handshake, the request and payload arrive within this or the connection ends.
    private const val REQUEST_TIMEOUT_MS = 10_000L

    // The shim tries a busy or unanswering bridge this many times before giving up.
    private const val CLIENT_ATTEMPTS = 5
    private const val CLIENT_RETRY_MS = 400L

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
    private var endpointToken: String? = null
    private var hooked = false

    // What start() was given, so the Settings switch can start and stop the bridge later.
    private var configuredDir: Path? = null
    private var configuredHandler: Handler? = null

    // ── App side ────────────────────────────────────────────────────────────

    /**
     * Register the app's signer and start serving when git signing is turned on in Settings
     * (GitSigningPrefs). True when listening. With the setting off nothing listens until
     * [setEnabled] turns it on.
     */
    fun start(dataDir: Path, handler: Handler): Boolean {
        synchronized(lock) {
            configuredDir = dataDir
            configuredHandler = handler
            if (server != null) return true
            if (!GitSigningPrefs.enabled()) return false
            return startLocked(dataDir, handler)
        }
    }

    /** The Settings switch: remember the choice, then start or stop serving. True when listening. */
    fun setEnabled(enabled: Boolean): Boolean {
        GitSigningPrefs.setEnabled(enabled)
        synchronized(lock) {
            if (!enabled) {
                stopLocked()
                return false
            }
            if (server != null) return true
            val dir = configuredDir ?: return false
            val handler = configuredHandler ?: return false
            return startLocked(dir, handler)
        }
    }

    fun isRunning(): Boolean = synchronized(lock) { server != null }

    private fun startLocked(dataDir: Path, handler: Handler): Boolean =
        try {
            val socket = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
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
            endpointToken = token
            if (!hooked) {
                hooked = true
                Runtime.getRuntime().addShutdownHook(Thread { stop() })
            }
            val slots = Semaphore(MAX_CLIENTS)
            val preauth = Semaphore(MAX_PREAUTH)
            Thread({ serve(socket, token, handler, slots, preauth) }, "pgpony-shim-bridge").apply {
                isDaemon = true
                start()
            }
            true
        } catch (_: Exception) {
            false
        }

    fun stop() {
        synchronized(lock) { stopLocked() }
    }

    private fun stopLocked() {
        runCatching { server?.close() }
        // The endpoint file goes only while it is still this process's: another PGPony that
        // wrote its own since then keeps its endpoint.
        val file = endpointFile
        val token = endpointToken
        if (file != null && token != null) {
            runCatching {
                if (readEndpoint(file)?.second == token) Files.deleteIfExists(file)
            }
        }
        server = null
        endpointFile = null
        endpointToken = null
    }

    private fun serve(socket: ServerSocket, token: String, handler: Handler, slots: Semaphore, preauth: Semaphore) {
        while (!socket.isClosed) {
            val client = try {
                socket.accept()
            } catch (_: Exception) {
                break
            }
            if (!preauth.tryAcquire()) {
                // Too many connections that have not proved the token: drop this one unread.
                runCatching { client.close() }
                continue
            }
            Thread({
                try {
                    client.use { handle(it, token, handler, slots, preauth) }
                } catch (_: Exception) {
                    // A dropped or malformed connection ends with the connection.
                } finally {
                    preauth.release()
                }
            }, "pgpony-shim-request").apply {
                isDaemon = true
                start()
            }
        }
    }

    /**
     * One connection: the handshake under the short pre-auth deadline, holding a pre-auth
     * permit ([preauth], released by the caller); then a request slot from [slots], only once the
     * peer has proved the token.
     */
    private fun handle(client: Socket, token: String, handler: Handler, slots: Semaphore, preauth: Semaphore) {
        client.soTimeout = PREAUTH_TIMEOUT_MS.toInt()
        val raw = BufferedInputStream(client.getInputStream())
        val out = client.getOutputStream()
        serverHandshake(DeadlineInputStream(raw, PREAUTH_TIMEOUT_MS), out, token)?.let { bad ->
            writeReply(out, Reply.Refused(bad.message))
            return
        }
        if (!slots.tryAcquire()) {
            writeReply(out, Reply.Refused("PGPony is busy with another signing request"))
            return
        }
        try {
            client.soTimeout = REQUEST_TIMEOUT_MS.toInt()
            val reply = when (val request = readSign(DeadlineInputStream(raw, REQUEST_TIMEOUT_MS))) {
                is Request.Bad -> Reply.Refused(request.message)
                is Request.Sign -> handler.sign(request.fingerprint, request.payload)
            }
            writeReply(out, reply)
        } finally {
            slots.release()
        }
    }

    /**
     * The app's side of the handshake. The shim sends a nonce; the app answers with its own
     * nonce and a proof over the shim's (HMAC under the token), so the shim knows it is talking
     * to the app before it sends anything; the shim then proves itself over the app's nonce.
     * The token itself never crosses the socket. Null when the peer proved the token.
     */
    internal fun serverHandshake(input: InputStream, out: OutputStream, token: String): Request.Bad? {
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
        return null
    }

    /** The handshake and then the request, on one stream (tests). */
    internal fun serverExchange(input: InputStream, out: OutputStream, token: String): Request =
        serverHandshake(input, out, token) ?: readSign(input)

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
        val endpoint = dataDir.resolve(FILE_NAME)
        var last: Reply = Reply.Unreachable
        // A bridge that is busy or did not answer the handshake (its pre-auth pool full, say)
        // gets a few tries. A refusal after the handshake is the app's answer and is final.
        for (attempt in 1..CLIENT_ATTEMPTS) {
            val (port, token) = readEndpoint(endpoint) ?: return Reply.Unreachable
            val (reply, sent) = attemptOnce(port, token, fingerprint, payload)
            last = reply
            // Once the request went out, the app may already be asking for the passphrase or
            // have signed: never send it a second time.
            val retry = !sent && (reply == Reply.Unreachable) ||
                (reply is Reply.Refused && reply.message.contains("busy"))
            if (!retry || attempt == CLIENT_ATTEMPTS) break
            try {
                Thread.sleep(CLIENT_RETRY_MS * attempt)
            } catch (_: InterruptedException) {
                break
            }
        }
        return last
    }

    /** One connection: the reply, and whether the request itself was sent. */
    private fun attemptOnce(port: Int, token: String, fingerprint: String, payload: ByteArray): Pair<Reply, Boolean> {
        var sent = false
        val reply = try {
            Socket().use { s ->
                s.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), CONNECT_TIMEOUT_MS)
                s.soTimeout = REQUEST_TIMEOUT_MS.toInt()
                clientExchange(
                    BufferedInputStream(s.getInputStream()), BufferedOutputStream(s.getOutputStream()),
                    token, fingerprint, payload
                ) {
                    sent = true
                    s.soTimeout = REPLY_TIMEOUT_MS
                }
            }
        } catch (_: Exception) {
            Reply.Unreachable
        }
        return reply to sent
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
     *
     * Only a git commit, tag or push certificate is signed (GitPayload). A remembered passphrase
     * is used only when it was entered to sign (PassphraseCache.getForSigning); one entered to
     * decrypt or for ssh asks again. Every signature made here is announced through [notify].
     */
    fun signForShim(
        repo: DesktopKeyRepository,
        fingerprint: String,
        payload: ByteArray,
        notify: (String) -> Unit = ::announce,
        prompt: (label: String) -> String? = { AgentPrompt.ask(it, "d_shim_unlock_object") }
    ): ShimBridge.Reply {
        val what = GitPayload.describe(payload)
            ?: return ShimBridge.Reply.Refused("PGPony signs only git commits, tags and push certificates for pgpony-gpg")
        val key = runBlocking { repo.byFingerprint(fingerprint) }
            ?.takeIf { it.isKeyPair && !it.isCardBacked }
            ?: return ShimBridge.Reply.Refused("no secret key $fingerprint in PGPony")
        if (!KeyUsePolicy.allowExpiredKeys() && KeyUsePolicy.isExpired(key)) {
            return ShimBridge.Reply.Refused("key $fingerprint has expired")
        }
        val label = key.userEmail.ifBlank { key.userName }.ifBlank { key.shortFingerprint }
        val described = tr("d_shim_what", what, label)
        fun signed(r: Result.Signed): ShimBridge.Reply.Signed {
            runCatching { notify(described) }
            return ShimBridge.Reply.Signed(r.armored, r.pkAlgo, r.hashAlgo)
        }

        when (val r = sign(repo, key, payload, PassphraseCache.getForSigning(fingerprint))) {
            is Result.Signed -> return signed(r)
            is Result.Failed -> return ShimBridge.Reply.Refused(r.message)
            Result.WrongPassphrase -> PassphraseCache.clear(fingerprint)
            Result.Locked -> Unit
        }
        repeat(3) {
            val pass = prompt(described) ?: return ShimBridge.Reply.Refused("the passphrase was not entered in PGPony")
            when (val r = sign(repo, key, payload, pass)) {
                is Result.Signed -> {
                    PassphraseCache.put(fingerprint, pass, forSigning = true)
                    return signed(r)
                }
                is Result.Failed -> return ShimBridge.Reply.Refused(r.message)
                else -> Unit
            }
        }
        return ShimBridge.Reply.Refused("wrong passphrase")
    }

    /** The tray notification for a signature the bridge made. */
    private fun announce(described: String) {
        TrayOutbox.post(TrayOutbox.Msg(tr("d_shim_signed_title"), tr("d_shim_signed_body", described), warn = false))
    }
}

/** The Settings switch for git signing through the running app (ShimBridge). Off by default. */
object GitSigningPrefs {
    private const val KEY_ENABLED = "git_signing_bridge_enabled"

    /** Test hook, the SshAgentPrefs pattern. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun enabled(): Boolean = runCatching { prefs().getBoolean(KEY_ENABLED, false) }.getOrDefault(false)

    fun setEnabled(value: Boolean) {
        runCatching { prefs().putBoolean(KEY_ENABLED, value) }
    }
}

/**
 * What git asks pgpony-gpg to sign: a commit object, a tag object or a push certificate. The
 * bridge signs nothing else, so a process that can reach it cannot get a signature over a
 * release file, a mail or any other document.
 */
object GitPayload {

    private val OID = Regex("[0-9a-f]{40}|[0-9a-f]{64}")
    private const val MAX_SUBJECT = 80

    enum class Kind { COMMIT, TAG, PUSH_CERTIFICATE }

    /** A recognised git object: its kind and its subject line or tag name. */
    data class Parsed(val kind: Kind, val name: String)

    /** A short description ("the commit \"subject\"", "the tag v1.0"), or null when not git. */
    fun describe(payload: ByteArray): String? {
        val p = parse(payload) ?: return null
        return when (p.kind) {
            Kind.COMMIT -> tr("d_shim_object_commit", p.name)
            Kind.TAG -> tr("d_shim_object_tag", p.name)
            Kind.PUSH_CERTIFICATE -> tr("d_shim_object_push")
        }
    }

    /** [payload] as a git commit, tag or push certificate, or null. */
    fun parse(payload: ByteArray): Parsed? {
        // Decoded leniently: a commit made with i18n.commitEncoding (an "encoding" header) carries
        // a message that is not UTF-8. The structure below decides what the payload is.
        val text = String(payload, Charsets.UTF_8)
        val blank = text.indexOf("\n\n")
        val headerText = if (blank < 0) text else text.substring(0, blank)
        val body = if (blank < 0) "" else text.substring(blank + 2)
        // Header lines; a line starting with a space continues the one before (mergetag).
        val headers = headerText.split('\n').filter { it.isNotEmpty() && !it.startsWith(" ") }
        if (headers.isEmpty()) return null
        fun field(name: String) = headers.firstOrNull { it.startsWith("$name ") }?.removePrefix("$name ")
        val first = headers.first()
        return when {
            first.startsWith("tree ") -> {
                if (!OID.matches(first.removePrefix("tree "))) return null
                if (field("author") == null || field("committer") == null) return null
                if (headers.drop(1).any { h -> h.startsWith("parent ") && !OID.matches(h.removePrefix("parent ")) }) return null
                Parsed(Kind.COMMIT, subject(body))
            }
            first.startsWith("object ") -> {
                if (!OID.matches(first.removePrefix("object "))) return null
                val type = field("type") ?: return null
                val tag = field("tag") ?: return null
                if (type !in setOf("commit", "tree", "blob", "tag")) return null
                Parsed(Kind.TAG, clean(tag))
            }
            first == "certificate version 0.1" -> {
                if (field("pusher") == null) return null
                Parsed(Kind.PUSH_CERTIFICATE, "")
            }
            else -> null
        }
    }

    private fun subject(body: String): String =
        clean(body.lineSequence().firstOrNull { it.isNotBlank() }.orEmpty())

    /** One line, control characters dropped, bounded. */
    private fun clean(s: String): String {
        val one = s.filter { it >= ' ' && it != '\u007F' }.trim()
        return if (one.length > MAX_SUBJECT) one.take(MAX_SUBJECT - 3) + "..." else one
    }
}
