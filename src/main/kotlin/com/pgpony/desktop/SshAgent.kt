// SshAgent.kt
// PGPony Desktop — D15 (2.0.0 §1a): the ssh-agent, impure half.
//
// SshWire.kt holds the protocol; this file holds everything that touches the world: the
// off-by-default preference, the keyring→SSH identity bridge, raw signing, the Unix-socket
// listener, the passphrase prompt bus, and the Settings section (kept here with its logic,
// the UpdateCheck.kt pattern, so SettingsScreen's edit stays one SectionCard call).
//
// WHAT THE AGENT IS NOT. It does not hold decrypted key material between requests, and SshWire
// answers FAILURE to every message that would change state. A protected key's passphrase is
// asked for once and then remembered for the session length in Settings (3.0.0 stage 4b,
// SessionPolicy), the same passphrase cache the app and git signing use; a remembered passphrase
// that no longer unlocks is dropped and the prompt comes back. The socket is 0600 in a 0700
// directory, which on a single-user machine is the same trust boundary ssh-agent lives behind.
//
// IDENTITY SOURCE (3.0.0, plan section 5, Android 4.6.0 item 16). Each key pair's newest
// DEDICATED authentication subkey, chosen by the vendored SshAuth: bound with the Authenticate
// flag, not able to sign or certify (a dual-use subkey would let ssh ask for a signature
// OpenPGP accepts), unrevoked and unexpired under a live primary. Ed25519, RSA and ECDSA on
// NIST P-256/384/521, including a classical subkey on a composite ML-DSA key (its carrier ring
// comes from CompositeKeyFacade.classicalAuthRing). Before 3.0.0 the agent served any
// Authenticate-capable key, the primary and dual-use subkeys included, Ed25519 and RSA only.
// SHA-1 ssh-rsa stays for a request with no SHA-2 flag (plan Q10), for old servers; Android
// answers the same way through SshAuth.HASH_SHA1.
//
// Card identities: LOCAL secret material only, for now.
// Card AUT slots are the plan's other half, but PSO:INTERNAL AUTHENTICATE is unimplemented in
// the vendored card session (OpenPgpCard.INS_INTERNAL_AUTHENTICATE — "deferred (auth slot)"),
// and vendored files are fixed upstream in PGPonyAndroid then re-synced, never edited here.
// The card leg therefore waits on that upstream sync; the seam is `SshAgentKeys.identities`,
// which is where card rows (hide-until-cert-imported, per the recipients-rule precedent)
// will join the list.
//
// WINDOWS ships without the agent in 2.0.0: the JDK cannot serve the named pipe OpenSSH
// expects, and the decision (D15) is a tiny native bridge exe in a later phase rather than a
// JNA dependency now. isSupported() gates every entry point, and Settings says so plainly.

package com.pgpony.desktop

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import com.pgpony.android.crypto.ssh.SshAuth
import com.pgpony.android.crypto.ssh.SshSigningKey
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.openpgp.PGPSecretKeyRing
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.channels.Channels
import java.nio.channels.ServerSocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.prefs.Preferences

// ── Preference ─────────────────────────────────────────────────────────────

object SshAgentPrefs {
    private const val KEY_ENABLED = "ssh_agent_enabled"

    /** Test hook — same pattern as DesktopNetworkPrefs. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    /** OFF by default (the update-check posture); read defensively like UpdateCheck. */
    fun enabled(): Boolean = runCatching { prefs().getBoolean(KEY_ENABLED, false) }.getOrDefault(false)

    fun setEnabled(value: Boolean) {
        runCatching { prefs().putBoolean(KEY_ENABLED, value) }
    }
}

// ── Keyring → SSH identities ───────────────────────────────────────────────

/** One servable key: the wire identity plus what's needed to find its secret half again. */
class AgentKey(
    val identity: SshIdentity,
    val primaryFingerprint: String,
    val keyId: Long,
    val material: SshAuth.Material
)

object SshAgentKeys {

    // OpenPGP public-key algorithm ids (RFC 4880 §9.1 / RFC 9580). Named locally rather than
    // through BC's PublicKeyAlgorithmTags so the mapping this file actually serves is in one
    // place a reviewer can check against the spec.
    private const val ALGO_RSA_GENERAL = 1
    private const val ALGO_RSA_ENCRYPT = 2
    private const val ALGO_RSA_SIGN = 3
    private const val ALGO_EDDSA_LEGACY = 22   // v4 Ed25519
    private const val ALGO_ED25519_V6 = 27     // RFC 9580

    /**
     * The authentication-capable identities the keyring holds right now. Re-enumerated per
     * REQUEST_IDENTITIES — key imports and deletions show up without touching the toggle.
     * Never throws: an unreadable ring is a missing identity, not a dead agent.
     */
    fun identities(repo: DesktopKeyRepository): List<AgentKey> = try {
        val out = ArrayList<AgentKey>()
        val entities = runBlocking { repo.allKeys() }.filter { it.isKeyPair && !it.isRevoked && !it.isCardBacked }
        for (entity in entities) {
            val identity = runCatching { identityFor(repo, entity) }.getOrNull() ?: continue
            out += identity
        }
        out
    } catch (_: Exception) {
        emptyList()
    }

    /** The one identity [entity] serves: its newest dedicated authentication subkey (SshAuth). */
    internal fun identityFor(repo: DesktopKeyRepository, entity: PGPKeyEntity): AgentKey? {
        val cert = runBlocking { repo.rawPublicBytes(entity.fingerprint) } ?: return null
        val sub = SshAuth.authSubkey(cert) ?: return null
        val m = SshAuth.material(sub.publicBody) ?: return null
        return AgentKey(SshIdentity(SshAuth.publicBlob(m), commentFor(entity)), entity.fingerprint, sub.keyId, m)
    }

    /** SSH public blob for a PGP key, or null when SSH has no name for it (Ed448, PQC, EC). */
    internal fun publicBlob(pub: PGPPublicKey): ByteArray? = try {
        when (pub.algorithm) {
            ALGO_EDDSA_LEGACY, ALGO_ED25519_V6 -> {
                val params = BcPGPKeyConverter().getPublicKey(pub) as? Ed25519PublicKeyParameters
                params?.let { SshWire.ed25519PublicBlob(it.encoded) }
            }
            ALGO_RSA_GENERAL, ALGO_RSA_ENCRYPT, ALGO_RSA_SIGN -> {
                val params = BcPGPKeyConverter().getPublicKey(pub) as? RSAKeyParameters
                params?.let { SshWire.rsaPublicBlob(it.exponent, it.modulus) }
            }
            else -> null
        }
    } catch (_: Exception) {
        null
    }

    /** The `ssh-add -L` comment: who this is, and that PGPony is serving it. */
    internal fun commentFor(entity: PGPKeyEntity): String {
        val label = sequenceOf(entity.userEmail, entity.userID, entity.fingerprint)
            .firstOrNull { it.isNotBlank() } ?: entity.fingerprint
        return "$label (PGPony)"
    }

    /**
     * Answer one SIGN_REQUEST: find the key by blob, unlock (prompting only for a protected
     * key), and produce the RAW algorithm signature — deliberately not a PGP signature; the
     * SSH wire wants bare Ed25519 / PKCS#1, and mixing the two containers is how a signing
     * oracle grows. Null for every refusal; SshWire turns that into SSH_AGENT_FAILURE.
     */
    fun sign(repo: DesktopKeyRepository, keyBlob: ByteArray, data: ByteArray, flags: Int): ByteArray? {
        val match = identities(repo).firstOrNull { it.identity.blob.contentEquals(keyBlob) } ?: return null
        val ring = repo.loadSshAuthSecretRing(match.primaryFingerprint) ?: return null
        val key = unlock(ring, match.keyId, match.identity.comment, match.primaryFingerprint) ?: return null
        // The flags choose the RSA signature algorithm; with none, SHA-1 "ssh-rsa" (plan Q10).
        val hash = when {
            flags and SshWire.SSH_AGENT_RSA_SHA2_512 != 0 -> SshAuth.HASH_SHA512
            flags and SshWire.SSH_AGENT_RSA_SHA2_256 != 0 -> SshAuth.HASH_SHA256
            else -> SshAuth.HASH_SHA1
        }
        return try {
            SshAuth.sign(match.material, key, data, hash)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Try without a passphrase first (PGPony's generated keys may have none), then the key's
     * remembered passphrase (SessionPolicy), then prompt through [AgentPrompt] up to three times
     * for a protected subkey, remembering the one that works. A missing or stub secret subkey is
     * a refusal, not a prompt.
     */
    private fun unlock(ring: PGPSecretKeyRing, keyId: Long, label: String, fingerprint: String): AsymmetricKeyParameter? {
        when (val first = SshSigningKey.unlock(ring, keyId, null)) {
            is SshSigningKey.Unlock.Ok -> return first.key
            is SshSigningKey.Unlock.Missing -> return null
            else -> Unit
        }
        PassphraseCache.get(fingerprint)?.let { remembered ->
            when (val u = SshSigningKey.unlock(ring, keyId, remembered)) {
                is SshSigningKey.Unlock.Ok -> return u.key
                is SshSigningKey.Unlock.Missing -> return null
                else -> PassphraseCache.clear(fingerprint)
            }
        }
        repeat(3) {
            val pass = AgentPrompt.ask(label) ?: return null // cancelled or timed out
            when (val u = SshSigningKey.unlock(ring, keyId, pass)) {
                is SshSigningKey.Unlock.Ok -> {
                    PassphraseCache.put(fingerprint, pass)
                    return u.key
                }
                is SshSigningKey.Unlock.Missing -> return null
                else -> Unit
            }
        }
        return null
    }
}

// ── The passphrase prompt bus ──────────────────────────────────────────────
//
// The agent thread cannot compose UI; the TrayNav idiom bridges it: a @Volatile request the
// window polls, rendered as a dialog, completed back through a latch the agent thread waits
// on. One request at a time — a second concurrent sign against a locked key fails rather than
// queueing prompts the user never asked for.

class AgentUnlockRequest(val keyLabel: String, val messageKey: String = "d_agent_unlock_message") {
    private val latch = CountDownLatch(1)
    @Volatile private var passphrase: String? = null

    /** Called from the UI. Null means the user cancelled. */
    fun complete(value: String?) {
        passphrase = value
        latch.countDown()
    }

    internal fun await(timeoutMs: Long): String? =
        if (latch.await(timeoutMs, TimeUnit.MILLISECONDS)) passphrase else null
}

object AgentPrompt {
    /** The window's poll target (Gui.kt drain loop). */
    @Volatile var request: AgentUnlockRequest? = null
        private set

    private const val TIMEOUT_MS = 60_000L

    /**
     * Agent-thread side: raise the window, wait for an answer or the timeout. [messageKey] says
     * who is asking (the ssh agent, or git through ShimBridge).
     */
    fun ask(keyLabel: String, messageKey: String = "d_agent_unlock_message"): String? {
        val req = AgentUnlockRequest(keyLabel, messageKey)
        synchronized(this) {
            if (request != null) return null // one prompt at a time
            request = req
        }
        AppOpen.focusWindow?.invoke()
        return try {
            req.await(TIMEOUT_MS)
        } finally {
            synchronized(this) { if (request === req) request = null }
        }
    }
}

// ── The listener ───────────────────────────────────────────────────────────

object SshAgentService {

    @Volatile private var channel: ServerSocketChannel? = null
    @Volatile private var repository: DesktopKeyRepository? = null

    /** Last start failure, for the Settings section; null when running or never started. */
    @Volatile var lastError: String? = null
        private set

    private var hookAdded = false

    /** The JDK cannot serve Windows named pipes; 2.0.0 ships the agent on macOS/Linux only. */
    fun isSupported(): Boolean =
        !System.getProperty("os.name").lowercase().contains("win")

    val socketPath: Path get() = Config.agentDir.resolve("agent.sock")

    /** What the user pastes: a line their shell understands today, not a doc reference. */
    fun exportLine(): String = "export SSH_AUTH_SOCK=\"$socketPath\""

    fun isRunning(): Boolean = channel != null

    @Synchronized
    fun start(repo: DesktopKeyRepository) {
        if (!isSupported() || channel != null) return
        lastError = null
        try {
            Files.createDirectories(Config.agentDir)
            restrictToOwner(Config.agentDir, directory = true)
            Files.deleteIfExists(socketPath) // a stale socket from a killed process
            val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
            server.bind(UnixDomainSocketAddress.of(socketPath))
            restrictToOwner(socketPath)
            channel = server
            repository = repo
            if (!hookAdded) {
                hookAdded = true
                Runtime.getRuntime().addShutdownHook(Thread {
                    runCatching { Files.deleteIfExists(socketPath) }
                })
            }
            val t = Thread { serve(server) }
            t.isDaemon = true
            t.name = "pgpony-ssh-agent"
            t.start()
        } catch (e: Exception) {
            lastError = e.message ?: e.javaClass.simpleName
            runCatching { channel?.close() }
            channel = null
        }
    }

    @Synchronized
    fun stop() {
        runCatching { channel?.close() }
        channel = null
        repository = null
        runCatching { Files.deleteIfExists(socketPath) }
    }

    /**
     * Accept loop. 3.0.0 (4d): each client gets its own thread, up to [MAX_CLIENTS] at once, so
     * one that connects and never speaks (or waits on a passphrase prompt) does not stall every
     * other ssh on the machine; a client past the cap is closed at once. Prompts stay one at a
     * time (AgentPrompt).
     */
    private fun serve(server: ServerSocketChannel) {
        val slots = java.util.concurrent.Semaphore(MAX_CLIENTS)
        while (server.isOpen) {
            val client = try {
                server.accept()
            } catch (_: Exception) {
                break // closed by stop(); the thread ends with the socket
            }
            if (!slots.tryAcquire()) {
                runCatching { client.close() }
                continue
            }
            Thread({
                try {
                    runCatching { serveClient(client) }
                } finally {
                    slots.release()
                }
            }, "pgpony-ssh-agent-client").apply {
                isDaemon = true
                start()
            }
        }
    }

    private fun serveClient(client: java.nio.channels.SocketChannel) {
        client.use { c ->
            val input = Channels.newInputStream(c)
            val output = Channels.newOutputStream(c)
            while (true) {
                val payload = SshWire.readFrame(input) ?: break
                val repo = repository ?: break
                val response = SshWire.handleRequest(
                    payload,
                    identities = { SshAgentKeys.identities(repo).map { it.identity } },
                    sign = { blob, data, flags -> SshAgentKeys.sign(repo, blob, data, flags) }
                )
                SshWire.writeFrame(output, response)
            }
        }
    }

    private const val MAX_CLIENTS = 8

    /** KeyMaterialStore's owner-only helper, repeated for the socket (theirs is private). */
    private fun restrictToOwner(path: Path, directory: Boolean = false) {
        runCatching {
            val perms = if (directory) "rwx------" else "rw-------"
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(perms))
        }
    }
}

// ── Settings UI ────────────────────────────────────────────────────────────
//
// Lives here rather than in SettingsScreen.kt so the screen's edit stays a single SectionCard
// call — same-package, so no import is needed there (the UpdateCheck.kt pattern).

@Composable
fun SshAgentSection(state: DesktopState) {
    if (!SshAgentService.isSupported()) {
        Text(
            tr("d_settings_ssh_agent_windows"),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        return
    }

    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(
            checked = state.sshAgentEnabled,
            onCheckedChange = { state.enableSshAgent(it) }
        )
        Spacer(Modifier.width(Spacing.Small))
        Text(tr("d_settings_ssh_agent_enable"), style = MaterialTheme.typography.bodyMedium)
    }

    Spacer(Modifier.height(Spacing.Small))
    Text(
        tr("d_settings_ssh_agent_keys_note"),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )

    SshAgentService.lastError?.let { error ->
        Spacer(Modifier.height(Spacing.Small))
        Text(
            tr("d_settings_ssh_agent_error", error),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error
        )
    }

    if (state.sshAgentEnabled && SshAgentService.isRunning()) {
        Spacer(Modifier.height(Spacing.Medium))
        LabeledValue(
            label = tr("d_settings_ssh_agent_socket"),
            value = SshAgentService.exportLine(),
            monospace = true
        ) {
            TextButton(onClick = {
                DesktopClipboard.copy(SshAgentService.exportLine(), secret = false)
                state.status = tr("d_status_copied")
            }) {
                Text(tr("d_settings_ssh_agent_copy"))
            }
        }
    }
}

/** The passphrase dialog the Gui renders when the agent needs a protected key unlocked. */
@Composable
fun AgentUnlockDialog(request: AgentUnlockRequest, onDone: () -> Unit) {
    var passphrase by remember(request) { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = { request.complete(null); onDone() },
        title = { Text(tr("d_agent_unlock_title")) },
        text = {
            androidx.compose.foundation.layout.Column {
                Text(tr(request.messageKey, request.keyLabel))
                Spacer(Modifier.height(Spacing.Medium))
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text(tr("d_agent_unlock_field")) },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { request.complete(passphrase); onDone() }) {
                Text(tr("d_agent_unlock_confirm"))
            }
        },
        dismissButton = {
            TextButton(onClick = { request.complete(null); onDone() }) {
                Text(tr("d_agent_unlock_cancel"))
            }
        }
    )
}
