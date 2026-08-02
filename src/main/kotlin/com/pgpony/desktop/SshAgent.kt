// SshAgent.kt
// PGPony Desktop — D15 (2.0.0 §1a): the ssh-agent, impure half.
//
// SshWire.kt holds the protocol; this file holds everything that touches the world: the
// off-by-default preference, the keyring→SSH identity bridge, raw signing, the Unix-socket
// listener, the passphrase prompt bus, and the Settings section (kept here with its logic,
// the UpdateCheck.kt pattern, so SettingsScreen's edit stays one SectionCard call).
//
// WHAT THE AGENT IS NOT. It does not hold decrypted key material between requests, does not
// cache passphrases (each protected-key signature prompts; PGPony's own keys are typically
// passphrase-less and sign without one), and does not speak any message that mutates state —
// SshWire answers FAILURE to all of those. The socket is 0600 in a 0700 directory, which on
// a single-user machine is the same trust boundary ssh-agent itself lives behind.
//
// IDENTITY SOURCE. Authentication-capable subkeys with LOCAL secret material only, for now.
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
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.SubkeyCapability
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.RSADigestSigner
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
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
    val keyId: Long
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

    private val crypto get() = PGPCryptoService.shared

    /**
     * The authentication-capable identities the keyring holds right now. Re-enumerated per
     * REQUEST_IDENTITIES — key imports and deletions show up without touching the toggle.
     * Never throws: an unreadable ring is a missing identity, not a dead agent.
     */
    fun identities(repo: DesktopKeyRepository): List<AgentKey> = try {
        val out = ArrayList<AgentKey>()
        val entities = runBlocking { repo.allKeys() }.filter { it.isKeyPair && !it.isRevoked }
        for (entity in entities) {
            val ring = repo.loadSecretKeyRing(entity.fingerprint) ?: continue
            val iterator = ring.secretKeys
            while (iterator.hasNext()) {
                val secretKey = iterator.next()
                val pub = secretKey.publicKey
                val caps = SubkeyCapability.fromPgpPublicKey(
                    pub, crypto.detectAlgorithm(pub), pub.isMasterKey
                )
                if (!SubkeyCapability.hasCapability(caps, SubkeyCapability.Authenticate)) continue
                val blob = publicBlob(pub) ?: continue
                out += AgentKey(SshIdentity(blob, commentFor(entity)), entity.fingerprint, pub.keyID)
            }
        }
        out
    } catch (_: Exception) {
        emptyList()
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
        val ring = repo.loadSecretKeyRing(match.primaryFingerprint) ?: return null
        val secretKey = ring.getSecretKey(match.keyId) ?: return null
        val priv = unlock(secretKey, match.identity.comment) ?: return null
        val params = try {
            BcPGPKeyConverter().getPrivateKey(priv)
        } catch (_: Exception) {
            return null
        }
        return try {
            when (params) {
                is Ed25519PrivateKeyParameters -> {
                    val signer = Ed25519Signer()
                    signer.init(true, params)
                    signer.update(data, 0, data.size)
                    SshWire.signatureBlob("ssh-ed25519", signer.generateSignature())
                }
                is RSAPrivateCrtKeyParameters -> {
                    // The flags choose the RSA signature algorithm; SHA-1 "ssh-rsa" survives
                    // only as the spec's flagless default, which modern OpenSSH never sends.
                    val (name, digest) = when {
                        flags and SshWire.SSH_AGENT_RSA_SHA2_512 != 0 -> "rsa-sha2-512" to SHA512Digest()
                        flags and SshWire.SSH_AGENT_RSA_SHA2_256 != 0 -> "rsa-sha2-256" to SHA256Digest()
                        else -> "ssh-rsa" to SHA1Digest()
                    }
                    val signer = RSADigestSigner(digest)
                    signer.init(true, params)
                    signer.update(data, 0, data.size)
                    SshWire.signatureBlob(name, signer.generateSignature())
                }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Unlock with the empty passphrase first (PGPony's generated keys are passphrase-less by
     * default — see PGPCryptoService's guard note), then prompt through [AgentPrompt] for a
     * protected key. The s2KUsage==0 test is the house rule for telling "no passphrase set"
     * from "wrong passphrase" (SigningService.buildSignatureGenerator).
     */
    private fun unlock(secretKey: PGPSecretKey, label: String): PGPPrivateKey? {
        fun attempt(pass: String): PGPPrivateKey? = try {
            val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
                .build(pass.toCharArray())
            secretKey.extractPrivateKey(decryptor)
        } catch (_: Exception) {
            null
        }
        attempt("")?.let { return it }
        if (secretKey.s2KUsage.toInt() == 0) return null // unprotected and still failed: structural
        repeat(3) {
            val pass = AgentPrompt.ask(label) ?: return null // cancelled or timed out
            attempt(pass)?.let { return it }
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

class AgentUnlockRequest(val keyLabel: String) {
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

    /** Agent-thread side: raise the window, wait for an answer or the timeout. */
    fun ask(keyLabel: String): String? {
        val req = AgentUnlockRequest(keyLabel)
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
     * Accept loop, serial like SingleInstance's: ssh clients hold a connection for
     * milliseconds, and a queue of one keeps every signature request behind the same
     * single prompt path.
     */
    private fun serve(server: ServerSocketChannel) {
        while (server.isOpen) {
            val client = try {
                server.accept()
            } catch (_: Exception) {
                break // closed by stop(); the thread ends with the socket
            }
            runCatching {
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
        }
    }

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
                Text(tr("d_agent_unlock_message", request.keyLabel))
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
