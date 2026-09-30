// PairController.kt
// PGPony Desktop 3.0.0, F1 (pair with another computer): everything between the pairing
// protocol (com.pgpony.pair, docs/F1_PAIRING_PROTOCOL.md) and the dialog. It opens and joins
// pairing windows, turns the user's picks into offered items, and imports what arrives through
// the same code a file import or a backup restore uses. No Compose here, so it can be tested.

package com.pgpony.desktop

import com.pgpony.android.backup.CrockfordBase32
import com.pgpony.pair.PairAttempt
import com.pgpony.pair.PairCrypto
import com.pgpony.pair.PairItem
import com.pgpony.pair.PairProtocol
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException

class PairController(private val repo: DesktopKeyRepository, private val edits: DesktopKeyEdits) {

    /** Something the user can send. */
    sealed class Outgoing {
        abstract val name: String

        data class PublicKey(val fingerprint: String, override val name: String) : Outgoing()
        data class KeyPair(val fingerprint: String, override val name: String, val protected: Boolean) : Outgoing()
        object Backup : Outgoing() {
            override val name: String get() = tr("d_pair_item_backup")
        }
    }

    /** Offered items with their bytes, and the backup's recovery code when a backup is among them. */
    class Prepared(val items: List<PairItem>, val payloads: Map<Int, ByteArray>, val recoveryCode: String?)

    /** What this keyring could send. Card-backed keys go as public keys only. */
    suspend fun candidates(): List<Outgoing> {
        val keys = repo.allKeys()
        val out = ArrayList<Outgoing>()
        for (k in keys) {
            val name = k.userID.ifBlank { k.fingerprint }
            if (k.isKeyPair && !k.isCardBacked) {
                out += Outgoing.KeyPair(k.fingerprint, name, runCatching { edits.isPassphraseProtected(k.fingerprint) }.getOrDefault(false))
            }
        }
        for (k in keys) out += Outgoing.PublicKey(k.fingerprint, k.userID.ifBlank { k.fingerprint })
        if (keys.isNotEmpty()) out += Outgoing.Backup
        return out
    }

    /**
     * Builds the items for [picked]. [transferPassphrase] protects key pairs that have no
     * passphrase of their own; without it such a pick fails with [PairPrepareException].
     */
    suspend fun prepare(picked: List<Outgoing>, transferPassphrase: String?): Prepared {
        val items = ArrayList<PairItem>()
        val payloads = HashMap<Int, ByteArray>()
        var recovery: String? = null
        picked.forEachIndexed { i, o ->
            val id = i + 1
            val (kind, fingerprint, bytes) = when (o) {
                is Outgoing.PublicKey -> Triple(
                    PairItem.PUBLIC_KEY, o.fingerprint,
                    (repo.exportArmoredPublicKeyForSharing(o.fingerprint) ?: throw PairPrepareException(tr("d_pair_err_export", o.name)))
                        .toByteArray(Charsets.UTF_8)
                )
                is Outgoing.KeyPair -> Triple(
                    PairItem.KEY_PAIR, o.fingerprint,
                    (edits.transferArmor(o.fingerprint, transferPassphrase)
                        ?: throw PairPrepareException(
                            if (!o.protected && transferPassphrase.isNullOrEmpty()) tr("d_pair_err_needs_passphrase", o.name)
                            else tr("d_pair_err_export", o.name)
                        )).toByteArray(Charsets.UTF_8)
                )
                Outgoing.Backup -> {
                    val code = CrockfordBase32.generate()
                    recovery = code.grouped
                    Triple(PairItem.BACKUP, null, DesktopBackupService(repo).exportBackup(code.canonical))
                }
            }
            if (bytes.size > com.pgpony.pair.PairSession.MAX_ITEM_BYTES) throw PairPrepareException(tr("d_pair_err_too_large", o.name))
            items += PairItem(id, kind, o.name, fingerprint, bytes.size.toLong())
            payloads[id] = bytes
        }
        return Prepared(items, payloads, recovery)
    }

    /**
     * Imports one received item and says what happened. A backup needs [backupCode], the
     * recovery code the sending screen shows. Throws with a readable message on failure.
     */
    suspend fun apply(item: PairItem, bytes: ByteArray, backupCode: String?): String = when (item.kind) {
        PairItem.PUBLIC_KEY, PairItem.KEY_PAIR -> {
            val report = repo.importArmoredText(bytes.toString(Charsets.UTF_8))
            if (report.failed > 0 && report.total == report.failed) throw PairPrepareException(tr("d_pair_err_import", item.name))
            report.summary()
        }
        PairItem.BACKUP -> {
            val code = backupCode?.takeIf { it.isNotBlank() } ?: throw PairPrepareException(tr("d_pair_err_backup_code"))
            DesktopBackupService(repo).restoreBackup(bytes, code).summary()
        }
        else -> throw PairPrepareException(tr("d_pair_err_import", item.name))
    }

    companion object {
        /** How long a pairing window stays open (docs/F1_PAIRING_PROTOCOL.md, section 1). */
        const val WINDOW_MS = 10 * 60 * 1000

        /** The addresses another computer on this network can reach, IPv4 first. */
        fun localAddresses(): List<InetAddress> = runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .filter { it.isUp && !it.isLoopback && !it.isVirtual && !it.isPointToPoint }
                .flatMap { it.inetAddresses.toList() }
                .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isMulticastAddress }
                .sortedBy { if (it is Inet4Address) 0 else 1 }
        }.getOrDefault(emptyList())

        /** `192.168.1.20:49152` or `[fd00::1]:49152` as the host screen shows it. */
        fun display(address: InetAddress, port: Int): String =
            if (address is Inet4Address) "${address.hostAddress}:$port"
            else "[${address.hostAddress.substringBefore('%')}]:$port"

        /** Reads what the user typed on the joining computer; null when it is not an address. */
        fun parse(text: String): InetSocketAddress? {
            val t = text.trim()
            val (host, portText) = when {
                t.startsWith("[") -> t.substringAfter('[').substringBefore(']') to t.substringAfter("]:", "")
                t.count { it == ':' } == 1 -> t.substringBefore(':') to t.substringAfter(':')
                else -> return null
            }
            val port = portText.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            if (host.isBlank()) return null
            return runCatching { InetSocketAddress(InetAddress.getByName(host), port) }.getOrNull()
        }
    }

    /**
     * An open pairing window: a listener on an ephemeral port on every interface. [accept]
     * waits for the one connection, closes the listener, and runs phase 1.
     */
    class HostWindow : AutoCloseable {
        private val server = ServerSocket(0)
        val hostKey: PairCrypto.KeyPair = PairCrypto.keyPair()
        val port: Int get() = server.localPort
        val openedAt = System.currentTimeMillis()

        fun addresses(): List<String> = localAddresses().map { display(it, port) }

        fun accept(): PairAttempt {
            server.soTimeout = WINDOW_MS
            val socket = try {
                server.accept()
            } catch (e: SocketTimeoutException) {
                throw com.pgpony.pair.PairException(com.pgpony.pair.PairFailure.TIMEOUT, tr("d_pair_err_window_expired"))
            } finally {
                runCatching { server.close() }
            }
            socket.tcpNoDelay = true
            return PairProtocol.host(socket.getInputStream(), socket.getOutputStream(), { socket.soTimeout = it }, { socket.close() }, hostKey)
        }

        override fun close() {
            runCatching { server.close() }
        }
    }

    /** Connects to a host window at [address] and runs phase 1. */
    fun join(address: InetSocketAddress): PairAttempt {
        val socket = Socket()
        socket.connect(address, 10_000)
        socket.tcpNoDelay = true
        return PairProtocol.join(socket.getInputStream(), socket.getOutputStream(), { socket.soTimeout = it }, { socket.close() })
    }
}

class PairPrepareException(message: String) : Exception(message)
