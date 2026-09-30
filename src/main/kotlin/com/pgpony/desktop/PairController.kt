// PairController.kt
// PGPony Desktop 3.0.0, F1 (pair with another computer): everything between the pairing
// protocol (com.pgpony.android.pair, vendored from PGPonyAndroid with its docs/PAIRING_PROTOCOL.md)
// and the dialog. It opens and joins
// pairing windows, turns the user's picks into offered items, and imports what arrives through
// the same code a file import or a backup restore uses. No Compose here, so it can be tested.

package com.pgpony.desktop

import com.pgpony.android.backup.CrockfordBase32
import com.pgpony.android.pair.PairAttempt
import com.pgpony.android.pair.PairCrypto
import com.pgpony.android.pair.PairException
import com.pgpony.android.pair.PairFailure
import com.pgpony.android.pair.PairInvite
import com.pgpony.android.pair.PairItem
import com.pgpony.android.pair.PairProtocol
import com.pgpony.android.pair.PairSession
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
            if (bytes.size > PairSession.MAX_ITEM_BYTES) throw PairPrepareException(tr("d_pair_err_too_large", o.name))
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
        /** How long a pairing window stays open (docs/PAIRING_PROTOCOL.md, section 1). */
        const val WINDOW_MS = 10 * 60 * 1000

        /** The addresses another computer on this network can reach, IPv4 first. */
        fun localAddresses(): List<InetAddress> = runCatching {
            NetworkInterface.getNetworkInterfaces().toList()
                .filter { it.isUp && !it.isLoopback && !it.isVirtual && !it.isPointToPoint }
                .flatMap { it.inetAddresses.toList() }
                .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isMulticastAddress }
                .sortedBy { if (it is Inet4Address) 0 else 1 }
        }.getOrDefault(emptyList())

        /**
         * The address on the interface that carries the default route, which is the one another
         * computer on the same network almost always reaches. A connected UDP socket only picks a
         * route; it sends nothing. Null when there is no default route (a network with no way out).
         */
        fun primaryAddress(): InetAddress? = runCatching {
            java.net.DatagramSocket().use { s ->
                s.connect(InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1)), 9)
                s.localAddress.takeIf { !it.isAnyLocalAddress && !it.isLoopbackAddress }
            }
        }.getOrNull()

        /**
         * What the host screen lists: the primary address first, then the other IPv4 addresses
         * (virtual machine and VPN adapters among them, which a VM on this computer may need).
         * IPv6 addresses are listed only when the computer has no IPv4 address at all: a Mac
         * holds several rotating IPv6 privacy addresses, and a local network pairs over IPv4.
         */
        fun hostAddresses(): Pair<InetAddress?, List<InetAddress>> {
            val all = localAddresses()
            val v4 = all.filterIsInstance<Inet4Address>()
            val candidates = if (v4.isNotEmpty()) v4 else all
            val primary = primaryAddress()?.takeIf { it in candidates } ?: candidates.firstOrNull()
            return primary to candidates.filter { it != primary }
        }

        /** `192.168.1.20:49152` or `[fd00::1]:49152` as the host screen shows it. */
        fun display(address: InetAddress, port: Int): String =
            if (address is Inet4Address) "${address.hostAddress}:$port"
            else "[${address.hostAddress.substringBefore('%')}]:$port"

        /**
         * What the join field holds: a pasted invite (docs/PAIRING_PROTOCOL.md, section 8), whose
         * host key hash the join then checks, or a typed address. Null when it is neither.
         */
        fun target(text: String): JoinTarget? {
            PairInvite.parse(text)?.let { invite ->
                return JoinTarget(invite.addresses.map { it.socketAddress() }, invite.hostKeyHash)
            }
            if (looksLikeInvite(text)) return null
            return parse(text)?.let { JoinTarget(listOf(it), null) }
        }

        /** Starts like an invite, so a failed [target] should say the invite is unreadable. */
        fun looksLikeInvite(text: String): Boolean = text.trim().startsWith("pgpony-pair:", ignoreCase = true)

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

        /**
         * The invite the host screen shows as a QR code and offers to copy: the primary address
         * first, then the others, and the hash of this window's key. Null with no address.
         */
        fun invite(): PairInvite? {
            val (primary, others) = hostAddresses()
            val list = (listOfNotNull(primary) + others).mapNotNull { PairInvite.parseAddress(display(it, port)) }
            if (list.isEmpty()) return null
            return PairInvite.forHostKey(hostKey.public, list.take(PairInvite.MAX_ADDRESSES))
        }

        /** The primary address and the others, formatted with this window's port. */
        fun addresses(): Pair<String?, List<String>> {
            val (primary, others) = hostAddresses()
            return primary?.let { display(it, port) } to others.map { display(it, port) }
        }

        fun accept(): PairAttempt {
            server.soTimeout = WINDOW_MS
            val socket = try {
                server.accept()
            } catch (e: SocketTimeoutException) {
                throw PairException(PairFailure.TIMEOUT, tr("d_pair_err_window_expired"))
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

    /** Where a join connects: one typed address, or an invite's addresses and host key hash. */
    class JoinTarget(val addresses: List<InetSocketAddress>, val hostKeyHash: ByteArray?)

    /** Connects to a host window at [address] and runs phase 1. */
    fun join(address: InetSocketAddress): PairAttempt = join(JoinTarget(listOf(address), null))

    /**
     * Connects to the first of [target]'s addresses that answers and runs phase 1, checking the
     * host key against the invite's hash when there is one.
     */
    fun join(target: JoinTarget): PairAttempt {
        val timeout = if (target.addresses.size > 1) PairInvite.CONNECT_TIMEOUT_MS else 10_000
        var last: Exception? = null
        for (address in target.addresses) {
            val socket = Socket()
            try {
                socket.connect(address, timeout)
            } catch (e: Exception) {
                runCatching { socket.close() }
                last = e
                continue
            }
            socket.tcpNoDelay = true
            return PairProtocol.join(
                socket.getInputStream(), socket.getOutputStream(), { socket.soTimeout = it }, { socket.close() }, target.hostKeyHash
            )
        }
        throw last ?: PairException(PairFailure.CLOSED, "no address to connect to")
    }
}

class PairPrepareException(message: String) : Exception(message)
