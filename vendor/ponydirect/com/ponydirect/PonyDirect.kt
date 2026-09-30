package com.ponydirect

/**
 * The application boundary. PonyDirect moves opaque bytes between already-paired
 * peers; the app supplies the per-peer key, the out-of-band signaling channel, and
 * the sink for delivered payloads. The app owns all encryption and key exchange.
 */

/**
 * Supplies the single 32-byte symmetric key PonyDirect shares with a peer. Both
 * sides must derive the same value out of band (in CarrierPony, from the sealed
 * pair keys). Used only for the identify handshake and hole-punch probe MACs.
 */
interface PonyDirectKeyProvider {
    fun pairKey(peerID: String): ByteArray?
}

/** One WAN signaling message, relayed by the app over its own confidential channel. */
class PonyDirectSignal(
    val kind: Kind,
    val candidates: List<String> = emptyList(),  // "ip:port" list, for offer/answer
    val sessionNonce: ByteArray? = null,          // binds a hole-punch session
    val candidate: String? = null,                // a single trickled "ip:port", for ice
) {
    enum class Kind { OFFER, ANSWER, ICE }
}

/** The app's out-of-band channel for relaying signaling to a peer. */
interface PonyDirectSignaling {
    fun sendSignal(signal: PonyDirectSignal, peerID: String)
}

/** Receives payloads delivered directly from a peer (already sealed by the app). */
interface PonyDirectEnvelopeSink {
    fun received(payload: ByteArray, peerID: String)
}

/** A device seen on the local network, known only by a per-launch random node id. */
data class DiscoveredNode(val nodeID: String)

/**
 * Local-network discovery (mDNS). App-supplied: the concrete implementation lives
 * with the app because it needs platform APIs (NsdManager); the transport logic
 * is platform-neutral.
 */
interface PonyDirectDiscovery {
    fun start()
    fun stop()
    val nearby: List<DiscoveredNode>
}
