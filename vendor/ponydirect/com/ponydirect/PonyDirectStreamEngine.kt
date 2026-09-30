package com.ponydirect

/**
 * Ties the stream sender and receiver to the wire: builds SDATA/SFIN frames from the sender,
 * dispatches and authenticates incoming SDATA/SACK/SFIN/SRST, and replies with SACKs. This is the
 * driver core PonyDirectWan runs on its socket and timer; it is transport-agnostic (outgoing frames
 * go through [onDatagram]), so it is testable end to end over a simulated wire. The blocking
 * InputStream/OutputStream wrapper and the timer thread live with the real socket in the app driver.
 * Byte-identical intent to the Swift twin.
 */
class PonyDirectStreamEngine(
    private val pairKey: ByteArray,
    private val sessionNonce: ByteArray,
    private val onDatagram: (ByteArray) -> Unit,
) {
    private val sender = PonyDirectStreamSender()
    private val receiver = PonyDirectStreamReceiver()

    fun write(bytes: ByteArray) = sender.write(bytes)
    fun finishSending() = sender.finish()
    fun read(max: Int): ByteArray = receiver.read(max)
    fun sendComplete(): Boolean = sender.isDone()
    fun recvComplete(): Boolean = receiver.isComplete()

    /** Drive the sender: emit due SDATA/SFIN frames. Call on a timer. */
    fun tick(nowMs: Long) {
        for (o in sender.poll(nowMs)) when (o) {
            is StreamOut.Data -> onDatagram(PonyDirectStream.data(pairKey, sessionNonce, o.seq, o.payload))
            is StreamOut.Fin -> onDatagram(PonyDirectStream.fin(pairKey, sessionNonce, o.finalSeq))
        }
    }

    /** Feed one received wire datagram. Ignores anything that fails auth or session binding. */
    fun onWireDatagram(nowMs: Long, d: ByteArray) {
        if (d.isEmpty()) return
        when (d[0]) {
            PonyDirectStream.SDATA -> {
                val p = PonyDirectStream.parseData(d) ?: return
                if (!p.sessionNonce.contentEquals(sessionNonce) || !PonyDirectStream.verifyData(p, pairKey)) return
                receiver.onData(p.seq, p.payload)
                sendAck()
            }
            PonyDirectStream.SFIN -> {
                val p = PonyDirectStream.parseFin(d) ?: return
                if (!p.sessionNonce.contentEquals(sessionNonce) || !PonyDirectStream.verifyFin(p, pairKey)) return
                receiver.onFin(p.finalSeq)
                sendAck()
            }
            PonyDirectStream.SACK -> {
                val p = PonyDirectStream.parseAck(d) ?: return
                if (!p.sessionNonce.contentEquals(sessionNonce) || !PonyDirectStream.verifyAck(p, pairKey)) return
                sender.onAck(nowMs, p.cumAck, p.rwnd, p.blocks)
            }
            PonyDirectStream.SRST -> { /* peer aborted; the codec-level engine has nothing to tear down */ }
        }
    }

    private fun sendAck() {
        onDatagram(PonyDirectStream.ack(pairKey, sessionNonce, receiver.cumAck(), receiver.rwnd(), receiver.sackBlocks()))
    }
}
