package com.ponydirect

import java.io.ByteArrayOutputStream

/**
 * Receiver half of the stream ARQ: reassembles SDATA payloads into an in-order byte stream and
 * reports the SACK state (cumulative ack + selective ranges + receive window) the sender needs.
 *
 * The engine sends SDATA chunk-aligned (each at a 1024-byte offset), so reassembly is indexed by
 * chunk. The wire stays byte-offset, so this is an engine choice, not a protocol one. Pure logic,
 * no I/O and no timers, so it is exhaustively testable against loss, reordering and duplication.
 * Byte-identical intent to the Swift twin.
 */
class PonyDirectStreamReceiver(private val capacity: Int = 1 shl 20) {

    private val chunk = PonyDirectStream.MAX_PAYLOAD.toLong()   // 1024

    private var nextChunk = 0L        // next in-order chunk index still needed
    private var deliveredBytes = 0L   // total bytes handed in order to the readable queue
    private var bufferedBytes = 0     // out-of-order bytes held above nextChunk
    private val buffered = HashMap<Long, ByteArray>()  // chunkIndex -> payload, for gaps above nextChunk
    private val readable = ArrayDeque<ByteArray>()     // delivered, in-order, awaiting read()
    private var readHead = 0
    private var finalSeq: Long? = null

    /** Integrate one SDATA payload at byte offset [seq]. Ignores duplicates, old and non-aligned. */
    fun onData(seq: Long, payload: ByteArray) {
        if (payload.isEmpty()) return
        if (seq % chunk != 0L) return
        val idx = seq / chunk
        if (idx < nextChunk || buffered.containsKey(idx)) return
        if ((idx - nextChunk) * chunk >= capacity) return       // beyond the receive window
        buffered[idx] = payload
        bufferedBytes += payload.size
        while (true) {
            val p = buffered.remove(nextChunk) ?: break
            bufferedBytes -= p.size
            readable.addLast(p)
            deliveredBytes += p.size
            nextChunk += 1
        }
    }

    fun onFin(finalSeq: Long) { this.finalSeq = finalSeq }

    /** True once every byte up to the sender's FIN has been delivered in order. */
    fun isComplete(): Boolean = finalSeq?.let { deliveredBytes >= it } ?: false

    /** Drain up to [max] in-order bytes for the app. */
    fun read(max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        var need = max
        while (need > 0 && readable.isNotEmpty()) {
            val head = readable.first()
            val avail = head.size - readHead
            val take = minOf(need, avail)
            out.write(head, readHead, take)
            readHead += take; need -= take
            if (readHead == head.size) { readable.removeFirst(); readHead = 0 }
        }
        return out.toByteArray()
    }

    fun cumAck(): Long = deliveredBytes
    fun rwnd(): Int = maxOf(0, capacity - readableBytes() - bufferedBytes)

    /** Selective-ack ranges [start, end) in byte offsets, one per contiguous run of buffered chunks. */
    fun sackBlocks(): List<PonyDirectStream.SackBlock> {
        if (buffered.isEmpty()) return emptyList()
        val idxs = buffered.keys.sorted()
        val blocks = ArrayList<PonyDirectStream.SackBlock>()
        var i = 0
        while (i < idxs.size && blocks.size < PonyDirectStream.MAX_SACK_BLOCKS) {
            val startChunk = idxs[i]
            var j = i
            var bytes = 0L
            while (j < idxs.size && idxs[j] == startChunk + (j - i)) { bytes += buffered[idxs[j]]!!.size; j++ }
            val startByte = startChunk * chunk
            blocks.add(PonyDirectStream.SackBlock(startByte, startByte + bytes))
            i = j
        }
        return blocks
    }

    private fun readableBytes(): Int { var t = -readHead; for (c in readable) t += c.size; return t }
}
