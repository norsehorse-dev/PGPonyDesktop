package com.ponydirect

/**
 * The reliable-stream (bulk) codec for the WAN path: an ordered byte stream over the hole-punched
 * UDP socket, for payloads too large for the message ARQ (files). Pure byte functions built on
 * PonyDirectWire's per-pair stream tags; the sliding-window ARQ, flow control and congestion control
 * that use them live in the stream engine. Must stay byte-identical to the Swift twin.
 *
 * Sequence numbers are byte offsets (8 bytes), so a stream can carry gigabytes without wrapping and
 * a resumed transfer can name an exact offset.
 */
object PonyDirectStream {

    const val SDATA: Byte = 0x16
    const val SACK: Byte = 0x17
    const val SFIN: Byte = 0x18
    const val SRST: Byte = 0x19

    const val MAX_PAYLOAD = 1024
    const val MAX_SACK_BLOCKS = 16

    // SDATA = type(1) | sessionNonce(16) | seq(8) | len(2) | payload | tag(32)

    fun data(pairKey: ByteArray, sessionNonce: ByteArray, seq: Long, payload: ByteArray): ByteArray {
        val header = sessionNonce + u64(seq) + u16(payload.size)
        val tag = PonyDirectWire.streamDataTag(pairKey, header, payload)
        return byteArrayOf(SDATA) + header + payload + tag
    }

    class DataPacket(val sessionNonce: ByteArray, val seq: Long, val payload: ByteArray,
                     val header: ByteArray, val tag: ByteArray)

    fun parseData(d: ByteArray): DataPacket? {
        if (d.size < 1 + 26 + 32 || d[0] != SDATA) return null
        val len = readU16(d, 25)
        if (d.size != 1 + 26 + len + 32) return null
        return DataPacket(d.copyOfRange(1, 17), readU64(d, 17), d.copyOfRange(27, 27 + len),
                          d.copyOfRange(1, 27), d.copyOfRange(27 + len, d.size))
    }

    fun verifyData(p: DataPacket, pairKey: ByteArray): Boolean =
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.streamDataTag(pairKey, p.header, p.payload))

    // SACK = type(1) | sessionNonce(16) | cumAck(8) | rwnd(4) | nblk(1) | nblk*[start(8) end(8)] | tag(32)

    data class SackBlock(val start: Long, val end: Long)

    fun ack(pairKey: ByteArray, sessionNonce: ByteArray, cumAck: Long, rwnd: Int, blocks: List<SackBlock>): ByteArray {
        val n = minOf(blocks.size, MAX_SACK_BLOCKS)
        val header = sessionNonce + u64(cumAck) + u32(rwnd) + byteArrayOf(n.toByte())
        var blk = ByteArray(0)
        for (i in 0 until n) blk += u64(blocks[i].start) + u64(blocks[i].end)
        val tag = PonyDirectWire.streamAckTag(pairKey, header, blk)
        return byteArrayOf(SACK) + header + blk + tag
    }

    class AckPacket(val sessionNonce: ByteArray, val cumAck: Long, val rwnd: Int, val blocks: List<SackBlock>,
                    val header: ByteArray, val blk: ByteArray, val tag: ByteArray)

    fun parseAck(d: ByteArray): AckPacket? {
        if (d.size < 1 + 29 + 32 || d[0] != SACK) return null
        val n = d[29].toInt() and 0xFF
        val blkLen = n * 16
        if (d.size != 1 + 29 + blkLen + 32) return null
        val blocks = ArrayList<SackBlock>(n)
        var off = 30
        repeat(n) { blocks.add(SackBlock(readU64(d, off), readU64(d, off + 8))); off += 16 }
        return AckPacket(d.copyOfRange(1, 17), readU64(d, 17), readU32(d, 25), blocks,
                         d.copyOfRange(1, 30), d.copyOfRange(30, 30 + blkLen), d.copyOfRange(30 + blkLen, d.size))
    }

    fun verifyAck(p: AckPacket, pairKey: ByteArray): Boolean =
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.streamAckTag(pairKey, p.header, p.blk))

    // SFIN = type(1) | sessionNonce(16) | finalSeq(8) | tag(32)

    fun fin(pairKey: ByteArray, sessionNonce: ByteArray, finalSeq: Long): ByteArray {
        val header = sessionNonce + u64(finalSeq)
        return byteArrayOf(SFIN) + header + PonyDirectWire.streamFinTag(pairKey, header)
    }

    class FinPacket(val sessionNonce: ByteArray, val finalSeq: Long, val header: ByteArray, val tag: ByteArray)

    fun parseFin(d: ByteArray): FinPacket? {
        if (d.size != 1 + 24 + 32 || d[0] != SFIN) return null
        return FinPacket(d.copyOfRange(1, 17), readU64(d, 17), d.copyOfRange(1, 25), d.copyOfRange(25, d.size))
    }

    fun verifyFin(p: FinPacket, pairKey: ByteArray): Boolean =
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.streamFinTag(pairKey, p.header))

    // SRST = type(1) | sessionNonce(16) | tag(32)

    fun rst(pairKey: ByteArray, sessionNonce: ByteArray): ByteArray =
        byteArrayOf(SRST) + sessionNonce + PonyDirectWire.streamRstTag(pairKey, sessionNonce)

    class RstPacket(val sessionNonce: ByteArray, val tag: ByteArray)

    fun parseRst(d: ByteArray): RstPacket? {
        if (d.size != 1 + 16 + 32 || d[0] != SRST) return null
        return RstPacket(d.copyOfRange(1, 17), d.copyOfRange(17, d.size))
    }

    fun verifyRst(p: RstPacket, pairKey: ByteArray): Boolean =
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.streamRstTag(pairKey, p.sessionNonce))

    // byte helpers
    private fun u64(v: Long): ByteArray = ByteArray(8) { ((v ushr (56 - it * 8)) and 0xFF).toByte() }
    private fun u32(v: Int): ByteArray = byteArrayOf(((v ushr 24) and 0xFF).toByte(), ((v ushr 16) and 0xFF).toByte(),
                                                     ((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())
    private fun u16(v: Int): ByteArray = byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())
    private fun readU64(b: ByteArray, i: Int): Long { var v = 0L; for (k in 0 until 8) v = (v shl 8) or (b[i + k].toLong() and 0xFF); return v }
    private fun readU32(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 24) or ((b[i+1].toInt() and 0xFF) shl 16) or ((b[i+2].toInt() and 0xFF) shl 8) or (b[i+3].toInt() and 0xFF)
    private fun readU16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i+1].toInt() and 0xFF)
}
