package com.ponydirect

/**
 * The reliable-datagram codec for the WAN path: a payload larger than one UDP
 * datagram is split into authenticated DATA chunks; the receiver ACKs a bitmap of
 * what it has and the sender retransmits the gaps. Pure byte functions built on
 * PonyDirectWire's per-pair tags. Byte-identical to PonyDirectArq.swift.
 */
object PonyDirectArq {

    const val DATA: Byte = 0x14
    const val ACK: Byte = 0x15

    /** Max application payload per DATA chunk, kept under a safe path MTU. */
    const val MAX_CHUNK_PAYLOAD = 1024

    // DATA = type(1) | sessionNonce(16) | msgSeq(4) | chunkIndex(2) | chunkCount(2) | payload | tag(32)

    fun data(pairKey: ByteArray, sessionNonce: ByteArray, msgSeq: Int,
             chunkIndex: Int, chunkCount: Int, payload: ByteArray): ByteArray {
        val header = sessionNonce + u32(msgSeq) + u16(chunkIndex) + u16(chunkCount)
        val tag = PonyDirectWire.dataTag(pairKey, header, payload)
        return byteArrayOf(DATA) + header + payload + tag
    }

    class DataPacket(
        val sessionNonce: ByteArray,
        val msgSeq: Int,
        val chunkIndex: Int,
        val chunkCount: Int,
        val payload: ByteArray,
        internal val header: ByteArray,
        internal val tag: ByteArray,
    )

    fun parseData(d: ByteArray): DataPacket? {
        if (d.size < 1 + 24 + 32 || d[0] != DATA) return null
        val payloadEnd = d.size - 32
        if (payloadEnd < 25) return null
        return DataPacket(
            sessionNonce = d.copyOfRange(1, 17),
            msgSeq = readU32(d, 17),
            chunkIndex = readU16(d, 21),
            chunkCount = readU16(d, 23),
            payload = d.copyOfRange(25, payloadEnd),
            header = d.copyOfRange(1, 25),
            tag = d.copyOfRange(payloadEnd, d.size),
        )
    }

    fun verifyData(p: DataPacket, pairKey: ByteArray): Boolean =
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.dataTag(pairKey, p.header, p.payload))

    // ACK = type(1) | sessionNonce(16) | msgSeq(4) | chunkCount(2) | bitmap | tag(32)

    fun ack(pairKey: ByteArray, sessionNonce: ByteArray, msgSeq: Int,
            chunkCount: Int, bitmap: ByteArray): ByteArray {
        val header = sessionNonce + u32(msgSeq) + u16(chunkCount)
        val tag = PonyDirectWire.ackTag(pairKey, header, bitmap)
        return byteArrayOf(ACK) + header + bitmap + tag
    }

    class AckPacket(
        val sessionNonce: ByteArray,
        val msgSeq: Int,
        val chunkCount: Int,
        val bitmap: ByteArray,
        internal val header: ByteArray,
        internal val tag: ByteArray,
    )

    fun parseAck(d: ByteArray): AckPacket? {
        if (d.size < 1 + 22 + 32 || d[0] != ACK) return null
        val chunkCount = readU16(d, 21)
        val bitmapLen = (chunkCount + 7) / 8
        if (d.size != 1 + 22 + bitmapLen + 32) return null
        return AckPacket(
            sessionNonce = d.copyOfRange(1, 17),
            msgSeq = readU32(d, 17),
            chunkCount = chunkCount,
            bitmap = d.copyOfRange(23, 23 + bitmapLen),
            header = d.copyOfRange(1, 23),
            tag = d.copyOfRange(23 + bitmapLen, d.size),
        )
    }

    fun verifyAck(p: AckPacket, pairKey: ByteArray): Boolean =
        PonyDirectWire.constantTimeEquals(p.tag, PonyDirectWire.ackTag(pairKey, p.header, p.bitmap))

    // Bitmap + chunking helpers

    fun bitmapLen(chunkCount: Int): Int = (chunkCount + 7) / 8

    fun bitmapSet(bitmap: ByteArray, index: Int) {
        val byte = index / 8; val bit = index % 8
        if (byte < bitmap.size) bitmap[byte] = (bitmap[byte].toInt() or (1 shl bit)).toByte()
    }

    fun bitmapGet(bitmap: ByteArray, index: Int): Boolean {
        val byte = index / 8; val bit = index % 8
        if (byte >= bitmap.size) return false
        return (bitmap[byte].toInt() and (1 shl bit)) != 0
    }

    /** Split a payload into <= MAX_CHUNK_PAYLOAD-byte chunks (at least one, empty ok). */
    fun chunk(payload: ByteArray, max: Int = MAX_CHUNK_PAYLOAD): List<ByteArray> {
        if (payload.isEmpty()) return listOf(ByteArray(0))
        val out = ArrayList<ByteArray>()
        var i = 0
        while (i < payload.size) {
            val end = minOf(i + max, payload.size)
            out.add(payload.copyOfRange(i, end))
            i = end
        }
        return out
    }

    // private byte helpers
    private fun u32(v: Int): ByteArray = byteArrayOf(
        ((v ushr 24) and 0xFF).toByte(), ((v ushr 16) and 0xFF).toByte(),
        ((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte()
    )
    private fun u16(v: Int): ByteArray = byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())
    private fun readU32(b: ByteArray, i: Int): Int =
        ((b[i].toInt() and 0xFF) shl 24) or ((b[i+1].toInt() and 0xFF) shl 16) or
        ((b[i+2].toInt() and 0xFF) shl 8) or (b[i+3].toInt() and 0xFF)
    private fun readU16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i+1].toInt() and 0xFF)
}
