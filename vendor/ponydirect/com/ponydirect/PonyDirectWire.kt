package com.ponydirect

import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The wire crypto and framing. Dependency-free (javax.crypto only). Must stay
 * byte-identical to the Swift implementation - see WIRE-PROTOCOL.md.
 *
 * The application supplies the per-peer key; this object never derives or stores it.
 */
object PonyDirectWire {

    /** Sent once at the start of every connection/stream. "PonyDirect wire v1". */
    val MAGIC: ByteArray = "PDR1".toByteArray(Charsets.US_ASCII)

    /** Framing is `type(1) | length(4, big-endian) | payload`. */
    const val HELLO: Byte = 0x01
    const val HELLO_ACK: Byte = 0x02
    const val NO_MATCH: Byte = 0x03
    const val ENVELOPE: Byte = 0x04

    // Fixed domain-separation labels (ASCII, no NUL).
    private val LABEL_IDENTIFY = "ponydirect/id/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_IDENTIFY_ACK = "ponydirect/id-ack/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_PROBE = "ponydirect/wan-probe/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_PONG = "ponydirect/wan-pong/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_DATA = "ponydirect/wan-data/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_ACK = "ponydirect/wan-ack/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_STREAM_DATA = "ponydirect/stream-data/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_STREAM_ACK = "ponydirect/stream-ack/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_STREAM_FIN = "ponydirect/stream-fin/v1".toByteArray(Charsets.US_ASCII)
    private val LABEL_STREAM_RST = "ponydirect/stream-rst/v1".toByteArray(Charsets.US_ASCII)

    private val rng = SecureRandom()

    fun randomBytes(count: Int): ByteArray = ByteArray(count).also { rng.nextBytes(it) }

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    // LAN identify handshake.
    fun identifyTag(pairKey: ByteArray, dialerNonce: ByteArray): ByteArray =
        hmac(pairKey, LABEL_IDENTIFY + dialerNonce)

    fun identifyAckTag(pairKey: ByteArray, dialerNonce: ByteArray, listenerNonce: ByteArray): ByteArray =
        hmac(pairKey, LABEL_IDENTIFY_ACK + dialerNonce + listenerNonce)

    // WAN hole-punch authentication.
    fun probeTag(pairKey: ByteArray, sessionNonce: ByteArray, probeNonce: ByteArray): ByteArray =
        hmac(pairKey, LABEL_PROBE + sessionNonce + probeNonce)

    fun pongTag(pairKey: ByteArray, sessionNonce: ByteArray, probeNonce: ByteArray): ByteArray =
        hmac(pairKey, LABEL_PONG + sessionNonce + probeNonce)

    // WAN reliable-datagram (ARQ) authentication. [header] is the fixed fields, the
    // chunk [payload] is appended, so the tag covers the whole datagram.
    fun dataTag(pairKey: ByteArray, header: ByteArray, payload: ByteArray): ByteArray =
        hmac(pairKey, LABEL_DATA + header + payload)

    fun ackTag(pairKey: ByteArray, header: ByteArray, bitmap: ByteArray): ByteArray =
        hmac(pairKey, LABEL_ACK + header + bitmap)

    // WAN reliable-stream (bulk) authentication.
    fun streamDataTag(pairKey: ByteArray, header: ByteArray, payload: ByteArray): ByteArray =
        hmac(pairKey, LABEL_STREAM_DATA + header + payload)

    fun streamAckTag(pairKey: ByteArray, header: ByteArray, blocks: ByteArray): ByteArray =
        hmac(pairKey, LABEL_STREAM_ACK + header + blocks)

    fun streamFinTag(pairKey: ByteArray, header: ByteArray): ByteArray =
        hmac(pairKey, LABEL_STREAM_FIN + header)

    fun streamRstTag(pairKey: ByteArray, sessionNonce: ByteArray): ByteArray =
        hmac(pairKey, LABEL_STREAM_RST + sessionNonce)

    /** Length-prefixed frame: `type(1) | length(4, big-endian) | payload`. */
    fun frame(type: Byte, payload: ByteArray): ByteArray {
        val n = payload.size
        val out = ByteArray(5 + n)
        out[0] = type
        out[1] = ((n ushr 24) and 0xFF).toByte()
        out[2] = ((n ushr 16) and 0xFF).toByte()
        out[3] = ((n ushr 8) and 0xFF).toByte()
        out[4] = (n and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 5, n)
        return out
    }

    /** One parsed frame and how many bytes it consumed. */
    data class ParsedFrame(val type: Byte, val payload: ByteArray, val consumed: Int)

    /** Parse one frame from the front of [buffer], or null if it is not yet whole. */
    fun parseFrame(buffer: ByteArray): ParsedFrame? {
        if (buffer.size < 5) return null
        val type = buffer[0]
        val len = ((buffer[1].toInt() and 0xFF) shl 24) or
                  ((buffer[2].toInt() and 0xFF) shl 16) or
                  ((buffer[3].toInt() and 0xFF) shl 8) or
                  (buffer[4].toInt() and 0xFF)
        if (len < 0 || buffer.size < 5 + len) return null
        return ParsedFrame(type, buffer.copyOfRange(5, 5 + len), 5 + len)
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
