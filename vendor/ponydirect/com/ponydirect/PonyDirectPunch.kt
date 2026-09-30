package com.ponydirect

/**
 * The UDP hole-punch datagram codec: authenticated PROBE / PONG / KEEPALIVE
 * packets, built on PonyDirectWire's per-pair tags. Datagrams are self-delimiting,
 * so unlike the TCP frame() there is no length prefix - just a one-byte type.
 * Byte-identical to PonyDirectPunch.swift.
 */
object PonyDirectPunch {

    const val PROBE: Byte = 0x11
    const val PONG: Byte = 0x12
    const val KEEPALIVE: Byte = 0x13

    const val NONCE_LEN = 16
    const val TAG_LEN = 32
    const val PROBE_LEN = 1 + 16 + 16 + 32
    const val PONG_LEN = 1 + 16 + 16 + 32
    const val KEEPALIVE_LEN = 1 + 16

    fun probe(pairKey: ByteArray, sessionNonce: ByteArray, probeNonce: ByteArray): ByteArray {
        val tag = PonyDirectWire.probeTag(pairKey, sessionNonce, probeNonce)
        return byteArrayOf(PROBE) + sessionNonce + probeNonce + tag
    }

    fun pong(pairKey: ByteArray, sessionNonce: ByteArray, probeNonce: ByteArray): ByteArray {
        val tag = PonyDirectWire.pongTag(pairKey, sessionNonce, probeNonce)
        return byteArrayOf(PONG) + sessionNonce + probeNonce + tag
    }

    fun keepalive(sessionNonce: ByteArray): ByteArray = byteArrayOf(KEEPALIVE) + sessionNonce

    data class Parsed(
        val type: Byte,
        val sessionNonce: ByteArray,
        val probeNonce: ByteArray,   // empty for keepalive
        val tag: ByteArray,          // empty for keepalive
    )

    /** Split a datagram into fields without verifying the tag, or null on error. */
    fun parse(data: ByteArray): Parsed? {
        if (data.isEmpty()) return null
        return when (data[0]) {
            PROBE, PONG -> {
                if (data.size != PROBE_LEN) return null
                Parsed(data[0], data.copyOfRange(1, 17), data.copyOfRange(17, 33), data.copyOfRange(33, 65))
            }
            KEEPALIVE -> {
                if (data.size != KEEPALIVE_LEN) return null
                Parsed(data[0], data.copyOfRange(1, 17), ByteArray(0), ByteArray(0))
            }
            else -> null
        }
    }

    fun verifyProbe(p: Parsed, pairKey: ByteArray): Boolean {
        if (p.type != PROBE) return false
        val expected = PonyDirectWire.probeTag(pairKey, p.sessionNonce, p.probeNonce)
        return PonyDirectWire.constantTimeEquals(p.tag, expected)
    }

    fun verifyPong(p: Parsed, pairKey: ByteArray): Boolean {
        if (p.type != PONG) return false
        val expected = PonyDirectWire.pongTag(pairKey, p.sessionNonce, p.probeNonce)
        return PonyDirectWire.constantTimeEquals(p.tag, expected)
    }
}
