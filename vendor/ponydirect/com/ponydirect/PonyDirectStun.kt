package com.ponydirect

/**
 * A minimal STUN client codec (RFC 5389): build a Binding request and parse the
 * server-reflexive address out of a Binding success response. Used only to learn
 * our own public ip:port from the self-hosted STUN server; STUN sees no message
 * content. Pure byte functions, no sockets. Byte-identical to PonyDirectStun.swift.
 */
object PonyDirectStun {

    const val MAGIC_COOKIE = 0x2112A442L

    private const val BINDING_REQUEST = 0x0001
    private const val BINDING_SUCCESS = 0x0101
    private const val ATTR_MAPPED_ADDRESS = 0x0001
    private const val ATTR_XOR_MAPPED_ADDRESS = 0x0020

    data class MappedAddress(val ip: String, val port: Int)

    /** Build a 20-byte Binding request with the given 12-byte transaction id. */
    fun bindingRequest(transactionID: ByteArray): ByteArray {
        require(transactionID.size == 12) { "STUN transaction id must be 12 bytes" }
        val out = ByteArray(20)
        out[0] = 0x00; out[1] = 0x01               // message type
        out[2] = 0x00; out[3] = 0x00               // length 0
        out[4] = 0x21; out[5] = 0x12; out[6] = 0xA4.toByte(); out[7] = 0x42  // cookie
        System.arraycopy(transactionID, 0, out, 8, 12)
        return out
    }

    fun newTransactionID(): ByteArray = PonyDirectWire.randomBytes(12)

    /**
     * Parse a Binding success response for [transactionID]. XOR-MAPPED-ADDRESS is
     * preferred; MAPPED-ADDRESS is a fallback for older servers. Returns null on any
     * mismatch or malformed message.
     */
    fun parseResponse(data: ByteArray, transactionID: ByteArray): MappedAddress? {
        if (data.size < 20) return null
        val type = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        if (type != BINDING_SUCCESS) return null
        val length = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        val cookie = ((data[4].toLong() and 0xFF) shl 24) or ((data[5].toLong() and 0xFF) shl 16) or
                     ((data[6].toLong() and 0xFF) shl 8) or (data[7].toLong() and 0xFF)
        if (cookie != MAGIC_COOKIE) return null
        for (k in 0 until 12) if (data[8 + k] != transactionID[k]) return null
        if (data.size < 20 + length) return null

        var xor: MappedAddress? = null
        var plain: MappedAddress? = null
        var i = 20
        val end = 20 + length
        while (i + 4 <= end) {
            val attrType = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            val attrLen = ((data[i + 2].toInt() and 0xFF) shl 8) or (data[i + 3].toInt() and 0xFF)
            val valueStart = i + 4
            if (valueStart + attrLen > end) break
            val value = data.copyOfRange(valueStart, valueStart + attrLen)
            if (attrType == ATTR_XOR_MAPPED_ADDRESS) {
                xor = decodeAddress(value, true, data)
            } else if (attrType == ATTR_MAPPED_ADDRESS) {
                plain = decodeAddress(value, false, data)
            }
            i = valueStart + attrLen + ((4 - (attrLen % 4)) % 4)
        }
        return xor ?: plain
    }

    // value layout: reserved(1) | family(1) | port(2) | address(4 or 16)
    private fun decodeAddress(value: ByteArray, xored: Boolean, header: ByteArray): MappedAddress? {
        if (value.size < 4) return null
        val family = value[1].toInt() and 0xFF
        var port = ((value[2].toInt() and 0xFF) shl 8) or (value[3].toInt() and 0xFF)
        if (xored) port = port xor ((MAGIC_COOKIE ushr 16).toInt() and 0xFFFF)

        return when (family) {
            0x01 -> {                                     // IPv4
                if (value.size < 8) return null
                val a = intArrayOf(
                    value[4].toInt() and 0xFF, value[5].toInt() and 0xFF,
                    value[6].toInt() and 0xFF, value[7].toInt() and 0xFF
                )
                if (xored) {
                    val cookie = intArrayOf(0x21, 0x12, 0xA4, 0x42)
                    for (k in 0 until 4) a[k] = a[k] xor cookie[k]
                }
                MappedAddress("${a[0]}.${a[1]}.${a[2]}.${a[3]}", port)
            }
            0x02 -> {                                     // IPv6
                if (value.size < 20) return null
                val a = IntArray(16) { value[4 + it].toInt() and 0xFF }
                if (xored) {
                    val seed = IntArray(16)
                    val c = intArrayOf(0x21, 0x12, 0xA4, 0x42)
                    for (k in 0 until 4) seed[k] = c[k]
                    for (k in 0 until 12) seed[4 + k] = header[8 + k].toInt() and 0xFF
                    for (k in 0 until 16) a[k] = a[k] xor seed[k]
                }
                MappedAddress(ipv6String(a), port)
            }
            else -> null
        }
    }

    private fun ipv6String(a: IntArray): String {
        val groups = ArrayList<String>(8)
        var k = 0
        while (k < 16) {
            val g = (a[k] shl 8) or a[k + 1]
            groups.add(Integer.toHexString(g))
            k += 2
        }
        return groups.joinToString(":")
    }
}
