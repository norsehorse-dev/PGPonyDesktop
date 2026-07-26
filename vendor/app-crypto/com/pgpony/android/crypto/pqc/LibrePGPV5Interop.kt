// LibrePGPV5Interop.kt
// PGPony Android — 4.0.0 Phase 2b (v5 LibrePGP secret-key format shim)
//
// BouncyCastle's v5 secret-key framing diverges from the LibrePGP / RFC 9580
// layout that GnuPG, Sequoia (sq), and PGPony-iOS use — but ONLY for an
// UNPROTECTED (S2K usage 0) algorithm-8 composite subkey:
//
//   BC (internal):  usage(0) | condLen(0) | count(4)=96 | material(96) | cksum(2)
//   LibrePGP (wire): usage(0) |             count(4)=96 | material(96)
//
// (v6, and v5 *protected* usage-254 keys, are byte-identical between BC and
// LibrePGP — BC parses those directly, so they need no shim.)
//
// Rather than take composite secret keys off BC's storage/lookup path, we
// keep the proven BC-based internals and translate at the import/export
// boundary: strip the 3 extra octets when exporting (BC -> LibrePGP), and
// add them back when importing (LibrePGP -> BC). The transform is
// deterministic (condLen is always 0; the checksum is sum-of-material mod
// 65536) and idempotent — it detects the format by the secret-region length,
// so re-running it or feeding it an already-correct key is a no-op.

package com.pgpony.android.crypto.pqc

import java.io.ByteArrayOutputStream

object LibrePGPV5Interop {

    private const val ALGO_KYBER = 8
    private const val MATERIAL_LEN = 96                 // X25519(32) + ML-KEM seed(64)
    private const val BC_REGION = 1 + 1 + 4 + MATERIAL_LEN + 2   // 104
    private const val LIBREPGP_REGION = 1 + 4 + MATERIAL_LEN      // 101

    /** BC internal -> LibrePGP wire (for export). No-op if already LibrePGP. */
    fun toLibrePGPFormat(keyBytes: ByteArray): ByteArray = transform(keyBytes, toLibrePGP = true)

    /** LibrePGP wire -> BC internal (for import). No-op if already BC. */
    fun toBcFormat(keyBytes: ByteArray): ByteArray = transform(keyBytes, toLibrePGP = false)

    // ── implementation ───────────────────────────────────────────────

    private fun transform(data: ByteArray, toLibrePGP: Boolean): ByteArray {
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < data.size) {
            val h = header(data, i) ?: run { out.write(data, i, data.size - i); return out.toByteArray() }
            val body = data.copyOfRange(h.bodyStart, h.bodyStart + h.bodyLen)
            val rebuilt = tryRewrite(h.tag, body, toLibrePGP)
            if (rebuilt != null) {
                out.write(newFormatHeader(h.tag, rebuilt.size))
                out.write(rebuilt)
            } else {
                out.write(data, i, (h.bodyStart - i) + h.bodyLen) // verbatim
            }
            i = h.bodyStart + h.bodyLen
        }
        return out.toByteArray()
    }

    /** Rewrite a v5 algo-8 unprotected secret (sub)key body, or null to pass through. */
    private fun tryRewrite(tag: Int, body: ByteArray, toLibrePGP: Boolean): ByteArray? {
        if (tag != 7 && tag != 5) return null
        if (body.size <= 10 || body[0].toInt() != 5 || (body[5].toInt() and 0xFF) != ALGO_KYBER) return null
        val pkm = uint32(body, 6)
        val secStart = 10 + pkm
        if (secStart >= body.size || (body[secStart].toInt() and 0xFF) != 0) return null // only usage 0
        val region = body.size - secStart

        if (toLibrePGP) {
            if (region != BC_REGION) return null // already LibrePGP (or unexpected)
            // BC: usage(0) condLen(0) count(4) material(96) cksum(2)  -> drop condLen + cksum
            val o = ByteArrayOutputStream()
            o.write(body, 0, secStart)                 // public portion
            o.write(0)                                 // usage 0
            o.write(body, secStart + 2, 4 + MATERIAL_LEN)  // count(4) + material(96)
            return o.toByteArray()
        } else {
            if (region != LIBREPGP_REGION) return null // already BC (or unexpected)
            // LibrePGP: usage(0) count(4) material(96)  -> insert condLen(0), append cksum(2)
            val matStart = secStart + 1 + 4
            var sum = 0
            for (k in 0 until MATERIAL_LEN) sum = (sum + (body[matStart + k].toInt() and 0xFF)) and 0xFFFF
            val o = ByteArrayOutputStream()
            o.write(body, 0, secStart)                 // public portion
            o.write(0)                                 // usage 0
            o.write(0)                                 // condLen 0 (BC requires it for v5)
            o.write(body, secStart + 1, 4 + MATERIAL_LEN)  // count(4) + material(96)
            o.write((sum ushr 8) and 0xFF)             // 2-octet checksum
            o.write(sum and 0xFF)
            return o.toByteArray()
        }
    }

    private class Header(val tag: Int, val bodyStart: Int, val bodyLen: Int)

    private fun header(data: ByteArray, start: Int): Header? {
        if (start >= data.size) return null
        var i = start
        val c = data[i++].toInt() and 0xFF
        if (c and 0x80 == 0) return null
        val tag: Int
        val length: Int
        if (c and 0x40 != 0) {
            tag = c and 0x3F
            val l0 = data[i++].toInt() and 0xFF
            length = when {
                l0 < 192 -> l0
                l0 < 224 -> ((l0 - 192) shl 8) + (data[i++].toInt() and 0xFF) + 192
                l0 == 255 -> uint32(data, i).also { i += 4 }
                else -> return null // partial length not expected in key material
            }
        } else {
            tag = (c shr 2) and 0x0F
            length = when (c and 0x03) {
                0 -> data[i++].toInt() and 0xFF
                1 -> (((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)).also { i += 2 }
                2 -> uint32(data, i).also { i += 4 }
                else -> data.size - i
            }
        }
        if (i + length > data.size) return null
        return Header(tag, i, length)
    }

    private fun newFormatHeader(tag: Int, bodyLen: Int): ByteArray = when {
        bodyLen < 192 -> byteArrayOf((0xC0 or tag).toByte(), bodyLen.toByte())
        bodyLen < 8384 -> {
            val l = bodyLen - 192
            byteArrayOf((0xC0 or tag).toByte(), (0xC0 or (l shr 8)).toByte(), (l and 0xFF).toByte())
        }
        else -> byteArrayOf((0xC0 or tag).toByte(), 0xFF.toByte()) + uint32Bytes(bodyLen)
    }

    private fun uint32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    private fun uint32Bytes(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
}
