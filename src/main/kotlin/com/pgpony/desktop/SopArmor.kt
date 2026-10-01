// SopArmor.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5a: SOP armor and dearmor, and the packet helpers the
// SOP commands share (splitting a packet stream, reading a signature's creation time, issuer and
// type without BouncyCastle, which cannot parse composite ML-DSA signatures).

package com.pgpony.desktop

import com.pgpony.android.crypto.pqc.CompositeSigPacket
import org.bouncycastle.bcpg.ArmoredInputStream
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.Date

internal object SopArmor {

    const val SIGNATURE = "SIGNATURE"
    const val MESSAGE = "MESSAGE"
    const val PUBLIC_KEY = "PUBLIC KEY BLOCK"
    const val PRIVATE_KEY = "PRIVATE KEY BLOCK"

    fun isArmored(data: ByteArray): Boolean =
        String(data, 0, minOf(data.size, 2048), Charsets.ISO_8859_1).trimStart().startsWith("-----BEGIN PGP ")

    fun armor(label: String, bytes: ByteArray): ByteArray =
        CompositeSigPacket.armor("-----BEGIN PGP $label-----", "-----END PGP $label-----", bytes).toByteArray(Charsets.UTF_8)

    /** [bytes] as the caller asked: armored with [label], or binary. */
    fun output(bytes: ByteArray, label: String, noArmor: Boolean): ByteArray = if (noArmor) bytes else armor(label, bytes)

    /** Binary packets from armored or binary input. Cleartext-signed input is not armor. */
    fun binary(data: ByteArray): ByteArray {
        if (!isArmored(data)) return data
        val head = String(data, 0, minOf(data.size, 2048), Charsets.ISO_8859_1)
        if (head.contains("-----BEGIN PGP SIGNED MESSAGE-----")) {
            throw SopException(SopExit.BAD_DATA, "a cleartext signed message is not armored data")
        }
        return try {
            ArmoredInputStream(ByteArrayInputStream(data)).use { it.readAllBytes() }
        } catch (e: Exception) {
            throw SopException(SopExit.BAD_DATA, "bad armor: ${e.message}")
        }
    }

    /** The armor label for a packet stream, from its first packet's tag. */
    fun labelFor(binary: ByteArray): String = when (SopPackets.split(binary).firstOrNull()?.first) {
        5 -> PRIVATE_KEY
        6 -> PUBLIC_KEY
        2 -> SIGNATURE
        null -> throw SopException(SopExit.BAD_DATA, "no OpenPGP packets")
        else -> MESSAGE
    }

    fun armor(rest: List<String>, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(rest, emptySet(), emptySet())
        if (a.positionals.isNotEmpty()) throw SopException(SopExit.UNSUPPORTED_OPTION, "armor takes no arguments")
        val data = stdin.readBytes()
        // Armoring armored data is a no-op (spec).
        if (isArmored(data)) {
            out.write(data)
            return SopExit.OK
        }
        out.write(armor(labelFor(data), data))
        return SopExit.OK
    }

    fun dearmor(rest: List<String>, stdin: InputStream, out: OutputStream): Int {
        val a = SopArgs(rest, emptySet(), emptySet())
        if (a.positionals.isNotEmpty()) throw SopException(SopExit.UNSUPPORTED_OPTION, "dearmor takes no arguments")
        val data = binary(stdin.readBytes())
        if (SopPackets.split(data).isEmpty()) throw SopException(SopExit.BAD_DATA, "no OpenPGP packets")
        out.write(data)
        return SopExit.OK
    }
}

internal object SopPackets {

    /** (tag, whole packet with its header) for each packet in [raw]. Stops at malformed input. */
    fun split(raw: ByteArray): List<Pair<Int, ByteArray>> {
        val out = mutableListOf<Pair<Int, ByteArray>>()
        var i = 0
        while (i < raw.size) {
            val start = i
            val c = raw[i++].toInt() and 0xFF
            if (c and 0x80 == 0) break
            val tag: Int
            var len: Long
            if (c and 0x40 != 0) {
                tag = c and 0x3F
                if (i >= raw.size) break
                val l0 = raw[i++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0.toLong()
                    l0 < 224 -> {
                        if (i >= raw.size) break
                        (((l0 - 192) shl 8) + (raw[i++].toInt() and 0xFF) + 192).toLong()
                    }
                    l0 == 255 -> {
                        if (i + 4 > raw.size) break
                        (be32(raw, i).toLong() and 0xFFFFFFFFL).also { i += 4 }
                    }
                    else -> break // partial lengths only appear in data packets; stop here
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> { if (i >= raw.size) break; (raw[i++].toInt() and 0xFF).toLong() }
                    1 -> { if (i + 2 > raw.size) break; (((raw[i].toInt() and 0xFF) shl 8) or (raw[i + 1].toInt() and 0xFF)).toLong().also { i += 2 } }
                    2 -> { if (i + 4 > raw.size) break; (be32(raw, i).toLong() and 0xFFFFFFFFL).also { i += 4 } }
                    else -> (raw.size - i).toLong()
                }
            }
            if (i + len > raw.size) break
            val end = (i + len).toInt()
            out += tag to raw.copyOfRange(start, end)
            i = end
        }
        return out
    }

    fun be32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    /** The signature packets in [raw], whole. */
    fun signatures(raw: ByteArray): List<ByteArray> = split(raw).filter { it.first == 2 }.map { it.second }
}

/** What a v4 or v6 signature packet says about itself. */
internal data class SopSigInfo(
    val version: Int,
    val type: Int,
    val pkAlgo: Int,
    val hashAlgo: Int,
    val created: Date?,
    val issuerFingerprint: String?,
    val issuerKeyId: Long?
) {
    val isText: Boolean get() = type == 0x01

    companion object {
        fun parse(packet: ByteArray): SopSigInfo? = runCatching { parseOrNull(packet) }.getOrNull()

        private fun parseOrNull(packet: ByteArray): SopSigInfo? {
            val (tag, body) = CompositeSigPacket.firstPacket(packet)
            if (tag != 2) return null
            val version = body[0].toInt() and 0xFF
            if (version != 4 && version != 6) return null
            val type = body[1].toInt() and 0xFF
            val pk = body[2].toInt() and 0xFF
            val hash = body[3].toInt() and 0xFF
            var p = 4
            fun area(): ByteArray {
                val n = if (version == 6) SopPackets.be32(body, p).also { p += 4 }
                else (((body[p].toInt() and 0xFF) shl 8) or (body[p + 1].toInt() and 0xFF)).also { p += 2 }
                return body.copyOfRange(p, p + n).also { p += n }
            }
            val hashed = area()
            val unhashed = area()
            var created: Date? = null
            var issuerFp: String? = null
            var issuerId: Long? = null
            // The creation time counts only from the hashed area, which the signature covers; the
            // issuer subpackets are hints for which key to try and may sit in either area.
            for ((kind, data) in subpackets(hashed)) {
                if (kind == 2 && created == null && data.size >= 4) {
                    created = Date((SopPackets.be32(data, 0).toLong() and 0xFFFFFFFFL) * 1000)
                }
            }
            for ((kind, data) in subpackets(hashed) + subpackets(unhashed)) {
                when (kind) {
                    33 -> if (issuerFp == null && data.size > 1) issuerFp = data.copyOfRange(1, data.size).joinToString("") { "%02X".format(it) }
                    16 -> if (issuerId == null && data.size == 8) issuerId = data.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
                }
            }
            return SopSigInfo(version, type, pk, hash, created, issuerFp, issuerId)
        }

        private fun subpackets(area: ByteArray): List<Pair<Int, ByteArray>> {
            val out = mutableListOf<Pair<Int, ByteArray>>()
            var p = 0
            while (p < area.size) {
                val l0 = area[p++].toInt() and 0xFF
                val len = when {
                    l0 < 192 -> l0
                    l0 < 255 -> ((l0 - 192) shl 8) + (area[p++].toInt() and 0xFF) + 192
                    else -> SopPackets.be32(area, p).also { p += 4 }
                }
                if (len < 1 || p + len > area.size) break
                out += (area[p].toInt() and 0x7F) to area.copyOfRange(p + 1, p + len)
                p += len
            }
            return out
        }
    }
}
