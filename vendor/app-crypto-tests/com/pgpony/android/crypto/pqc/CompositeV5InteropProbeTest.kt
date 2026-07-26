// CompositeV5InteropProbeTest.kt
// PGPony Android — 4.0.0 Phase 2b (v5 format parity probe)
//
// Diagnostic: does BouncyCastle parse the iOS / LibrePGP byte layout for an
// UNPROTECTED v5 composite (algo 8) secret key? Our keygen goes through BC,
// whose v5-usage-0 framing is  usage(0) | condLen(0) | count(4) | material |
// checksum(2)  — but iOS/gpg/sq emit  usage(0) | count(4) | material  (no
// condLen octet, no 2-octet checksum). This test generates an Android key,
// rewrites the composite subkey secret into the iOS layout, and prints
// whether BC accepts it. A rejection proves Android cannot import iOS/sq v5
// keys (and, symmetrically, that our v5 keys are off-spec).

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Test
import java.io.ByteArrayInputStream

class CompositeV5InteropProbeTest {

    private val svc = PGPCryptoService.shared
    private val calc = JcaKeyFingerprintCalculator()

    @Test
    fun `probe BC parsing of iOS-format v5 unprotected composite key`() {
        val base = svc.generateKeyPair("Probe", "probe@test.local", KeyAlgorithm.ED25519_CV25519, null)
        val secRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(base.privateKeyData)), calc
        )
        val android = CompositeKeyGen.addCompositeSubkey(secRing, CompositeKeyGen.Scheme.LIBREPGP_V5)
        val androidBytes = android.encoded

        // Sanity: BC round-trips its own format.
        val bcOwn = try { PGPSecretKeyRing(androidBytes, calc); "PARSED" }
        catch (e: Exception) { "REJECTED ${e.javaClass.simpleName}: ${e.message}" }
        println("[v5-probe] BC on Android(BC)-format: $bcOwn")

        val iosBytes = rewriteAlgo8SecretToIosLayout(androidBytes)
        val bcIos = try { PGPSecretKeyRing(iosBytes, calc); "PARSED" }
        catch (e: Exception) { "REJECTED ${e.javaClass.simpleName}: ${e.message}" }
        println("[v5-probe] BC on iOS/LibrePGP-format: $bcIos")
        println("[v5-probe] android secret region len vs ios: " +
            "${androidBytes.size} -> ${iosBytes.size} (expect -3)")
    }

    /**
     * Walk top-level packets; for the tag-7 v5/algo-8 secret subkey, rewrite
     * its body from the BC layout to the iOS layout:
     *   BC : ...pubMat | usage(0) | condLen(0) | count(4)=96 | mat(96) | cksum(2)
     *   iOS: ...pubMat | usage(0) |             count(4)=96 | mat(96)
     * i.e. drop the condLen octet and the trailing 2-octet checksum, then fix
     * the packet's new-format length header. All other packets pass through.
     */
    private fun rewriteAlgo8SecretToIosLayout(data: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < data.size) {
            val c = data[i].toInt() and 0xFF
            var j = i + 1
            val tag: Int
            val len: Int
            val newFormat = c and 0x40 != 0
            if (newFormat) {
                tag = c and 0x3F
                val l0 = data[j++].toInt() and 0xFF
                len = when {
                    l0 < 192 -> l0
                    l0 < 224 -> ((l0 - 192) shl 8) + (data[j++].toInt() and 0xFF) + 192
                    l0 == 255 -> uint32(data, j).also { j += 4 }
                    else -> error("partial length")
                }
            } else {
                tag = (c shr 2) and 0x0F
                len = when (c and 0x03) {
                    0 -> data[j++].toInt() and 0xFF
                    1 -> (((data[j].toInt() and 0xFF) shl 8) or (data[j + 1].toInt() and 0xFF)).also { j += 2 }
                    2 -> uint32(data, j).also { j += 4 }
                    else -> data.size - j
                }
            }
            val body = data.copyOfRange(j, j + len)
            if (tag == 7 && body.size > 10 && body[0].toInt() == 5 && (body[5].toInt() and 0xFF) == 8) {
                val pkm = uint32(body, 6)
                val secStart = 10 + pkm
                // usage octet
                val usage = body[secStart].toInt() and 0xFF
                if (usage == 0) {
                    val rebuilt = java.io.ByteArrayOutputStream()
                    rebuilt.write(body, 0, secStart)          // public portion
                    rebuilt.write(0)                          // usage 0
                    // BC body after usage: condLen(1) | count(4) | material | checksum(2)
                    // iOS wants:            count(4) | material
                    val count = uint32(body, secStart + 2)    // skip usage+condLen
                    rebuilt.write(uint32Bytes(count))
                    val matStart = secStart + 1 + 1 + 4
                    rebuilt.write(body, matStart, count)      // material only (no checksum)
                    // Emit tag-7 packet with a fresh new-format length header.
                    out.write(newFormatHeader(7, rebuilt.size()))
                    rebuilt.writeTo(out)
                    i = j + len
                    continue
                }
            }
            out.write(data, i, (j - i) + len) // pass packet through verbatim
            i = j + len
        }
        return out.toByteArray()
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
