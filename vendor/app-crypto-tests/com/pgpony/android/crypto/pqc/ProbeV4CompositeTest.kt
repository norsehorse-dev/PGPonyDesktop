// ProbeV4CompositeTest.kt
// PGPony Android, 4.2.0 workstream A2 (RFC 9980 conformance)
//
// Diagnostic probe for the RC1 report of a FreePGP-generated
// ML-KEM-1024 + X448 key importing with no algorithm indicator while the
// ring displays as a plain v4 Ed25519+Cv25519 pair. The reporter's ring is
// v4-framed, and RFC 9980 §3.5 allows algo 35 on v4 encryption subkeys
// (algo 36 is v6-only), so the open question is what OUR BouncyCastle does
// with a v4-framed composite subkey: throw (import would fail), keep it
// opaquely (detect would label), or drop it silently (matches the report).
//
// Probe style mirrors CompositeV5InteropProbeTest: println the observed
// behavior; the single assertion is only that the ring round-trips at all.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class ProbeV4CompositeTest {

    private val svc = PGPCryptoService.shared
    private val calc = JcaKeyFingerprintCalculator()

    private fun uint32(v: Int) = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    /** New-format packet header + body, tag 14 (public subkey). */
    private fun packet(body: ByteArray): ByteArray {
        val hdr = when {
            body.size < 192 -> byteArrayOf((0xC0 or 14).toByte(), body.size.toByte())
            body.size < 8384 -> {
                val l = body.size - 192
                byteArrayOf((0xC0 or 14).toByte(), (0xC0 or (l shr 8)).toByte(), (l and 0xFF).toByte())
            }
            else -> byteArrayOf((0xC0 or 14).toByte(), 0xFF.toByte()) + uint32(body.size)
        }
        return hdr + body
    }

    /** v4 public-subkey packet body: ver(1)=4 | ctime(4) | algo(1) | material.
     *  v4 carries NO key-material length field, which is exactly why unknown
     *  algorithms are hazardous there. Material is deterministic junk of the
     *  correct composite length. */
    private fun v4CompositeBody(algo: Int, materialLen: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(4)
        out.write(uint32(0x66000000))
        out.write(algo)
        val material = ByteArray(materialLen) { (it * 7).toByte() }
        out.write(material)
        return out.toByteArray()
    }

    private fun probe(label: String, algo: Int, materialLen: Int) {
        val base = svc.generateKeyPair("Probe", "probe@test.local", KeyAlgorithm.ED25519_CV25519, null)
        val baseRing = PGPPublicKeyRing(ByteArrayInputStream(base.publicKeyData), calc)
        val grafted = ByteArrayOutputStream().apply {
            write(base.publicKeyData)
            write(packet(v4CompositeBody(algo, materialLen)))
        }.toByteArray()

        val parsed: PGPPublicKeyRing? = try {
            PGPPublicKeyRing(ByteArrayInputStream(grafted), calc)
        } catch (e: Exception) {
            println("[v4-probe] $label: ring parse THREW ${e.javaClass.simpleName}: ${e.message}")
            null
        }
        if (parsed != null) {
            val algos = parsed.publicKeys.asSequence().map { "${it.algorithm}(v${it.version})" }.toList()
            val baseCount = baseRing.publicKeys.asSequence().count()
            val count = parsed.publicKeys.asSequence().count()
            val verdict = when {
                count > baseCount -> "KEPT (opaque)"
                else -> "DROPPED silently"
            }
            println("[v4-probe] $label: parse OK, subkey $verdict; ring algos=$algos")
            println("[v4-probe] $label: detectAlgorithm -> " +
                svc.detectAlgorithm(parsed.publicKey, parsed))
        }
        assertNotNull(base.publicKeyData)
    }

    @Test
    fun `v4-framed algo 35 subkey, the RFC 9980 legal case`() =
        probe("algo35/v4 (1216)", 35, 1216)

    @Test
    fun `v4-framed algo 36 subkey, the reporter's shape if freepg emitted v4`() =
        probe("algo36/v4 (1624)", 36, 1624)

    @Test
    fun `v4-framed private-range algo 105, the early-freepg shape`() =
        probe("algo105/v4 (1624)", 105, 1624)
}
