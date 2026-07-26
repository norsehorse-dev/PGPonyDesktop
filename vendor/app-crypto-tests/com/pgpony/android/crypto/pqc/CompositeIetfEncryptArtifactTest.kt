// CompositeIetfEncryptArtifactTest.kt
// PGPony Android — 4.0.0 Phase 2b (leftovers: external PGPony -> sq check)
//
// Writes a PGPony-encrypted IETF composite (algo 35) message addressed to
// the draft-ietf-openpgp-pqc Appendix-A sample key, so a PQC-capable
// external implementation can decrypt it. The offline round-trip already
// proves our encrypt; this artifact is the *external* confirmation.
//
// Validate with sequoia-sq 1.4.0-pqc.1:
//   sq decrypt --recipient-file <path-to>/rfc9580-pqc-sample-key.asc \
//       $TMPDIR/pgpony-ietf-out.asc
// Expected plaintext: "ietf interop test"

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

class CompositeIetfEncryptArtifactTest {

    private fun res(name: String): ByteArray? =
        javaClass.getResourceAsStream("/pqc/$name")?.use { it.readBytes() }

    @Test
    fun `writes a composite message for external sq validation`() {
        val sk = res("rfc9580-pqc-sample-key.asc")
        assumeTrue("pqc/rfc9580-pqc-sample-key.asc absent", sk != null)

        val sec = PGPSecretKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(sk!!)), JcaKeyFingerprintCalculator())
        val pubRing = PGPPublicKeyRing(sec.publicKeys.asSequence().toList())

        val armored = PGPCryptoService.shared.encrypt("ietf interop test".toByteArray(), listOf(pubRing))

        // Structural self-check: leads with a v6 / algo-35 PKESK.
        val bin = ArmoredInputStream(ByteArrayInputStream(armored)).use { it.readBytes() }
        assertEquals("PKESK tag", 1, (bin[0].toInt() and 0x3F))
        var i = 1
        val l0 = bin[i++].toInt() and 0xFF
        when { l0 < 192 -> {}; l0 < 224 -> i += 1; l0 == 255 -> i += 4 }
        assertEquals("PKESK version", 6, bin[i].toInt() and 0xFF)
        // body: ver(1) | count(1) | keyVer(1) | fp(32) | algo → algo at +35
        assertEquals("PKESK algo", 35, bin[i + 35].toInt() and 0xFF)

        val out = File(File(System.getProperty("user.home"), "pgpony-interop").apply { mkdirs() }, "pgpony-ietf-out.asc")
        out.writeBytes(armored)
        println("[ietf] wrote ${out.absolutePath} — validate: sq decrypt --recipient-file rfc9580-pqc-sample-key.asc ${out.absolutePath}")
        assertTrue(out.length() > 0)
    }
}
