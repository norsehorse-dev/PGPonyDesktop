// CompositeGpgCompatExportTest.kt
// PGPony Android — issue #2 symptom D.
//
// Locks the gpg-native composite secret export (LibrePGPGnuSecretExport via
// PGPCryptoService.exportArmoredPrivateKeyGpgCompat). The structural test runs
// in CI with no gpg; the gated emit writes real keys for a manual gpg import.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

class CompositeGpgCompatExportTest {

    private val svc = PGPCryptoService.shared

    private fun ringOf(bytes: ByteArray) = PGPSecretKeyRing(
        PGPUtil.getDecoderStream(ByteArrayInputStream(bytes)), JcaKeyFingerprintCalculator())

    private fun dearmor(s: String): ByteArray =
        ArmoredInputStream(ByteArrayInputStream(s.toByteArray())).use { it.readBytes() }

    @Test
    fun `gpg-compat export rewrites the composite subkey to a GNU s-expression`() {
        val gen = svc.generateKeyPair("GC", "gc@test.local",
            KeyAlgorithm.MLKEM1024_X448_LIBREPGP, passphrase = null)
        val ring = ringOf(gen.privateKeyData)
        val bin = dearmor(svc.exportArmoredPrivateKeyGpgCompat(ring))

        // Walk to the composite subkey and assert the GNU/S-expression shape.
        var i = 0
        var sawComposite = false
        while (i < bin.size) {
            val c = bin[i].toInt() and 0xFF; var j = i + 1
            val tag: Int; val len: Int
            if (c and 0x40 != 0) {
                tag = c and 0x3f; val l0 = bin[j++].toInt() and 0xFF
                len = when { l0 < 192 -> l0; l0 < 224 -> ((l0-192) shl 8)+(bin[j++].toInt() and 0xFF)+192
                    l0 == 255 -> u32(bin, j).also { j += 4 }; else -> error("partial") }
            } else {
                tag = (c shr 2) and 0x0f
                len = when (c and 3) { 0 -> bin[j++].toInt() and 0xFF
                    1 -> (((bin[j].toInt() and 0xFF) shl 8) or (bin[j+1].toInt() and 0xFF)).also { j += 2 }
                    2 -> u32(bin, j).also { j += 4 }; else -> bin.size - j }
            }
            val b = bin.copyOfRange(j, j + len)
            if ((tag == 7 || tag == 5) && b.size > 6 && b[0].toInt() == 5 && b[5].toInt() == 8) {
                sawComposite = true
                val pkMatLen = u32(b, 6); val sec = 10 + pkMatLen
                val hdr = b.copyOfRange(sec, sec + 9)
                assertEquals("usage 255 (GNU)", 0xFF, hdr[0].toInt() and 0xFF)
                assertEquals("GNU marker 'G'", 0x47, hdr[5].toInt())
                assertEquals("GNU marker 'N'", 0x4E, hdr[6].toInt())
                assertEquals("GNU marker 'U'", 0x55, hdr[7].toInt())
                assertEquals("GNU mode 3", 0x03, hdr[8].toInt())
                val sexpLen = u32(b, sec + 9)
                val sexp = b.copyOfRange(sec + 13, sec + 13 + sexpLen).decodeToString()
                assertTrue("has composite-key", sexp.contains("composite-key"))
                assertTrue("has kyber1024", sexp.contains("kyber1024"))
                assertTrue("has curve X448", sexp.contains("4:X448"))
                assertTrue("full ML-KEM secret (3168)", sexp.contains("1:s3168:"))
            }
            i = j + len
        }
        assertTrue("composite subkey present", sawComposite)
    }

    @Test
    fun `emit gpg-compat keys for manual gpg import`() {
        assumeTrue("run with -DrunInterop=true", System.getProperty("runInterop") == "true")
        val dir = File(System.getProperty("user.home"), "pgpony-interop").apply { mkdirs() }

        val plain = svc.generateKeyPair("GC Plain", "gcplain@test.local",
            KeyAlgorithm.MLKEM1024_X448_LIBREPGP, passphrase = null)
        File(dir, "pgpony-x448-gpgcompat.asc")
            .writeText(svc.exportArmoredPrivateKeyGpgCompat(ringOf(plain.privateKeyData)))

        val prot = svc.generateKeyPair("GC Prot", "gcprot@test.local",
            KeyAlgorithm.MLKEM1024_X448_LIBREPGP, passphrase = "test")
        File(dir, "pgpony-x448-gpgcompat-fromprotected.asc")
            .writeText(svc.exportArmoredPrivateKeyGpgCompat(ringOf(prot.privateKeyData), "test"))

        val protd = svc.generateKeyPair("GC ProtOut", "gcprotout@test.local",
            KeyAlgorithm.MLKEM1024_X448_LIBREPGP, passphrase = "pw")
        File(dir, "pgpony-x448-gpgcompat-protected.asc")
            .writeText(svc.exportArmoredPrivateKeyGpgCompat(ringOf(protd.privateKeyData), "pw", "pw"))
        println("[gpgcompat] wrote pgpony-x448-gpgcompat.asc + -fromprotected.asc + -protected.asc")
    }

    @Test
    fun `OCB protection reproduces a real gpg 2_5_21 ciphertext`() {
        // Values captured from a real gpg 2.5.21 protected export (passphrase
        // "test"). If BouncyCastle's OCB, our S2K, AAD and plaintext framing all
        // match gpg, we reproduce its ciphertext exactly.
        val q = hex("98a8c81adc9cab97c95a024b81cc4afe3c5c76cd0bbcf1358f41ea6af6b4f9e1502e7a50ba48284dfcec343fffaf5b670cc4b0eb9cc6b736")
        val d = hex("435b9bc66f5cd95407f60d3455031d97f8e755db96e16b1f3ea09a3ae00762bc2633c79de531212bdbd845664f71eb738c0f42c0bd97728d")
        val salt = hex("bb421d43f91f46de")
        val nonce = hex("d5d6600f439112a1d45518e7")
        val ts = "20260820T042700".toByteArray()
        val expected = "ea88fb8a2f702d20a97796ea75edccc7275894f66ebe745b86da0a5af1e72678552644be35bb133c508a1a165945fd3c2efb06f40506e50ab3d749012c1266b8a1ac668bbbb407cae6ed770f7d37e6b2b8986820"
        val ct = LibrePGPGnuSecretExport.ocbProtectEccSecret(
            "test".toCharArray(), "X448", q, d, salt, nonce, 106521600, ts)
        assertEquals(expected, ct.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun `protected gpg-compat export protects the ecc key and leaves ML-KEM plaintext`() {
        val gen = svc.generateKeyPair("GCP", "gcp@test.local",
            KeyAlgorithm.MLKEM1024_X448_LIBREPGP, passphrase = "pw")
        val bin = dearmor(svc.exportArmoredPrivateKeyGpgCompat(ringOf(gen.privateKeyData), "pw", "pw"))
        val text = bin.decodeToString()
        assertTrue("protected-private-key", text.contains("protected-private-key"))
        assertTrue("openpgp-s2k3-ocb-aes", text.contains("openpgp-s2k3-ocb-aes"))
        assertTrue("protected-at", text.contains("protected-at"))
        assertTrue("ML-KEM secret stays plaintext", text.contains("1:s3168:"))
        assertTrue("no plaintext ecc d element", !text.contains("1:d56:"))
    }

    private fun hex(h: String): ByteArray =
        ByteArray(h.length / 2) { ((Character.digit(h[it*2],16) shl 4) or Character.digit(h[it*2+1],16)).toByte() }

    private fun u32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o+1].toInt() and 0xFF) shl 16) or
            ((b[o+2].toInt() and 0xFF) shl 8) or (b[o+3].toInt() and 0xFF)
}
