// LibrePGPV5InteropTest.kt
// PGPony Android — 4.0.0 Phase 2b (v5 LibrePGP export/import boundary shim)
//
// Proves the export/import wiring of LibrePGPV5Interop:
//
//   * exportArmoredPrivateKey emits the LibrePGP on-the-wire framing for a v5
//     composite (algo-8) subkey — BouncyCastle's internal condLen + checksum
//     octets are stripped, so the raw exported bytes are 3 octets shorter and
//     BC round-trips them only after re-normalization.
//   * importArmoredKey normalizes that wire framing back so BC can parse it,
//     and the reimported key still encrypts/decrypts (proving the material
//     survived the strip + re-insert unharmed).
//   * The transform is a byte-exact no-op for ordinary (non-composite) keys.
//   * toLibrePGPFormat / toBcFormat are idempotent.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class LibrePGPV5InteropTest {

    private val svc = PGPCryptoService.shared
    private val calc = JcaKeyFingerprintCalculator()

    private fun dearmor(armored: String): ByteArray {
        val armorIn = ArmoredInputStream(ByteArrayInputStream(armored.toByteArray()))
        val out = ByteArrayOutputStream()
        armorIn.copyTo(out)
        armorIn.close()
        return out.toByteArray()
    }

    private fun ringOf(privateKeyData: ByteArray): PGPSecretKeyRing =
        PGPSecretKeyRing(PGPUtil.getDecoderStream(ByteArrayInputStream(privateKeyData)), calc)

    @Test
    fun `LibrePGP v5 composite exports wire framing and re-imports for a full round-trip`() {
        val gen = svc.generateKeyPair(
            "Interop", "interop@test.local", KeyAlgorithm.MLKEM768_X25519_LIBREPGP, passphrase = null
        )
        val ring = ringOf(gen.privateKeyData)

        val armored = svc.exportArmoredPrivateKey(ring)
        val rawExported = dearmor(armored)

        // Exported bytes are the LibrePGP wire form: BC can't parse them until
        // toBcFormat re-inserts the condLen + 2-octet checksum (3 octets).
        val normalized = LibrePGPV5Interop.toBcFormat(rawExported)
        assertEquals(
            "normalization must re-add the 3 stripped octets",
            rawExported.size + 3, normalized.size
        )
        // Re-normalized bytes parse cleanly.
        PGPSecretKeyRing(ByteArrayInputStream(normalized), calc)

        // Import through the service (which normalizes internally).
        val imported = svc.importArmoredKey(armored)
        assertTrue("must import as a secret key", imported.hasPrivateKey)
        val sec = imported.secretKeyRing!!
        val pub = imported.publicKeyRing!!

        // Labeling survives the boundary trip.
        assertEquals(
            KeyAlgorithm.MLKEM768_X25519_LIBREPGP,
            svc.detectAlgorithm(pub.publicKey, pub)
        )

        // The decisive check: encrypt to the reimported public ring and decrypt
        // with the reimported secret ring. A single wrong octet in the composite
        // material would break the recovered session key.
        val pt = "librepgp export/import interop".toByteArray()
        val enc = svc.encrypt(pt, listOf(pub))
        assertArrayEquals(pt, svc.decrypt(enc, listOf(sec), passphrase = null).data)
    }

    @Test
    fun `transform is a no-op for an ordinary Ed25519 key`() {
        val gen = svc.generateKeyPair(
            "Plain", "plain@test.local", KeyAlgorithm.ED25519_CV25519, passphrase = null
        )
        val ring = ringOf(gen.privateKeyData)
        val encoded = ring.encoded

        assertArrayEquals(
            "toLibrePGPFormat must not touch a non-composite key",
            encoded, LibrePGPV5Interop.toLibrePGPFormat(encoded)
        )
        assertArrayEquals(
            "toBcFormat must not touch a non-composite key",
            encoded, LibrePGPV5Interop.toBcFormat(encoded)
        )

        // And a full export -> import -> round-trip still works.
        val armored = svc.exportArmoredPrivateKey(ring)
        val imported = svc.importArmoredKey(armored)
        assertTrue(imported.hasPrivateKey)
        val pt = "plain key export/import".toByteArray()
        val enc = svc.encrypt(pt, listOf(imported.publicKeyRing!!))
        assertArrayEquals(pt, svc.decrypt(enc, listOf(imported.secretKeyRing!!), passphrase = null).data)
    }

    @Test
    fun `toLibrePGPFormat and toBcFormat are idempotent`() {
        val gen = svc.generateKeyPair(
            "Idem", "idem@test.local", KeyAlgorithm.MLKEM768_X25519_LIBREPGP, passphrase = null
        )
        val bc = ringOf(gen.privateKeyData).encoded

        val wire = LibrePGPV5Interop.toLibrePGPFormat(bc)
        assertArrayEquals(
            "re-stripping an already-wire key is a no-op",
            wire, LibrePGPV5Interop.toLibrePGPFormat(wire)
        )

        val back = LibrePGPV5Interop.toBcFormat(wire)
        assertArrayEquals(
            "round-tripping wire -> BC restores the original BC bytes",
            bc, back
        )
        assertArrayEquals(
            "re-normalizing an already-BC key is a no-op",
            back, LibrePGPV5Interop.toBcFormat(back)
        )
    }
}
