// CompositeBrainpoolInteropTest.kt
// PGPony Android - issue #2 (gpg -> PGPony interop for the brainpool composite)
//
// Two-phase manual round-trip that verifies the brainpoolP384r1 composite
// against a real gpg 2.5.x, the one check the inline self-tests cannot do:
//
//   Phase 1 (emit): PGPony generates an Ed25519 key whose ONLY encryption
//     subkey is a brainpoolP384r1 ML-KEM-1024 composite (the classical Cv25519
//     subkey is stripped from the exported cert so gpg has no other target),
//     and writes the public cert + BC secret ring to ~/pgpony-interop/.
//
//   Phase 2 (decrypt): after gpg imports the cert and encrypts a message to it,
//     PGPony reads the secret ring back and decrypts. A correct plaintext proves
//     gpg accepted our brainpool key AND that our decapsulation matches gpg's.
//
// Gated on -DrunInterop=true; phase 2 self-skips until the gpg message exists.
// Phase 1 is idempotent so re-running does not regenerate the key mid-flow.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

class CompositeBrainpoolInteropTest {

    private val svc = PGPCryptoService.shared
    private val dir = File(System.getProperty("user.home"), "pgpony-interop")
    private val pubFile = File(dir, "pgpony-bp-pub.asc")
    private val secFile = File(dir, "pgpony-bp-sec.bin")
    private val msgFile = File(dir, "gpg-to-pgpony-bp.asc")
    private val marker = "PGPony brainpool interop OK"

    @Before
    fun requireInteropFlag() {
        assumeTrue(
            "manual interop test: run with -DrunInterop=true",
            System.getProperty("runInterop") == "true"
        )
    }

    @Test
    fun `emit a PGPony brainpool composite keypair for gpg`() {
        if (pubFile.exists() && secFile.exists()) {
            println("[bp-interop] reusing existing key at ${pubFile.absolutePath}")
            return
        }
        dir.mkdirs()
        val base = svc.generateKeyPair(
            "PGPony BP", "bp-interop@test.local", KeyAlgorithm.ED25519_CV25519, passphrase = null
        )
        val baseRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(base.privateKeyData)),
            JcaKeyFingerprintCalculator()
        )
        val ring = CompositeKeyGen.addCompositeSubkey(
            baseRing, CompositeSuite.LIBREPGP_1024_BP384, passphrase = null
        )
        var pubRing = CompositeKeyGen.publicRingOf(ring)
        pubRing.publicKeys.asSequence()
            .filter { !it.isMasterKey && it.algorithm == 18 }  // classical Cv25519 ECDH
            .toList()
            .forEach { pubRing = PGPPublicKeyRing.removePublicKey(pubRing, it) }
        pubFile.writeText(svc.exportArmoredPublicKey(pubRing))
        secFile.writeBytes(ring.encoded)
        println("[bp-interop] wrote ${pubFile.absolutePath}")
        println("[bp-interop] wrote ${secFile.absolutePath}")
        println("[bp-interop] now run gpg 2.5.x: import the cert and encrypt to bp-interop@test.local")
    }

    @Test
    fun `decrypt a gpg-encrypted brainpool message`() {
        assumeTrue(
            "run emit + the gpg encrypt step first (no ${msgFile.name} yet)",
            msgFile.exists() && secFile.exists()
        )
        val secRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(secFile.readBytes())),
            JcaKeyFingerprintCalculator()
        )
        val result = svc.decrypt(msgFile.readBytes(), listOf(secRing), passphrase = null)
        val text = result.data.decodeToString().trim()
        println("[bp-interop] decrypted plaintext: '$text'")
        assertEquals(marker, text)
    }
}
