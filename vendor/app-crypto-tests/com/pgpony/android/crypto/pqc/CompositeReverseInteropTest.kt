// CompositeReverseInteropTest.kt
// PGPony Android — 4.0.0 Phase 2b (reverse interop: gpg -> PGPony, LibrePGP)
//
// Two-phase, manual round-trip that closes the gpg -> PGPony direction for a
// LibrePGP (algo 8) composite key WITHOUT needing to load gpg's proprietary
// s-expr secret into BouncyCastle:
//
//   Phase 1 (emitPgponyLibrePgpKeypair): PGPony generates its own algo-8
//     composite key and writes the PUBLIC cert + BC-format SECRET ring to
//     ~/pgpony-interop/. The user imports the public cert into gpg 2.5.x and
//     encrypts a message to it -> ~/pgpony-interop/gpg-to-pgpony-lp.asc.
//
//   Phase 2 (decryptGpgLibrePgpMessage): PGPony reads that secret ring back
//     and decrypts the gpg-produced message. A correct plaintext proves gpg
//     accepted our generated algo-8 public key (key-format interop) AND that
//     our decrypt path handles a genuinely foreign LibrePGP composite PKESK.
//
// Run phase 1, do the gpg step, then run phase 2 (separate gradle
// invocations). Phase 2 self-skips until the gpg message file exists.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

class CompositeReverseInteropTest {

    private val svc = PGPCryptoService.shared
    private val dir = File(System.getProperty("user.home"), "pgpony-interop")
    private val pubFile = File(dir, "pgpony-lp-pub.asc")
    private val secFile = File(dir, "pgpony-lp-sec.bin")
    private val msgFile = File(dir, "gpg-to-pgpony-lp.asc")
    private val marker = "PGPony reverse interop OK"

    // Manual interop harness: skipped in the normal suite (needs external
    // files + gpg/iOS steps, and some tests mutate shared fixtures). Run
    // explicitly with -DrunInterop=true.
    @Before
    fun requireInteropFlag() {
        assumeTrue(
            "manual interop test — run with -DrunInterop=true",
            System.getProperty("runInterop") == "true"
        )
    }

    @Test
    fun `emit a PGPony LibrePGP composite keypair for gpg`() {
        dir.mkdirs()
        val gen = svc.generateKeyPair(
            "PGPony Reverse", "reverse@test.local",
            KeyAlgorithm.MLKEM768_X25519_LIBREPGP, passphrase = null
        )
        pubFile.writeText(gen.armoredPublicKey)
        secFile.writeBytes(gen.privateKeyData)   // BC-format, re-parsed in phase 2
        println("[reverse] wrote ${pubFile.absolutePath}")
        println("[reverse] fingerprint ${gen.fingerprint}")
        println("[reverse] gpg step:")
        println("  gpg --import ${pubFile.absolutePath}")
        println("  echo -n '$marker' | gpg --trust-model always --encrypt " +
            "-r reverse@test.local --armor > ${msgFile.absolutePath}")
    }

    @Test
    fun `decrypt a gpg-encrypted LibrePGP message`() {
        assumeTrue(
            "run 'emit...' + the gpg encrypt step first (no ${msgFile.name} yet)",
            msgFile.exists() && secFile.exists()
        )
        val secRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(secFile.readBytes())),
            JcaKeyFingerprintCalculator()
        )
        val result = svc.decrypt(msgFile.readBytes(), listOf(secRing), passphrase = null)
        println("[reverse] decrypted plaintext: '${result.plaintext.trim()}'")
        assertEquals(marker, result.plaintext.trim())
    }
}
