// CompositeIosInteropTest.kt
// PGPony Android — 4.0.0 Phase 2b (iOS <-> Android composite cross-import)
//
// Manual, file-driven cross-import checks for LibrePGP (algo 8) composite
// keys between PGPony-iOS and PGPony-Android, run against ~/pgpony-interop/.
// Each test self-skips until its input file exists.
//
//   Direction A (iOS -> Android): iOS imports our pgpony-lp-pub.asc, encrypts
//     a message to it, and you save the armored output as ios-to-android.asc.
//     `decrypt...` reads our secret (pgpony-lp-sec.bin from the emit step) and
//     decrypts it — proving iOS accepts an Android-generated composite key AND
//     iOS's composite encrypt is Android-decryptable.
//
//   Direction B (Android -> iOS): iOS generates a composite key and exports
//     its public cert as ios-pub.asc. `encrypt...` imports it and writes
//     android-to-ios.asc for you to decrypt in iOS — proving Android accepts
//     an iOS-generated composite key AND Android's composite encrypt is
//     iOS-decryptable.

package com.pgpony.android.crypto.pqc

import com.pgpony.android.crypto.PGPCryptoService
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.File

class CompositeIosInteropTest {

    private val svc = PGPCryptoService.shared
    private val dir = File(System.getProperty("user.home"), "pgpony-interop")
    private val marker = "PGPony iOS interop OK"

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

    // Direction A: iOS -> Android.
    @Test
    fun `decrypt an iOS-encrypted message to our composite key`() {
        val msg = File(dir, "ios-to-android.asc")
        val sec = File(dir, "pgpony-lp-sec.bin")
        assumeTrue("save iOS's message as ${msg.name} first", msg.exists() && sec.exists())
        val secRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(sec.readBytes())),
            JcaKeyFingerprintCalculator()
        )
        val result = svc.decrypt(msg.readBytes(), listOf(secRing), passphrase = null)
        println("[ios->android] decrypted: '${result.plaintext.trim()}'")
        // Encrypt exactly this marker in iOS so a green test == correct decrypt.
        assertEquals(marker, result.plaintext.trim())
    }

    // Direction B: Android -> iOS.
    @Test
    fun `encrypt to an iOS composite public key`() {
        val pub = File(dir, "ios-pub.asc")
        assumeTrue("export an iOS composite public key as ${pub.name} first", pub.exists())
        val imported = svc.importArmoredKey(pub.readText())
        val pubRing = imported.publicKeyRing!!
        println("[android->ios] imported iOS key ${imported.fingerprint}, algo=${imported.algorithm}")
        val out = File(dir, "android-to-ios.asc")
        out.writeBytes(svc.encrypt(marker.toByteArray(), listOf(pubRing)))
        println("[android->ios] wrote ${out.absolutePath} — decrypt this in iOS (expect: '$marker')")
        assertTrue(out.length() > 0)
    }

    // Secret-key portability: import an iOS-generated composite SECRET key
    // (LibrePGP wire format) through importArmoredKey — exercising the
    // LibrePGPV5Interop shim on a genuinely foreign secret — then prove the
    // recovered secret works via a full encrypt->decrypt round-trip. Pass the
    // iOS key's passphrase via -DiosSecPass=... (omit for a passwordless key).
    @Test
    fun `import and use an iOS composite secret key`() {
        val sec = File(dir, "ios-sec.asc")
        assumeTrue("export an iOS composite secret as ${sec.name} first", sec.exists())
        // Passphrase for a protected iOS key: prefer a file (survives Gradle's
        // forked test JVM, which -D system properties do NOT reach), else -D.
        val passFile = File(dir, "ios-sec-pass.txt")
        val pass = if (passFile.exists()) passFile.readText().trimEnd('\n', '\r').ifEmpty { null }
                   else System.getProperty("iosSecPass")?.ifEmpty { null }
        val imported = svc.importArmoredKey(sec.readText())
        assumeTrue("ios-sec.asc carries no private key", imported.hasPrivateKey)
        val secRing = imported.secretKeyRing!!
        val pubRing = imported.publicKeyRing!!
        println("[ios-sec->android] imported ${imported.fingerprint} algo=${imported.algorithm}")
        val pt = "ios secret import OK".toByteArray()
        val enc = svc.encrypt(pt, listOf(pubRing))
        val result = svc.decrypt(enc, listOf(secRing), passphrase = pass)
        assertEquals("ios secret import OK", result.plaintext.trim())
    }
}
