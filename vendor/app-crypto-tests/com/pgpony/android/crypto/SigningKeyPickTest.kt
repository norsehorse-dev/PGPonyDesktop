// SigningKeyPickTest.kt
// PGPony Android 4.7.0 (item 39, #83): which secret key makes a new
// signature. Fixtures in /signsub were made with GnuPG 2.2 and
// --faked-system-time (Oct 2026), without a passphrase:
//   expired-first  [C] primary; [S] 2020-01-02 expired 2021-01-01, then [S] 2026-01-01
//   renewed        [S] 2020-01-02 set to expire in 2021, renewed to never on 2020-06-01
//   revoked        [S] 2020-01-02, and [S] 2020-02-01 revoked on 2020-03-01
//   two-current    [S] 2025-01-02 and [S] 2025-07-01, neither expiring
//   all-expired    [C] primary, still valid; its only [S] expired 2021-01-01
//   whole-expired  [SC] primary expired 2020-12-31, [S] 2020-01-02
// Before item 39 the first Sign-capable subkey in ring order signed, expired
// or revoked or not. Also covers the back-signature a signing subkey added in
// PGPony now carries (ClassicalSubkeyGen).

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

class SigningKeyPickTest {

    private val svc = PGPCryptoService.shared
    private val data = "signed by the right subkey\n".toByteArray()

    private fun ring(name: String) = PGPSecretKeyRing(
        javaClass.getResourceAsStream("/signsub/$name")!!.use { it.readBytes() },
        JcaKeyFingerprintCalculator()
    )

    private fun day(sk: PGPSecretKey): String =
        SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).apply { timeZone = TimeZone.getTimeZone("UTC") }
            .format(sk.publicKey.creationTime)

    /** Key ID of the subkey of [r] created on [date] (yyyy-MM-dd, UTC). */
    private fun subkey(r: PGPSecretKeyRing, date: String): Long =
        r.secretKeys.asSequence().single { !it.publicKey.isMasterKey && day(it) == date }.keyID

    private fun signerOf(sig: ByteArray): Long =
        (JcaPGPObjectFactory(sig).nextObject() as PGPSignatureList)[0].keyID

    @Test
    fun `an expired subkey stored first is skipped for the current one`() {
        val r = ring("expired-first.pgp")
        assertEquals(subkey(r, "2026-01-01"), svc.pickSigningSecretKey(r)?.keyID)
        assertEquals(subkey(r, "2026-01-01"), signerOf(SigningService.shared.signDetached(data, r, armor = false)))
        assertEquals(listOf(subkey(r, "2026-01-01")), svc.signingKeyOptions(r).map { it.keyId })
    }

    @Test
    fun `a chosen subkey that has expired falls back to the automatic pick`() {
        val r = ring("expired-first.pgp")
        assertEquals(subkey(r, "2026-01-01"), svc.pickSigningSecretKey(r, subkey(r, "2020-01-02"))?.keyID)
    }

    @Test
    fun `a subkey renewed by a newer binding is current`() {
        val r = ring("renewed.pgp")
        assertEquals(subkey(r, "2020-01-02"), svc.pickSigningSecretKey(r)?.keyID)
    }

    @Test
    fun `a revoked subkey is never picked, even when it is the newest`() {
        val r = ring("revoked.pgp")
        assertEquals(subkey(r, "2020-01-02"), svc.pickSigningSecretKey(r)?.keyID)
        assertEquals(listOf(subkey(r, "2020-01-02")), svc.signingKeyOptions(r).map { it.keyId })
    }

    @Test
    fun `with two current subkeys the newer signs and both are offered`() {
        val r = ring("two-current.pgp")
        val newer = subkey(r, "2025-07-01")
        val older = subkey(r, "2025-01-02")
        assertEquals(newer, svc.pickSigningSecretKey(r)?.keyID)
        assertEquals(listOf(newer, older), svc.signingKeyOptions(r).map { it.keyId })
        assertEquals(older, svc.pickSigningSecretKey(r, older)?.keyID)
        assertEquals(older, signerOf(SigningService.shared.signDetached(data, r, armor = false, signingKeyId = older)))
    }

    @Test
    fun `a valid key whose signing subkeys all expired refuses with its own message`() {
        val r = ring("all-expired.pgp")
        assertNull(svc.pickSigningSecretKey(r))
        assertTrue(svc.noSigningKeyError(r) is SigningError.SigningKeysExpired)
        try {
            SigningService.shared.signDetached(data, r, armor = false)
            fail("expected SigningKeysExpired")
        } catch (e: SigningError.SigningKeysExpired) {
            assertEquals("Every signing key in this key pair has expired or been revoked", e.message)
        }
    }

    @Test
    fun `a wholly expired key still offers its keys for the Allow expired keys path`() {
        val r = ring("whole-expired.pgp")
        val pick = svc.pickSigningSecretKey(r)
        assertNotNull(pick)
        assertEquals(subkey(r, "2020-01-02"), pick!!.keyID)
        assertEquals(listOf(subkey(r, "2020-01-02"), r.publicKey.keyID), svc.signingKeyOptions(r).map { it.keyId })
    }

    @Test
    fun `a signing subkey added in PGPony is back-signed and becomes the signer`() {
        val pass = "correct horse battery staple"
        val base = svc.importKeyData(
            svc.generateKeyPair(
                name = "Adder",
                email = "add-sign@example.test",
                algorithm = KeyAlgorithm.ED25519_CV25519,
                passphrase = pass
            ).privateKeyData
        ).secretKeyRing!!
        val r = ClassicalSubkeyGen.addSubkey(base, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN, pass)
        val added = r.secretKeys.asSequence().single { base.getSecretKey(it.keyID) == null }
        val report = CertificateBindings.analyze(org.bouncycastle.openpgp.PGPPublicKeyRing(r.publicKeys.asSequence().toList()))!!
        assertTrue("the added subkey carries a verified back-signature", report.isValidSignerKey(SignerEvaluator.fpHex(added.publicKey)))
        assertEquals(added.keyID, svc.pickSigningSecretKey(r)?.keyID)
        assertEquals(added.keyID, signerOf(SigningService.shared.signDetached(data, r, pass, armor = false)))
    }
}
