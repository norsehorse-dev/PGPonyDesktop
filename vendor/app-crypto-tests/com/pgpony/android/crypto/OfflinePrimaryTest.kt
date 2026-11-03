// OfflinePrimaryTest.kt
// PGPony Android 4.7.0 (item 22): keys whose primary secret is not on the
// device. Fixtures in /stub were made with GnuPG 2.4 (Oct 2026):
//   rsa-c, ed-c    certify-only primary with [E] and [S] subkeys, exported
//                  with `gpg --export-secret-subkeys 'ENC!' 'SIGN!'` (GNU 1001)
//   rsa-sc, ed-sc  sign+certify primary with an [E] subkey only, same export
//   ed-c-stub-protected  ed-c with the subkeys under the passphrase pgpony-test
//   ed-c-cardstub  ed-c with the primary rewritten as a divert-to-card stub
//                  (GNU 1002 plus a made-up card serial)
//   ed-c-allcard   ed-c with every secret key a divert-to-card stub
//   *-msg          a message gpg encrypted to the key
// The edits that need the primary must refuse with the offline message
// instead of asking for a passphrase, signing must use the [S] subkey, and
// export, re-protection and passphrase change must keep the stub as it is.

package com.pgpony.android.crypto

import com.pgpony.android.data.RevocationReason
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class OfflinePrimaryTest {

    private val svc = PGPCryptoService.shared
    private val plaintext = "hello from an offline primary\n"

    private fun res(name: String): ByteArray =
        javaClass.getResourceAsStream("/stub/$name")!!.use { it.readBytes() }

    private fun ring(name: String) = PGPSecretKeyRing(res(name), JcaKeyFingerprintCalculator())

    private fun publicOf(ring: PGPSecretKeyRing) = PGPPublicKeyRing(ring.publicKeys.asSequence().toList())

    private fun armor(bytes: ByteArray): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(bytes) }
        return out.toString(Charsets.US_ASCII.name())
    }

    private fun deArmor(text: String): ByteArray =
        ArmoredInputStream(ByteArrayInputStream(text.toByteArray())).use { it.readBytes() }

    private val classic = listOf("rsa-c-stub.pgp", "ed-c-stub.pgp")
    private val certSign = listOf("rsa-sc-stub.pgp", "ed-sc-stub.pgp")

    private inline fun expectOffline(what: String, block: () -> Unit) {
        try {
            block()
            fail("$what: expected the offline-primary refusal")
        } catch (e: OfflinePrimaryException) {
            assertEquals(OfflineStub.EDIT_MESSAGE, e.message)
        }
    }

    @Test
    fun `stubs are recognized, offline and divert-to-card apart`() {
        for (name in classic + certSign + "ed-c-stub-protected.pgp") {
            val r = ring(name)
            assertEquals(name, OfflineStub.Kind.OFFLINE, OfflineStub.primaryKind(r))
            assertTrue("$name: subkeys carry material", r.secretKeys.asSequence().filter { !it.publicKey.isMasterKey }.none { OfflineStub.isStub(it) })
            assertFalse(name, OfflineStub.allStubs(r))
        }
        val card = ring("ed-c-cardstub.pgp")
        assertEquals(OfflineStub.Kind.CARD, OfflineStub.primaryKind(card))
        assertTrue(OfflineStub.isCardStub(card.secretKey))
        assertTrue(OfflineStub.allStubs(ring("ed-c-allcard.pgp")))
    }

    @Test
    fun `import reads an offline primary as a key pair and an all-stub block as a public key`() {
        for (name in classic + certSign) {
            val result = svc.importArmoredKey(armor(res(name)))
            assertTrue(name, result.hasPrivateKey)
            assertEquals(name, OfflineStub.Kind.OFFLINE, result.primaryStub)
        }
        assertEquals(OfflineStub.Kind.CARD, svc.importArmoredKey(armor(res("ed-c-cardstub.pgp"))).primaryStub)
        val all = svc.importArmoredKey(armor(res("ed-c-allcard.pgp")))
        assertFalse("nothing secret in an all-stub block", all.hasPrivateKey)
        assertNull(all.secretKeyRing)
        assertNotNull(all.publicKeyRing)
        assertEquals(3, all.publicKeyRing!!.publicKeys.asSequence().count())
    }

    @Test
    fun `signing uses the signing subkey and never offers the stub`() {
        for (name in classic + "ed-c-cardstub.pgp") {
            val r = ring(name)
            val picked = svc.pickSigningSecretKey(r)
            assertNotNull(name, picked)
            assertFalse("$name: the stub primary is never picked", picked!!.publicKey.isMasterKey)
            assertTrue(name, svc.signingKeyOptions(r).none { it.isPrimary })

            val signed = SigningService.shared.signClear("signed by $name", r)
            val verified = VerifyService.shared.verifyClearSigned(signed, listOf(publicOf(r)))
            assertTrue("$name: $verified", verified is VerificationResult.Verified)

            val enc = svc.encrypt(plaintext.toByteArray(), listOf(publicOf(r)), signingSecretKey = r)
            val dec = svc.decrypt(enc, listOf(r), null, verificationKeys = listOf(publicOf(r)))
            assertEquals(name, plaintext, String(dec.data))
            assertTrue("$name: encrypt-and-sign verifies", dec.signatureVerified)
        }
    }

    @Test
    fun `a key whose only signer is the stub primary says so`() {
        for (name in certSign) {
            val r = ring(name)
            assertNull(name, svc.pickSigningSecretKey(r))
            assertTrue(name, svc.signingKeyOptions(r).isEmpty())
            assertTrue(name, svc.noSigningKeyError(r) is SigningError.OfflinePrimary)
            try {
                SigningService.shared.signClear("x", r)
                fail("$name: signed with a stub")
            } catch (e: SigningError.OfflinePrimary) {
                assertEquals(OfflineStub.SIGN_MESSAGE, e.message)
            }
            try {
                svc.encrypt(plaintext.toByteArray(), listOf(publicOf(r)), signingSecretKey = r)
                fail("$name: encrypt-and-sign with a stub")
            } catch (e: SigningError.OfflinePrimary) {
            }
            // Encrypting without signing still works, and decrypts.
            val enc = svc.encrypt(plaintext.toByteArray(), listOf(publicOf(r)))
            assertEquals(name, plaintext, String(svc.decrypt(enc, listOf(r), null).data))
        }
    }

    @Test
    fun `messages gpg encrypted decrypt with the stub ring`() {
        assertEquals(plaintext, String(svc.decrypt(res("rsa-c-msg.pgp"), listOf(ring("rsa-c-stub.pgp")), null).data))
        assertEquals(plaintext, String(svc.decrypt(res("ed-c-msg.pgp"), listOf(ring("ed-c-stub.pgp")), null).data))
        val prot = ring("ed-c-stub-protected.pgp")
        assertEquals(plaintext, String(svc.decrypt(res("ed-c-msg.pgp"), listOf(prot), "pgpony-test").data))
        try {
            svc.decrypt(res("ed-c-msg.pgp"), listOf(prot), null)
            fail("a locked subkey must ask for its passphrase")
        } catch (e: PGPCryptoError.PassphraseRequired) {
        }
    }

    @Test
    fun `edits that need the primary refuse with the offline message`() {
        for (name in classic + certSign + "ed-c-cardstub.pgp") {
            val r = ring(name)
            val pub = publicOf(r)
            expectOffline("$name add User ID") {
                UserIdService.shared.addUserId(r, pub, "Added <added@example.org>", false, null)
            }
            expectOffline("$name expiry") {
                KeyExpirationService.shared.setExpirationSoftware(r, pub, null, null)
            }
            expectOffline("$name revoke") {
                RevocationService.shared.generateRevocationCertificate(r, RevocationReason.NO_REASON, null, null)
            }
            expectOffline("$name add subkey") {
                ClassicalSubkeyGen.addSubkey(r, ClassicalSubkeyGen.ClassicalSubkeyType.ED25519_SIGN, null)
            }
        }
    }

    @Test
    fun `export keeps the stub byte for byte`() {
        for (name in classic + certSign + "ed-c-stub-protected.pgp" + "ed-c-cardstub.pgp") {
            val raw = res(name)
            val exported = deArmor(svc.exportArmoredPrivateKey(ring(name)))
            val before = CertificateBindings.packets(raw).first()
            val after = CertificateBindings.packets(exported).first()
            assertEquals(name, before.tag, after.tag)
            assertArrayEquals("$name: the primary stub packet is unchanged", before.body, after.body)
            assertEquals(name, OfflineStub.primaryKind(ring(name)), OfflineStub.primaryKind(PGPSecretKeyRing(exported, JcaKeyFingerprintCalculator())))
        }
    }

    @Test
    fun `protection is read from the subkeys, not the stub`() {
        assertFalse(svc.isPassphraseProtected(ring("ed-c-stub.pgp")))
        assertTrue(svc.isPassphraseProtected(ring("ed-c-stub-protected.pgp")))
    }

    @Test
    fun `an export passphrase and a passphrase change leave the stub alone`() {
        val r = ring("ed-c-stub.pgp")
        val primaryBody = CertificateBindings.packets(res("ed-c-stub.pgp")).first().body

        val exported = PGPSecretKeyRing(
            deArmor(svc.exportArmoredPrivateKeyWithPassphrase(r, "export-pass")), JcaKeyFingerprintCalculator()
        )
        assertEquals(OfflineStub.Kind.OFFLINE, OfflineStub.primaryKind(exported))
        assertTrue(exported.secretKeys.asSequence().filter { !it.publicKey.isMasterKey }.all { it.s2KUsage != 0 })
        assertArrayEquals(primaryBody, CertificateBindings.packets(exported.encoded).first().body)
        assertEquals(plaintext, String(svc.decrypt(res("ed-c-msg.pgp"), listOf(exported), "export-pass").data))

        val changed = svc.changePassphrase(r, "", "new-pass")
        assertEquals(OfflineStub.Kind.OFFLINE, OfflineStub.primaryKind(changed))
        assertTrue(svc.isPassphraseProtected(changed))
        assertArrayEquals(primaryBody, CertificateBindings.packets(changed.encoded).first().body)
        assertEquals(plaintext, String(svc.decrypt(res("ed-c-msg.pgp"), listOf(changed), "new-pass").data))

        val stripped = svc.changePassphrase(ring("ed-c-stub-protected.pgp"), "pgpony-test", "")
        assertFalse(svc.isPassphraseProtected(stripped))
        assertEquals(plaintext, String(svc.decrypt(res("ed-c-msg.pgp"), listOf(stripped), null).data))
    }
}
