// CertificationTest.kt
// PGPony Android 4.7.0 (item 31, #79): certifying other people's User IDs.
// Each level produces its signature type and verifies; a local-only
// certification carries Exportable = false and round-trips through its own
// storage format; expiry and revocation read back; v4 and v6 certify each
// other; an unknown or wrong issuer is reported as such; the certificate
// sanitizer keeps an exportable certification; an offline-primary key, a
// self-certification and a locked key without its passphrase are refused.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream

class CertificationTest {

    private val svc = PGPCryptoService.shared
    private val cs = CertificationService

    private fun gen(name: String, alg: KeyAlgorithm = KeyAlgorithm.ED25519_CV25519, pass: String? = null): Pair<PGPSecretKeyRing, PGPPublicKeyRing> {
        val g = svc.generateKeyPair(name, "${name.lowercase()}@example.test", alg, pass)
        return PGPSecretKeyRing(ByteArrayInputStream(g.privateKeyData), JcaKeyFingerprintCalculator()) to
            PGPPublicKeyRing(ByteArrayInputStream(g.publicKeyData), JcaKeyFingerprintCalculator())
    }

    private fun uid(ring: PGPPublicKeyRing): String = ring.publicKey.userIDs.next()

    private fun lookup(vararg keys: PGPPublicKey): (String?, Long) -> PGPPublicKey? = { fp, id ->
        keys.firstOrNull { k ->
            (fp != null && fp.equals(k.fingerprint.joinToString("") { "%02X".format(it) }, ignoreCase = true)) || k.keyID == id
        }
    }

    @Test
    fun `each level makes its signature type and verifies`() {
        val (alice, alicePub) = gen("Alice")
        val (_, bob) = gen("Bob")
        for (level in CertificationService.Level.entries) {
            val made = cs.certify(alice, null, bob, listOf(uid(bob)), level, null, exportable = true)
            assertEquals(1, made.size)
            assertEquals(level.sigType, made[0].signature.signatureType)
            assertTrue(cs.isExportable(made[0].signature))
            val certified = cs.withSignatures(bob, made)
            val rows = cs.certifications(certified, emptyList(), lookup(alicePub.publicKey))
            assertEquals(level.name, 1, rows.size)
            assertEquals(level, rows[0].level)
            assertEquals(CertificationService.Status.VERIFIED, rows[0].status)
            assertFalse(rows[0].revoked)
            assertTrue(rows[0].exportable)
        }
    }

    @Test
    fun `a local-only certification is marked non-exportable and stays out of the certificate`() {
        val (alice, alicePub) = gen("Alice")
        val (_, bob) = gen("Bob")
        val made = cs.certify(alice, null, bob, listOf(uid(bob)), CertificationService.Level.CASUAL, null, exportable = false)
        assertFalse(cs.isExportable(made[0].signature))
        val stored = cs.encodeLocal(made)
        val back = cs.decodeLocal(stored)
        assertEquals(1, back.size)
        assertEquals(uid(bob), back[0].userId)
        val rows = cs.certifications(bob, back, lookup(alicePub.publicKey))
        assertEquals(1, rows.size)
        assertFalse(rows[0].exportable)
        assertEquals(CertificationService.Status.VERIFIED, rows[0].status)
        // The certificate itself was never touched.
        assertTrue(cs.certifications(bob, emptyList(), lookup(alicePub.publicKey)).isEmpty())
        assertTrue(cs.decodeLocal(ByteArray(0)).isEmpty())
        assertTrue(cs.decodeLocal(byteArrayOf(0, 0, 0, 9, 1)).isEmpty())
    }

    @Test
    fun `expiry and revocation read back`() {
        val (alice, alicePub) = gen("Alice")
        val (_, bob) = gen("Bob")
        val year = 365L * 24 * 3600
        val made = cs.certify(alice, null, bob, listOf(uid(bob)), CertificationService.Level.POSITIVE, year, exportable = true)
        var certified = cs.withSignatures(bob, made)
        val row = cs.certifications(certified, emptyList(), lookup(alicePub.publicKey)).single()
        assertEquals(row.createdMs + year * 1000L, row.expiresMs)
        assertFalse(row.expiredAt(row.createdMs))
        assertTrue(row.expiredAt(row.createdMs + year * 1000L))
        val revocation = cs.revoke(alice, null, certified, uid(bob), java.util.Date(row.createdMs + 1000))
        assertEquals(PGPSignature.CERTIFICATION_REVOCATION, revocation.signature.signatureType)
        certified = cs.withSignatures(certified, listOf(revocation))
        assertTrue(cs.certifications(certified, emptyList(), lookup(alicePub.publicKey)).single().revoked)
    }

    @Test
    fun `v4 and v6 keys certify each other`() {
        val (v4, v4Pub) = gen("Four")
        val (v6, v6Pub) = gen("Six", KeyAlgorithm.V6_ED25519)
        for ((certifier, certifierPub, target) in listOf(Triple(v4, v4Pub, v6Pub), Triple(v6, v6Pub, v4Pub))) {
            val made = cs.certify(certifier, null, target, listOf(uid(target)), CertificationService.Level.NO_CLAIM, null, true)
            val rows = cs.certifications(cs.withSignatures(target, made), emptyList(), lookup(certifierPub.publicKey))
            assertEquals(CertificationService.Status.VERIFIED, rows.single().status)
        }
    }

    @Test
    fun `an unknown or wrong issuer is reported`() {
        val (alice, _) = gen("Alice")
        val (_, bob) = gen("Bob")
        val (_, carol) = gen("Carol")
        val certified = cs.withSignatures(bob, cs.certify(alice, null, bob, listOf(uid(bob)), CertificationService.Level.NO_CLAIM, null, true))
        assertEquals(CertificationService.Status.SIGNER_UNKNOWN, cs.certifications(certified, emptyList()) { _, _ -> null }.single().status)
        assertEquals(CertificationService.Status.FAILED, cs.certifications(certified, emptyList()) { _, _ -> carol.publicKey }.single().status)
    }

    @Test
    fun `the certificate sanitizer keeps an exportable certification`() {
        val (alice, alicePub) = gen("Alice")
        val (_, bob) = gen("Bob")
        val certified = cs.withSignatures(bob, cs.certify(alice, null, bob, listOf(uid(bob)), CertificationService.Level.NO_CLAIM, null, true))
        val clean = PGPPublicKeyRing(ByteArrayInputStream(CertificateBindings.sanitized(certified.encoded)), JcaKeyFingerprintCalculator())
        assertEquals(CertificationService.Status.VERIFIED, cs.certifications(clean, emptyList(), lookup(alicePub.publicKey)).single().status)
    }

    @Test
    fun `refusals`() {
        val (alice, alicePub) = gen("Alice")
        val (_, bob) = gen("Bob")
        try {
            cs.certify(alice, null, alicePub, listOf(uid(alicePub)), CertificationService.Level.NO_CLAIM, null, true)
            fail("certified itself")
        } catch (e: CertificationService.CertifyError) {
        }
        try {
            cs.certify(alice, null, bob, listOf("Nobody <nobody@example.test>"), CertificationService.Level.NO_CLAIM, null, true)
            fail("certified a User ID the key does not have")
        } catch (e: CertificationService.CertifyError) {
        }
        val stub = PGPSecretKeyRing(javaClass.getResourceAsStream("/stub/ed-c-stub.pgp")!!.readBytes(), JcaKeyFingerprintCalculator())
        assertFalse(cs.canCertify(stub))
        try {
            cs.certify(stub, null, bob, listOf(uid(bob)), CertificationService.Level.NO_CLAIM, null, true)
            fail("certified with an offline primary")
        } catch (e: OfflinePrimaryException) {
        }
        val (locked, _) = gen("Locked", pass = "pgpony-test")
        assertTrue(cs.canCertify(locked))
        try {
            cs.certify(locked, null, bob, listOf(uid(bob)), CertificationService.Level.NO_CLAIM, null, true)
            fail("certified with a locked key and no passphrase")
        } catch (e: PGPCryptoError.PassphraseRequired) {
        }
        assertNotNull(cs.certify(locked, "pgpony-test", bob, listOf(uid(bob)), CertificationService.Level.NO_CLAIM, null, true).single())
    }
}
