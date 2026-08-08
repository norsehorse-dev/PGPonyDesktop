// RevocationPreCacheTest.kt
// PGPony Android — 4.1.0 Phase 12a
//
// KeyRepository.generateKey pre-caches a revocation certificate at key
// creation, while the passphrase is still in scope, so a user who later loses
// that passphrase can still declare the key revoked. It has never worked.
//
// The pre-cache read importResult.secretKeyRing, where importResult came from
// crypto.importKeyData(result.publicKeyData). A public-only import cannot
// carry a secret ring, so the value was unconditionally null and every key
// generated since 4.0.3 stored a null certificate. Nothing looked broken
// because the revoke-from-UI flow generates fresh on demand; what was silently
// missing is the fallback for when the passphrase is gone.
//
// KeyRepository itself needs Room and SecureKeyStore and so is not reachable
// from a JVM test. What IS reachable, and what actually failed, is the parse:
// these tests pin the premise the fix depends on, in both directions, plus the
// full expression the pre-cache evaluates.
//
// V6 AND COMPOSITE EXPECTATION, as PLANNING_4_2_0.md §10.2 asked to have
// decided and written down:
//   • v4 (ED25519_CV25519) and v6 (V6_ED25519) are both generatable and both
//     must pre-cache. Covered below.
//   • The ML-KEM composites are import-only and are never produced by
//     generateKeyPair, so the pre-cache question does not arise for them. If
//     composite keygen is ever offered, add a case here rather than assuming
//     it inherits.

package com.pgpony.android.crypto

import com.pgpony.android.data.RevocationReason
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RevocationPreCacheTest {

    private val svc = PGPCryptoService.shared
    private val revocation = RevocationService.shared
    private val pass = "correct horse battery staple"

    private fun generate(algorithm: KeyAlgorithm, passphrase: String?) =
        svc.generateKeyPair(
            name = "Revoke Tester",
            email = "revoke@example.test",
            algorithm = algorithm,
            passphrase = passphrase
        )

    private fun assertLooksLikeArmoredCert(cert: String) {
        assertTrue("certificate must not be blank", cert.isNotBlank())
        assertTrue(
            "certificate must be ASCII-armored, got: ${cert.take(40)}",
            cert.trimStart().startsWith("-----BEGIN PGP")
        )
        assertTrue("certificate must be terminated", cert.contains("-----END PGP"))
    }

    // ── the premise, in both directions ──────────────────────────────────

    /**
     * THE BUG, stated as a test. This is what the pre-cache was reading, and
     * it is null every single time. If this ever starts returning a ring,
     * something about importKeyData has changed and the fix below should be
     * revisited rather than silently kept.
     */
    @Test
    fun publicKeyData_carriesNoSecretRing() {
        val r = generate(KeyAlgorithm.ED25519_CV25519, pass)
        assertNull(
            "a public-only import cannot carry a secret ring; reading it was the bug",
            svc.importKeyData(r.publicKeyData).secretKeyRing
        )
    }

    /** The fix: the same parse against the binary private material. */
    @Test
    fun privateKeyData_carriesTheSecretRing() {
        val r = generate(KeyAlgorithm.ED25519_CV25519, pass)
        assertNotNull(
            "the generated private key data must parse back to a secret ring",
            svc.importKeyData(r.privateKeyData).secretKeyRing
        )
    }

    // ── the whole expression the pre-cache evaluates ─────────────────────

    @Test
    fun revocationCertificate_generatesForPassphraseProtectedV4Key() {
        val r = generate(KeyAlgorithm.ED25519_CV25519, pass)
        val ring = svc.importKeyData(r.privateKeyData).secretKeyRing
        assertNotNull(ring)

        val cert = revocation.generateRevocationCertificate(
            secretKeyRing = ring!!,
            reason = RevocationReason.NO_REASON,
            comment = null,
            passphrase = pass
        )
        assertLooksLikeArmoredCert(cert)
    }

    /**
     * An unprotected key is the case where losing a passphrase cannot happen,
     * but the pre-cache still runs and must not throw.
     */
    @Test
    fun revocationCertificate_generatesForUnprotectedV4Key() {
        val r = generate(KeyAlgorithm.ED25519_CV25519, null)
        val ring = svc.importKeyData(r.privateKeyData).secretKeyRing
        assertNotNull(ring)

        val cert = revocation.generateRevocationCertificate(
            secretKeyRing = ring!!,
            reason = RevocationReason.NO_REASON,
            comment = null,
            passphrase = null
        )
        assertLooksLikeArmoredCert(cert)
    }

    /**
     * v6 is generatable as of V6-3 and takes the same path. Separate case
     * because the primary is a different key version and the revocation
     * signature is written over the primary key packet.
     */
    @Test
    fun revocationCertificate_generatesForV6Key() {
        val r = generate(KeyAlgorithm.V6_ED25519, pass)
        val ring = svc.importKeyData(r.privateKeyData).secretKeyRing
        assertNotNull("a generated v6 key must parse back to a secret ring", ring)

        val cert = revocation.generateRevocationCertificate(
            secretKeyRing = ring!!,
            reason = RevocationReason.NO_REASON,
            comment = null,
            passphrase = pass
        )
        assertLooksLikeArmoredCert(cert)
    }
}
