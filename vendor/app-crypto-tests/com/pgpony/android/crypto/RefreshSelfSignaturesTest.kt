// RefreshSelfSignaturesTest.kt
// PGPony Android 4.7.0 (item 51, #86): a key whose User ID certifications and subkey bindings
// use SHA-1 after the Feb 2023 cutoff keeps its User IDs with a weak-hash mark and loses those
// subkeys when stored. Refresh self-signatures re-signs them with SHA-256, each keeping its
// expiry, and brings back a subkey left out only for its hash when its secret is held.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class RefreshSelfSignaturesTest {

    private val day = 86_400L
    private val nowS = System.currentTimeMillis() / 1000L
    private val created = nowS - 400 * day
    private val uid = "Weak <weak@pgpony.test>"

    private fun ed() = BcPGPKeyPair(
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(),
        Date(created * 1000L)
    )

    private fun x() = BcPGPKeyPair(
        PublicKeyAlgorithmTags.ECDH,
        X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(),
        Date(created * 1000L)
    )

    private fun sub(flags: Int, expiry: Long?) = PGPSignatureSubpacketGenerator().apply {
        setKeyFlags(false, flags)
        if (expiry != null) setKeyExpirationTime(false, expiry)
    }.generate()

    /** Everything self-signed with SHA-1 now: User ID, an encryption subkey expiring in 600 days,
     *  one that expired 100 days ago, and a signing subkey (SHA-1 back-signature too). */
    private fun weakKey(): PGPKeyRingGenerator {
        val primary = ed()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, uid,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA) }.generate(),
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA1), null
        )
        gen.addSubKey(x(), sub(KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE, 1000 * day), null)
        gen.addSubKey(x(), sub(KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE, 300 * day), null)
        val signing = ed()
        gen.addSubKey(
            signing, sub(KeyFlags.SIGN_DATA, null), null,
            BcPGPContentSignerBuilder(signing.publicKey.algorithm, HashAlgorithmTags.SHA1)
        )
        return gen
    }

    private fun stored(ring: PGPPublicKeyRing) = PGPPublicKeyRing(CertificateBindings.sanitized(ring.encoded), org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator())
    private fun subkeys(ring: PGPPublicKeyRing) = ring.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
    private fun expiresAt(k: PGPPublicKey): Long? = k.validSeconds.takeIf { it > 0 }?.let { k.creationTime.time / 1000L + it }
    private fun newestBinding(k: PGPPublicKey) = k.signatures.asSequence()
        .filter { it.signatureType == PGPSignature.SUBKEY_BINDING }.maxByOrNull { it.creationTime }!!

    @Test
    fun `refresh brings back weak-hash subkeys and re-signs everything with SHA-256`() {
        val gen = weakKey()
        val secret = gen.generateSecretKeyRing()
        val public = gen.generatePublicKeyRing()
        val before = stored(public)
        assertEquals("the weak subkeys are dropped when stored", 0, subkeys(before).size)
        assertTrue(uid in (CertificateBindings.analyze(before.encoded)?.weakUserIds ?: emptySet<String>()))

        val out = KeyExpirationService.shared.refreshSelfSignatures(secret, before, null)
        assertEquals(3, out.restoredSubkeys.size)
        val after = stored(out.rings.publicRing)
        val subs = subkeys(after)
        assertEquals("the subkeys survive storage now", 3, subs.size)
        assertTrue((CertificateBindings.analyze(after.encoded)?.weakUserIds ?: emptySet<String>()).isEmpty())

        val original = subkeys(public).associateBy { it.keyID }
        for (s in subs) {
            val b = newestBinding(s)
            assertEquals(HashAlgorithmTags.SHA256, b.hashAlgorithm)
            b.init(BcPGPContentVerifierBuilderProvider(), after.publicKey)
            assertTrue(b.verifyCertification(after.publicKey, s))
            assertEquals("expiry kept", expiresAt(original.getValue(s.keyID)), expiresAt(s))
        }
        val expired = subs.first { expiresAt(it)?.let { e -> e < nowS } == true }
        assertNotNull(expired)
        val signing = subs.first { (newestBinding(it).hashedSubPackets.keyFlags and KeyFlags.SIGN_DATA) != 0 }
        val back = newestBinding(signing).hashedSubPackets.embeddedSignatures[0]
        assertEquals(HashAlgorithmTags.SHA256, back.hashAlgorithm)
        back.init(BcPGPContentVerifierBuilderProvider(), signing)
        assertTrue(back.verifyCertification(after.publicKey, signing))
        assertNull(expiresAt(after.publicKey))
    }

    @Test
    fun `a subkey whose secret is not held is not brought back`() {
        val gen = weakKey()
        val public = gen.generatePublicKeyRing()
        val secret = gen.generateSecretKeyRing()
        val primaryOnly = org.bouncycastle.openpgp.PGPSecretKeyRing(listOf(secret.secretKey))
        val out = KeyExpirationService.shared.refreshSelfSignatures(primaryOnly, stored(public), null)
        assertTrue(out.restoredSubkeys.isEmpty())
        assertEquals(0, subkeys(stored(out.rings.publicRing)).size)
    }
}
