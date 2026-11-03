// KeyExpirationTargetTest.kt
// PGPony Android 4.7.0 (item 53, #86): changing the primary key's expiry gave every subkey the
// same date, so a tester's expired subkeys came back to life. An edit now has a target: the
// primary (its live User IDs only, subkeys only when asked and only the ones valid now) or one
// subkey. Old self-signature subpackets are carried forward, and a revoked User ID stays revoked.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class KeyExpirationTargetTest {

    private val day = 86_400L
    private val nowS = System.currentTimeMillis() / 1000L
    private val created = nowS - 800 * day
    private val uid = "Target <target@pgpony.test>"
    private val oldUid = "Old <old@pgpony.test>"

    private fun ed(at: Long) = BcPGPKeyPair(
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(),
        Date(at * 1000L)
    )

    private fun x(at: Long) = BcPGPKeyPair(
        PublicKeyAlgorithmTags.ECDH,
        X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair(),
        Date(at * 1000L)
    )

    private class Key(val secret: PGPSecretKeyRing, val public: PGPPublicKeyRing)

    /** Primary [C,S] with no expiry and features MDC + SEIPDv2; a current encryption subkey (no
     *  expiry); an encryption subkey that expired 70 days ago; a current signing subkey. */
    private fun key(): Key {
        val primary = ed(created)
        val hashed = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            setFeature(false, (Features.FEATURE_MODIFICATION_DETECTION.toInt() or Features.FEATURE_SEIPD_V2.toInt()).toByte())
            setPreferredHashAlgorithms(false, intArrayOf(HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA256))
            setSignatureCreationTime(false, Date(created * 1000L))
        }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, uid,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), hashed, null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256), null
        )
        fun sub(flags: Int, expiry: Long?) = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, flags)
            setSignatureCreationTime(false, Date(created * 1000L))
            if (expiry != null) setKeyExpirationTime(false, expiry)
        }.generate()
        gen.addSubKey(x(created), sub(KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE, null), null)
        gen.addSubKey(x(created), sub(KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE, 730 * day), null)
        val signing = ed(created)
        gen.addSubKey(
            signing, sub(KeyFlags.SIGN_DATA, null), null,
            BcPGPContentSignerBuilder(signing.publicKey.algorithm, HashAlgorithmTags.SHA256)
        )
        val sec = gen.generateSecretKeyRing()
        return Key(sec, gen.generatePublicKeyRing())
    }

    private fun subkeys(ring: PGPPublicKeyRing) = ring.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
    private fun expiresAt(k: PGPPublicKey): Long? = k.validSeconds.takeIf { it > 0 }?.let { k.creationTime.time / 1000L + it }
    private fun newestBinding(k: PGPPublicKey) = k.signatures.asSequence()
        .filter { it.signatureType == PGPSignature.SUBKEY_BINDING }.maxByOrNull { it.creationTime }!!

    @Test
    fun `the primary's expiry leaves every subkey binding as it was`() {
        val k = key()
        val before = subkeys(k.public).map { newestBinding(it).encoded }
        val target = nowS + 365 * day
        val out = KeyExpirationService.shared.setExpirationSoftware(k.secret, k.public, target, null).publicRing
        assertEquals(target, expiresAt(out.publicKey))
        val after = subkeys(out).map { newestBinding(it).encoded }
        assertEquals(before.size, after.size)
        before.zip(after).forEach { (b, a) -> assertArrayEquals(b, a) }
    }

    @Test
    fun `also current subkeys never brings an expired subkey back`() {
        val k = key()
        val expired = subkeys(k.public)[1]
        val wasExpiry = expiresAt(expired)!!
        assertTrue(wasExpiry < nowS)
        val target = nowS + 365 * day
        val out = KeyExpirationService.shared.setExpirationSoftware(
            k.secret, k.public, target, null, KeyExpirationService.Target.Primary(currentSubkeys = true)
        ).publicRing
        val subs = subkeys(out)
        assertEquals(target, expiresAt(subs[0]))
        assertEquals(wasExpiry, expiresAt(subs[1]))
        assertEquals(target, expiresAt(subs[2]))
        val sign = newestBinding(subs[2])
        sign.init(BcPGPContentVerifierBuilderProvider(), out.publicKey)
        assertTrue(sign.verifyCertification(out.publicKey, subs[2]))
        val back = sign.hashedSubPackets.embeddedSignatures[0]
        back.init(BcPGPContentVerifierBuilderProvider(), subs[2])
        assertTrue(back.verifyCertification(out.publicKey, subs[2]))
    }

    @Test
    fun `a subkey target changes that subkey and nothing else`() {
        val k = key()
        val subs = subkeys(k.public)
        val primaryCert = k.public.publicKey.getSignaturesForID(uid).asSequence().toList().map { it.encoded }
        val target = nowS + 90 * day
        val out = KeyExpirationService.shared.setExpirationSoftware(
            k.secret, k.public, target, null, KeyExpirationService.Target.Subkey(subs[0].keyID)
        ).publicRing
        val outSubs = subkeys(out)
        assertEquals(target, expiresAt(outSubs[0]))
        assertArrayEquals(newestBinding(subs[1]).encoded, newestBinding(outSubs[1]).encoded)
        assertArrayEquals(newestBinding(subs[2]).encoded, newestBinding(outSubs[2]).encoded)
        val outCerts = out.publicKey.getSignaturesForID(uid).asSequence().toList().map { it.encoded }
        assertEquals(primaryCert.size, outCerts.size)
        primaryCert.zip(outCerts).forEach { (b, a) -> assertArrayEquals(b, a) }
        val binding = newestBinding(outSubs[0])
        binding.init(BcPGPContentVerifierBuilderProvider(), out.publicKey)
        assertTrue(binding.verifyCertification(out.publicKey, outSubs[0]))
        assertEquals(
            KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE,
            binding.hashedSubPackets.keyFlags
        )
    }

    @Test
    fun `the new self-certification keeps features and preferences`() {
        val k = key()
        val out = KeyExpirationService.shared.setExpirationSoftware(k.secret, k.public, nowS + 365 * day, null).publicRing
        val cert = out.publicKey.getSignaturesForID(uid).asSequence()
            .filter { it.signatureType == PGPSignature.POSITIVE_CERTIFICATION }.maxByOrNull { it.creationTime }!!
        val features = cert.hashedSubPackets.getSubpacket(SignatureSubpacketTags.FEATURES) as Features
        assertTrue(features.supportsFeature(Features.FEATURE_SEIPD_V2))
        assertEquals(listOf(HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA256), cert.hashedSubPackets.preferredHashAlgorithms.toList())
        assertEquals(KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA, cert.hashedSubPackets.keyFlags)
        assertEquals(1, cert.hashedSubPackets.getSubpackets(SignatureSubpacketTags.CREATION_TIME).size)
        cert.init(BcPGPContentVerifierBuilderProvider(), out.publicKey)
        assertTrue(cert.verifyCertification(uid, out.publicKey))
    }

    @Test
    fun `a revoked User ID stays revoked`() {
        val k = key()
        val priv = k.secret.secretKey.extractPrivateKey(null)
        var primary = k.public.publicKey
        fun sign(type: Int, at: Long): PGPSignature {
            val g = PGPSignatureGenerator(BcPGPContentSignerBuilder(primary.algorithm, HashAlgorithmTags.SHA256), primary)
            g.init(type, priv)
            g.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply { setSignatureCreationTime(false, Date(at * 1000L)) }.generate())
            return g.generateCertification(oldUid, primary)
        }
        primary = PGPPublicKey.addCertification(primary, oldUid, sign(PGPSignature.POSITIVE_CERTIFICATION, created + 10))
        primary = PGPPublicKey.addCertification(primary, oldUid, sign(PGPSignature.CERTIFICATION_REVOCATION, created + 20))
        val pub = PGPPublicKeyRing.insertPublicKey(k.public, primary)
        val sec = PGPSecretKeyRing.replacePublicKeys(k.secret, pub)
        assertTrue(UserIdService.shared.isRevoked(pub.publicKey, oldUid))
        val out = KeyExpirationService.shared.setExpirationSoftware(sec, pub, nowS + 365 * day, null).publicRing
        assertTrue(UserIdService.shared.isRevoked(out.publicKey, oldUid))
        assertTrue(!UserIdService.shared.isRevoked(out.publicKey, uid))
    }
}
