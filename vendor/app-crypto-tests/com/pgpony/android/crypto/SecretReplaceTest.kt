// SecretReplaceTest.kt
// PGPony Android, 4.7.0 (item 47, #78): a re-import of your own key pair
// whose secret keys are now under another passphrase (changed in gpg) can
// replace the stored ones. Keys are made here with Bouncy Castle: an Ed25519
// primary with an X25519 subkey, protected with one passphrase, then the
// same key re-protected with another.

package com.pgpony.android.crypto

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.bouncycastle.util.encoders.Hex
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import java.util.Date

class SecretReplaceTest {

    private val calc = BcPGPDigestCalculatorProvider()

    private fun encryptor(pass: String) =
        BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, calc.get(HashAlgorithmTags.SHA256))
            .build(pass.toCharArray())

    private fun decryptor(pass: String) = BcPBESecretKeyDecryptorBuilder(calc).build(pass.toCharArray())

    private fun generate(pass: String): PGPSecretKeyRing {
        val now = Date(System.currentTimeMillis() - 60_000)
        val sign = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
        val enc = X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
        val primary = BcPGPKeyPair(PublicKeyAlgorithmTags.Ed25519, sign, now)
        val sub = BcPGPKeyPair(PublicKeyAlgorithmTags.X25519, enc, now)
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, primary, "Test <test@example.org>",
            calc.get(HashAlgorithmTags.SHA1), null, null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
            encryptor(pass)
        )
        gen.addSubKey(sub)
        return gen.generateSecretKeyRing()
    }

    private fun reprotect(ring: PGPSecretKeyRing, old: String, new: String): PGPSecretKeyRing =
        PGPSecretKeyRing.copyWithNewPassword(ring, decryptor(old), encryptor(new))

    private fun fps(ring: PGPSecretKeyRing) =
        ring.secretKeys.asSequence().map { Hex.toHexString(it.publicKey.fingerprint).uppercase() }.toSet()

    private fun unlocks(ring: PGPSecretKeyRing, pass: String): Boolean =
        ring.secretKeys.asSequence().all {
            try { it.extractPrivateKey(decryptor(pass)) != null } catch (e: PGPException) { false }
        }

    @Test
    fun `a new passphrase makes every secret replaceable, and the replaced ring unlocks with it`() {
        val stored = generate("old passphrase")
        val incoming = reprotect(stored, "old passphrase", "new passphrase")
        val targets = SubkeyAdmission.replaceableSecrets(stored.encoded, incoming.encoded)
        assertEquals(fps(stored), targets)
        val certificate = PGPPublicKeyRing(stored.publicKeys.asSequence().toList())
        val (replaced, count) = SubkeyAdmission.replaceSecrets(stored, incoming, certificate, targets)
        assertEquals(2, count)
        assertTrue(unlocks(replaced, "new passphrase"))
        assertTrue(!unlocks(replaced, "old passphrase"))
        assertEquals(fps(stored), fps(replaced))
        assertEquals(
            Hex.toHexString(stored.publicKey.fingerprint),
            Hex.toHexString(replaced.publicKey.fingerprint)
        )
    }

    @Test
    fun `the same bytes are not replaceable`() {
        val stored = generate("pass")
        assertTrue(SubkeyAdmission.replaceableSecrets(stored.encoded, stored.encoded).isEmpty())
    }

    @Test
    fun `only the keys asked for are replaced`() {
        val stored = generate("old")
        val incoming = reprotect(stored, "old", "new")
        val subFp = Hex.toHexString(stored.secretKeys.asSequence().first { !it.publicKey.isMasterKey }.publicKey.fingerprint)
        val certificate = PGPPublicKeyRing(stored.publicKeys.asSequence().toList())
        val (replaced, count) = SubkeyAdmission.replaceSecrets(stored, incoming, certificate, setOf(subFp))
        assertEquals(1, count)
        val primary = replaced.secretKey
        val sub = replaced.secretKeys.asSequence().first { !it.publicKey.isMasterKey }
        assertTrue(primary.extractPrivateKey(decryptor("old")) != null)
        assertTrue(sub.extractPrivateKey(decryptor("new")) != null)
    }

    @Test
    fun `a different key's secrets are never replaceable`() {
        val stored = generate("pass")
        val other = generate("pass")
        assertTrue(SubkeyAdmission.replaceableSecrets(stored.encoded, other.encoded).isEmpty())
        val certificate = PGPPublicKeyRing(stored.publicKeys.asSequence().toList())
        assertEquals(0, SubkeyAdmission.replaceSecrets(stored, other, certificate, fps(other)).second)
    }
}
