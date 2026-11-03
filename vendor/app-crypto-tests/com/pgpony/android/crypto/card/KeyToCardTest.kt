// KeyToCardTest.kt
// PGPony Android, 4.7.0 RC4 (item 13, #71): the pure half of Move to
// Security Key. The import data layout follows the OpenPGP card 3.4 spec
// (4.4.3.12, Extended Header List) and gpg's scdaemon: 4D { CRT 00, 7F48
// {tag len ...}, 5F48 {values} }. Keys are made here with Bouncy Castle.

package com.pgpony.android.crypto.card

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

class KeyToCardTest {

    private val now = Date(System.currentTimeMillis() - 60_000)

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    @Test
    fun `BER lengths use one, two or three octets`() {
        assertEquals("7F", hex(KeyToCard.berLength(127)))
        assertEquals("8180", hex(KeyToCard.berLength(128)))
        assertEquals("81FF", hex(KeyToCard.berLength(255)))
        assertEquals("820100", hex(KeyToCard.berLength(256)))
        assertEquals("820405", hex(KeyToCard.berLength(1029)))
    }

    @Test
    fun `an EC import is 4D, the CRT, the template and the value`() {
        val secret = ByteArray(32) { (it + 1).toByte() }
        val ehl = KeyToCard.extendedHeaderList(CardSlot.DECRYPTION, KeyToCard.ecParts(secret.copyOf()))
        val expected = "4D2A" + "B800" + "7F48" + "02" + "9220" + "5F48" + "20" + hex(secret)
        assertEquals(expected, hex(ehl))
    }

    @Test
    fun `RSA 2048 standard and CRT parts have the card's lengths and values`() {
        val kp = RSAKeyPairGenerator().apply {
            init(RSAKeyGenerationParameters(BigInteger.valueOf(65537), SecureRandom(), 2048, 80))
        }.generateKeyPair()
        val pgp = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kp, now)
        val (e, p, q, d) = KeyToCard.rsaSecret(pgp.publicKey, pgp.privateKey)
        val std = KeyToCard.rsaParts(e, p, q, d, 2048, 17, KeyToCard.RSA_FORMAT_STANDARD)
        assertEquals(listOf(0x91, 0x92, 0x93), std.map { it.tag })
        assertEquals(listOf(3, 128, 128), std.map { it.value.size })
        assertEquals(BigInteger.valueOf(65537), BigInteger(1, std[0].value))
        assertEquals(p, BigInteger(1, std[1].value))
        val crt = KeyToCard.rsaParts(e, p, q, d, 2048, 17, KeyToCard.RSA_FORMAT_CRT)
        assertEquals(listOf(0x91, 0x92, 0x93, 0x94, 0x95, 0x96), crt.map { it.tag })
        val u = BigInteger(1, crt[3].value)
        assertEquals(BigInteger.ONE, u.multiply(q).mod(p))
        assertEquals(d.mod(p.subtract(BigInteger.ONE)), BigInteger(1, crt[4].value))
        assertEquals(d.mod(q.subtract(BigInteger.ONE)), BigInteger(1, crt[5].value))
        val withModulus = KeyToCard.rsaParts(e, p, q, d, 2048, 17, 0x01)
        assertEquals(p.multiply(q), BigInteger(1, withModulus.last().value))
        assertEquals(256, withModulus.last().value.size)
        val ehl = KeyToCard.extendedHeaderList(CardSlot.SIGNATURE, crt)
        assertEquals("4D82", hex(ehl.copyOfRange(0, 2)))
        assertEquals("B600", hex(ehl.copyOfRange(4, 6)))
        assertTrue(KeyToCard.eligibility(pgp.publicKey) == KeyToCard.Eligibility.Movable(KeyToCard.Kind.RSA, 2048))
    }

    @Test
    fun `RSA attributes are 01, n bits, e bits, format`() {
        assertEquals("010800001100", hex(KeyToCard.attributes(KeyToCard.Kind.RSA, 2048, 17, 0)))
        assertEquals("011000001102", hex(KeyToCard.attributes(KeyToCard.Kind.RSA, 4096, 17, 2)))
        assertEquals(2, KeyToCard.rsaFormatOf(KeyToCard.attributes(KeyToCard.Kind.RSA, 4096, 17, 2)))
        assertEquals(null, KeyToCard.rsaFormatOf(KeyToCard.attributes(KeyToCard.Kind.ED25519, 0, 0, 0)))
        assertEquals("162B06010401DA470F01", hex(KeyToCard.attributes(KeyToCard.Kind.ED25519, 0, 0, 0)))
        assertEquals("122B060104019755010501", hex(KeyToCard.attributes(KeyToCard.Kind.CV25519, 0, 0, 0)))
    }

    @Test
    fun `the Ed25519 seed and the X25519 scalar come out right`() {
        val ed = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
        val edPgp = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, ed, now)
        assertArrayEquals((ed.private as Ed25519PrivateKeyParameters).encoded, KeyToCard.ed25519Seed(edPgp.privateKey))
        assertTrue(KeyToCard.eligibility(edPgp.publicKey) == KeyToCard.Eligibility.Movable(KeyToCard.Kind.ED25519))

        val x = X25519KeyPairGenerator().apply { init(X25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
        val xPgp = BcPGPKeyPair(PublicKeyAlgorithmTags.ECDH, x, now)
        val native = KeyToCard.cv25519Secret(xPgp.privateKey, native = true)
        val stored = KeyToCard.cv25519Secret(xPgp.privateKey, native = false)
        // Bouncy Castle's own X25519 key is the native (RFC 7748) form.
        assertArrayEquals((x.private as X25519PrivateKeyParameters).encoded, native)
        assertArrayEquals(native.reversedArray(), stored)
        assertTrue(KeyToCard.eligibility(xPgp.publicKey) == KeyToCard.Eligibility.Movable(KeyToCard.Kind.CV25519))
    }

    @Test
    fun `attributes already on the slot are not written again`() {
        val ed = KeyToCard.attributes(KeyToCard.Kind.ED25519, 0, 0, 0)
        assertTrue(KeyToCard.sameAttributes(ed, ed))
        assertTrue(KeyToCard.sameAttributes(ed + byteArrayOf(0xFF.toByte()), ed))
        assertTrue(!KeyToCard.sameAttributes(null, ed))
        assertTrue(!KeyToCard.sameAttributes(KeyToCard.attributes(KeyToCard.Kind.CV25519, 0, 0, 0), ed))
        val rsa = KeyToCard.attributes(KeyToCard.Kind.RSA, 2048, 32, 0)
        assertTrue(!KeyToCard.sameAttributes(rsa + byteArrayOf(0), rsa))
        assertEquals(32, KeyToCard.rsaExponentBitsOf(rsa))
        assertEquals(null, KeyToCard.rsaExponentBitsOf(ed))
    }

    @Test
    fun `slots take the keys gpg would put there`() {
        assertTrue(KeyToCard.fitsSlot(KeyToCard.Kind.ED25519, CardSlot.SIGNATURE, false, false, false, primaryCanCertify = true))
        assertTrue(!KeyToCard.fitsSlot(KeyToCard.Kind.ED25519, CardSlot.SIGNATURE, false, false, false))
        assertTrue(KeyToCard.fitsSlot(KeyToCard.Kind.ED25519, CardSlot.SIGNATURE, true, false, false))
        assertTrue(!KeyToCard.fitsSlot(KeyToCard.Kind.ED25519, CardSlot.DECRYPTION, true, false, false))
        assertTrue(KeyToCard.fitsSlot(KeyToCard.Kind.CV25519, CardSlot.DECRYPTION, false, true, false))
        assertTrue(!KeyToCard.fitsSlot(KeyToCard.Kind.CV25519, CardSlot.AUTHENTICATION, false, false, true))
        assertTrue(KeyToCard.fitsSlot(KeyToCard.Kind.RSA, CardSlot.AUTHENTICATION, false, false, true))
        assertTrue(!KeyToCard.fitsSlot(KeyToCard.Kind.RSA, CardSlot.SIGNATURE, false, true, false))
    }

    @Test
    fun `a divert-to-card stub keeps the public key and reads back as a card stub`() {
        val ed = Ed25519KeyPairGenerator().apply { init(Ed25519KeyGenerationParameters(SecureRandom())) }.generateKeyPair()
        val pgp = BcPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, ed, now)
        val sk = PGPSecretKey(
            pgp.privateKey, pgp.publicKey, BcPGPDigestCalculatorProvider().get(org.bouncycastle.bcpg.HashAlgorithmTags.SHA1),
            true, null
        )
        val aid = KeyToCard.hexToBytes("D2760001240103040006123456780000")
        val stub = KeyToCard.divertToCardStub(sk, aid)
        val reread = PGPSecretKeyRing(stub.encoded, JcaKeyFingerprintCalculator()).secretKey
        assertArrayEquals(pgp.publicKey.fingerprint, reread.publicKey.fingerprint)
        assertEquals(org.bouncycastle.bcpg.S2K.GNU_DUMMY_S2K, reread.s2K.type)
        assertEquals(org.bouncycastle.bcpg.S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD, reread.s2K.protectionMode)
        assertEquals(SecretKeyPacket.USAGE_CHECKSUM, reread.s2KUsage)
        assertTrue(com.pgpony.android.crypto.OfflineStub.isCardStub(reread))
        assertTrue(com.pgpony.android.crypto.OfflineStub.isStub(reread))
    }
}
