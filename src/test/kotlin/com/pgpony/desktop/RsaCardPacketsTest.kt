// RsaCardPacketsTest.kt
// D20 validation — the RSA on-card packet building (RsaCardPackets), the byte-exact half of
// DesktopCardKeygen. A software RSA key stands in for the card (Java NONEwithRSA does exactly the
// PKCS#1 pad + private op over a DigestInfo that the card's PSO:CDS does), the whole transferable
// public key is assembled, and Bouncy Castle parses it back and verifies BOTH self-signatures
// and the fingerprint. This is the same proof run against real gpg while the feature landed
// (gpg imported it, matched the fingerprint, and validated the sigs); BC lets the suite pin it
// with no external tool. The card's algorithm-attribute bytes and the generate step are the only
// parts left for the hardware matrix (§8).

package com.pgpony.desktop

import com.pgpony.android.crypto.card.CardKeyPacketBuilder
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RsaCardPacketsTest {

    private fun beBytes(b: BigInteger): ByteArray {
        val a = b.toByteArray()
        return if (a.size > 1 && a[0].toInt() == 0) a.copyOfRange(1, a.size) else a
    }

    /** Assemble an RSA card key from two software RSA keys and return (binary, primaryFingerprint). */
    private fun assemble(bits: Int = 2048): Pair<ByteArray, ByteArray> {
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }
        val primary = kpg.generateKeyPair()
        val subkey = kpg.generateKeyPair()
        val pPub = primary.public as RSAPublicKey
        val sPub = subkey.public as RSAPublicKey
        val pPriv = primary.private as RSAPrivateKey

        val creation = 1_700_000_000L
        val primaryBody = RsaCardPackets.buildRsaPublicKeyBody(creation, beBytes(pPub.modulus), beBytes(pPub.publicExponent))
        val subkeyBody = RsaCardPackets.buildRsaPublicKeyBody(creation, beBytes(sPub.modulus), beBytes(sPub.publicExponent))
        val fp = CardKeyPacketBuilder.fingerprint(primaryBody)
        val keyId = CardKeyPacketBuilder.keyId(fp)

        val sign: (ByteArray) -> ByteArray = { di ->
            Signature.getInstance("NONEwithRSA").apply { initSign(pPriv); update(di) }.sign()
        }
        val binary = RsaCardPackets.assembleTransferableKey(
            creation, "RSA Card Test", "rsa@pgpony.app", null, primaryBody, subkeyBody, keyId, sign
        )
        return binary to fp
    }

    @Test
    fun theAssembledKeyParsesWithTheExpectedStructureAndFingerprint() {
        val (binary, fp) = assemble()
        val ring = PGPPublicKeyRing(binary, BcKeyFingerprintCalculator())
        val primary = ring.publicKey

        assertTrue(primary.isMasterKey, "first key is the primary")
        assertTrue(primary.algorithm == 1, "primary is RSA (algo 1), got ${primary.algorithm}")
        assertEquals(2048, primary.bitStrength)
        assertTrue(primary.fingerprint.contentEquals(fp), "BC computes the same fingerprint we did")

        val sub = ring.publicKeys.asSequence().first { !it.isMasterKey }
        assertTrue(sub.algorithm == 1, "subkey is RSA")
        assertTrue(primary.userIDs.hasNext(), "the user ID packet survived")
    }

    @Test
    fun theCertificationSelfSignatureVerifies() {
        val (binary, _) = assemble()
        val ring = PGPPublicKeyRing(binary, BcKeyFingerprintCalculator())
        val primary = ring.publicKey
        val uid = primary.userIDs.next()
        val sig = primary.getSignaturesForID(uid).next()
        sig.init(BcPGPContentVerifierBuilderProvider(), primary)
        assertTrue(sig.verifyCertification(uid, primary), "the card-made certification must verify")
    }

    @Test
    fun theSubkeyBindingSelfSignatureVerifies() {
        val (binary, _) = assemble()
        val ring = PGPPublicKeyRing(binary, BcKeyFingerprintCalculator())
        val primary = ring.publicKey
        val sub = ring.publicKeys.asSequence().first { !it.isMasterKey }
        val bind = sub.signatures.asSequence().first()
        bind.init(BcPGPContentVerifierBuilderProvider(), primary)
        assertTrue(bind.verifyCertification(primary, sub), "the subkey binding must verify")
    }

    @Test
    fun algorithmAttributesEncodeModulusAndExponentSizes() {
        // 01 || modulus-bits(BE) || exp-bits(0x0020) || format(0x00).
        assertTrue(RsaCardPackets.rsaAttributes(2048).contentEquals(byteArrayOf(0x01, 0x08, 0x00, 0x00, 0x20, 0x00)))
        assertTrue(RsaCardPackets.rsaAttributes(4096).contentEquals(byteArrayOf(0x01, 0x10, 0x00, 0x00, 0x20, 0x00)))
    }

    @Test
    fun mpiStripsLeadingZeroesAndEncodesTheBitLength() {
        // 0x00FF → 8 bits, value FF (leading zero dropped).
        assertTrue(RsaCardPackets.mpi(byteArrayOf(0x00, 0xFF.toByte())).contentEquals(byteArrayOf(0, 8, 0xFF.toByte())))
        // 0x0100 → 9 bits.
        assertTrue(RsaCardPackets.mpi(byteArrayOf(0x01, 0x00)).contentEquals(byteArrayOf(0, 9, 0x01, 0x00)))
    }
}
