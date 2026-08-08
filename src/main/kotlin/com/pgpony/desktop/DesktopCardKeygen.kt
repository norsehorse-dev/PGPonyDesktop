// DesktopCardKeygen.kt
// PGPony Desktop — D20 (2.0.0): RSA on-card key generation.
//
// DESKTOP-ONLY, by design. RSA keygen isn't wanted on mobile (a phone can't reasonably drive it),
// so this does NOT belong in the shared portable crypto (vendor/app-crypto). It lives here, a
// desktop twin, and reuses the vendored CARD PRIMITIVES (OpenPgpCardSession's APDU methods,
// CardKeyPacketBuilder's generic packet/subpacket helpers, CardSigningFormat's DigestInfo) while
// adding the RSA-specific packet building the vendored builder never had — its bodies and
// signature packets are hardcoded to EdDSA (algo 22).
//
// The vendored EdDSA path was ported from iOS and "verified against gpg byte-for-byte." There is
// no such reference port for RSA, so the bar is met a different way: [RsaCardPackets] is pure and
// signing is injected, which lets an offline test stand a SOFTWARE RSA key in for the card,
// assemble the transferable public key, and have real gpg import it — validating the self-
// signatures and (the byte-exact part) matching the fingerprint. Only the card's algorithm-
// attribute bytes and the generate step then need real hardware.
//
// The public-key BODY must be byte-exact (it feeds the v4 fingerprint); the self-signatures need
// only be cryptographically valid. MPIs are therefore canonical-minimal (leading zero bytes
// stripped), matching gpg's own encoding so the fingerprints agree.

package com.pgpony.desktop

import com.pgpony.android.crypto.card.CardKeyGenResult
import com.pgpony.android.crypto.card.CardKeyPacketBuilder
import com.pgpony.android.crypto.card.CardSigningFormat
import com.pgpony.android.crypto.card.CardSlot
import com.pgpony.android.crypto.card.OpenPgpCard
import com.pgpony.android.crypto.card.OpenPgpCardException
import com.pgpony.android.crypto.card.OpenPgpCardSession
import java.security.MessageDigest

object DesktopCardKeygen {

    /** RSA modulus sizes the card path offers. 4096 is card-dependent — a card may refuse it. */
    enum class RsaBits(val bits: Int) { RSA_2048(2048), RSA_4096(4096) }

    /**
     * Generate an RSA signing primary + RSA encryption subkey ON [session]'s card and return the
     * assembled, card-signed transferable PUBLIC key — the same [CardKeyGenResult] shape the
     * Ed25519 path returns, so the caller (importGeneratedCardKey) is unchanged. DESTRUCTIVE:
     * overwrites the signature + decryption slots. The private keys never leave the card and
     * cannot be backed up.
     *
     * One tap: PW3 (admin) to set attributes, generate, and write fingerprints + creation times;
     * then PW1 (signing) re-verified before EACH self-signature (cards reset PW1 after PSO:CDS).
     */
    fun generateRsaOnCard(
        session: OpenPgpCardSession,
        bits: RsaBits,
        name: String,
        email: String,
        expirationSeconds: Long?,
        adminPin: String,
        userPin: String
    ): CardKeyGenResult {
        val creationTime = System.currentTimeMillis() / 1000L
        val adminBytes = adminPin.toByteArray(Charsets.UTF_8)
        val userBytes = userPin.toByteArray(Charsets.UTF_8)
        val attrs = RsaCardPackets.rsaAttributes(bits.bits)

        session.select()

        // ── PW3 (admin): attributes, generate, fingerprints, creation times ──
        session.verify(OpenPgpCard.PW3_ADMIN, adminBytes)
        session.setAlgorithmAttributes(CardSlot.SIGNATURE, attrs)
        session.setAlgorithmAttributes(CardSlot.DECRYPTION, attrs)

        val signMaterial = session.generateKeyOnCard(CardSlot.SIGNATURE)
        val decMaterial = session.generateKeyOnCard(CardSlot.DECRYPTION)
        val signN = signMaterial.modulus ?: throw OpenPgpCardException.Malformed("Signature slot returned no RSA modulus")
        val signE = signMaterial.exponent ?: throw OpenPgpCardException.Malformed("Signature slot returned no RSA exponent")
        val decN = decMaterial.modulus ?: throw OpenPgpCardException.Malformed("Decryption slot returned no RSA modulus")
        val decE = decMaterial.exponent ?: throw OpenPgpCardException.Malformed("Decryption slot returned no RSA exponent")

        val primaryBody = RsaCardPackets.buildRsaPublicKeyBody(creationTime, signN, signE)
        val subkeyBody = RsaCardPackets.buildRsaPublicKeyBody(creationTime, decN, decE)
        val primaryFp = CardKeyPacketBuilder.fingerprint(primaryBody)
        val subkeyFp = CardKeyPacketBuilder.fingerprint(subkeyBody)
        val keyId = CardKeyPacketBuilder.keyId(primaryFp)

        session.writeFingerprint(CardSlot.SIGNATURE, primaryFp)
        session.writeFingerprint(CardSlot.DECRYPTION, subkeyFp)
        session.writeGenerationTime(CardSlot.SIGNATURE, creationTime)
        session.writeGenerationTime(CardSlot.DECRYPTION, creationTime)

        // ── PW1 (signing): the two card-produced RSA self-signatures ──
        // The card signs a DigestInfo (PKCS#1) for RSA; PW1 is re-verified before each PSO:CDS.
        val signDigestInfo: (ByteArray) -> ByteArray = { digestInfo ->
            session.verify(OpenPgpCard.PW1_SIGN, userBytes)
            session.signDigest(digestInfo)
        }

        val binary = RsaCardPackets.assembleTransferableKey(
            creationTime, name, email, expirationSeconds,
            primaryBody, subkeyBody, keyId, signDigestInfo
        )

        val cardInfo = session.readCardInfo()
        return CardKeyGenResult(
            publicKeyBinary = binary,
            cardInfo = cardInfo,
            primaryFingerprintHex = primaryFp.joinToString("") { "%02X".format(it) },
            subkeyFingerprintHex = subkeyFp.joinToString("") { "%02X".format(it) },
            creationTime = creationTime,
            keyId = keyId
        )
    }
}
