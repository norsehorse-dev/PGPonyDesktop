// CardKdf.kt
// PGPony Android — HW Phase KDF
//
// OpenPGP-card KDF-DO (0x00F9) support: parsing the card's KDF parameters
// and deriving the S2K-hashed PIN the card expects when `kdf-setup` has
// been run against it (gpg --edit-card → admin → kdf-setup).
//
// WHY THIS EXISTS
//
// A card with KDF enabled does NOT store the PIN. It stores a salted,
// iterated hash of it, and every command that carries a PIN over the wire
// must carry that hash instead of the plain characters. Sending the plain
// PIN to a KDF-enabled card is simply a wrong PIN: the card answers
// 63CX and burns a retry, and whatever operation the PIN was meant to
// authorize then fails with 0x6982 (security status not satisfied).
// That is the failure mode reported against 4.0.3 — the card was fine,
// PGPony was sending the wrong bytes.
//
// The derivation is RFC 4880 §3.7.1.3 iterated-and-salted S2K, which is
// what libgcrypt's GCRY_KDF_ITERSALTED_S2K computes for GnuPG, so a PIN
// hashed here is byte-identical to what gpg sends for the same card.
//
// SPEC GOTCHA (worth the comment — it is a classic)
//
// The iteration count in KDF-DO field 0x83 is a PLAIN BIG-ENDIAN uint32:
// the literal number of octets to hash. It is NOT the RFC 4880 coded
// count octet used inside S2K packets, and it must not be run through
// the 16 + (c & 15) << ((c >> 4) + 6) expansion. gpg's default is
// 100000 (0x000186A0), which as a coded octet would decode to something
// entirely different.
//
// No Android dependencies — pure JVM, unit-testable without a device.

package com.pgpony.android.crypto.card

import java.security.MessageDigest

/**
 * Which PIN is being hashed. The card carries a separate salt per PIN, so
 * the same characters hash to different values depending on the role.
 */
enum class CardPinPurpose {
    /** PW1 — the user PIN (VERIFY 0x81 / 0x82, CHANGE REFERENCE DATA 0x81). */
    USER,

    /** The Reset Code (RESET RETRY COUNTER in P1 = 0x00 mode). */
    RESET_CODE,

    /** PW3 — the admin PIN (VERIFY 0x83, CHANGE REFERENCE DATA 0x83). */
    ADMIN
}

/**
 * Parsed contents of the card's KDF data object (0x00F9).
 *
 * [algorithm] 0x00 means the card is not using a KDF and PINs travel as
 * plain UTF-8 bytes; 0x03 means iterated-and-salted S2K.
 */
data class CardKdfParams(
    val algorithm: Int,
    val hashAlgorithm: Int,
    val iterationCount: Long,
    val userSalt: ByteArray?,
    val resetCodeSalt: ByteArray?,
    val adminSalt: ByteArray?
) {

    /** True when PINs must be S2K-hashed before they cross the wire. */
    val isEnabled: Boolean
        get() = algorithm == OpenPgpCard.KDF_ALGO_ITERATED_SALTED

    /**
     * The salt for [purpose].
     *
     * `gpg --edit-card → kdf-setup` writes three salts (0x84/0x85/0x86);
     * `kdf-setup single` writes only the PW1 salt and reuses it for every
     * PIN. Falling back to [userSalt] covers the single-salt card without
     * a separate code path.
     */
    fun saltFor(purpose: CardPinPurpose): ByteArray? = when (purpose) {
        CardPinPurpose.USER -> userSalt
        CardPinPurpose.RESET_CODE -> resetCodeSalt ?: userSalt
        CardPinPurpose.ADMIN -> adminSalt ?: userSalt
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CardKdfParams) return false
        return algorithm == other.algorithm &&
            hashAlgorithm == other.hashAlgorithm &&
            iterationCount == other.iterationCount &&
            (userSalt ?: ByteArray(0)).contentEquals(other.userSalt ?: ByteArray(0)) &&
            (resetCodeSalt ?: ByteArray(0)).contentEquals(other.resetCodeSalt ?: ByteArray(0)) &&
            (adminSalt ?: ByteArray(0)).contentEquals(other.adminSalt ?: ByteArray(0))
    }

    override fun hashCode(): Int {
        var result = algorithm
        result = 31 * result + hashAlgorithm
        result = 31 * result + iterationCount.hashCode()
        result = 31 * result + (userSalt?.contentHashCode() ?: 0)
        result = 31 * result + (resetCodeSalt?.contentHashCode() ?: 0)
        result = 31 * result + (adminSalt?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        /** The state of a card that has never had kdf-setup run on it. */
        val DISABLED = CardKdfParams(
            algorithm = OpenPgpCard.KDF_ALGO_NONE,
            hashAlgorithm = OpenPgpCard.HASH_SHA256,
            iterationCount = 0L,
            userSalt = null,
            resetCodeSalt = null,
            adminSalt = null
        )
    }
}

object CardKdf {

    /**
     * Parse the body of GET DATA 0x00F9.
     *
     * Returns [CardKdfParams.DISABLED] for an empty body or an explicit
     * algorithm 0x00 — both mean "send the plain PIN". Throws
     * [OpenPgpCardException.Malformed] when the card claims a KDF is in
     * force but the parameters are unusable, because guessing there would
     * silently burn the user's retry counter.
     */
    fun parse(raw: ByteArray): CardKdfParams {
        if (raw.isEmpty()) return CardKdfParams.DISABLED

        val fields = try {
            Tlv.parse(raw)
        } catch (e: TlvException) {
            throw OpenPgpCardException.Malformed("Could not parse the card's KDF data object: ${e.message}", e)
        }

        fun field(tag: Int): ByteArray? = fields.firstOrNull { it.tag == tag }?.value

        val algorithm = field(OpenPgpCard.KDF_TAG_ALGORITHM)
            ?.firstOrNull()?.toInt()?.and(0xFF)
            ?: OpenPgpCard.KDF_ALGO_NONE

        if (algorithm == OpenPgpCard.KDF_ALGO_NONE) return CardKdfParams.DISABLED

        if (algorithm != OpenPgpCard.KDF_ALGO_ITERATED_SALTED) {
            throw OpenPgpCardException.Malformed(
                "Card uses KDF algorithm 0x%02X, which PGPony does not support".format(algorithm)
            )
        }

        val hashAlgorithm = field(OpenPgpCard.KDF_TAG_HASH)
            ?.firstOrNull()?.toInt()?.and(0xFF)
            ?: throw OpenPgpCardException.Malformed("Card's KDF data object has no hash algorithm (0x82)")

        // 0x83 is a plain big-endian uint32 octet count — NOT an RFC 4880
        // coded count octet. See the file header.
        val countBytes = field(OpenPgpCard.KDF_TAG_ITERATIONS)
            ?: throw OpenPgpCardException.Malformed("Card's KDF data object has no iteration count (0x83)")
        if (countBytes.size != 4) {
            throw OpenPgpCardException.Malformed(
                "Card's KDF iteration count is ${countBytes.size} bytes; expected 4"
            )
        }
        var iterationCount = 0L
        for (b in countBytes) {
            iterationCount = (iterationCount shl 8) or (b.toLong() and 0xFF)
        }

        val userSalt = field(OpenPgpCard.KDF_TAG_SALT_PW1)
            ?: throw OpenPgpCardException.Malformed("Card's KDF data object has no PW1 salt (0x84)")

        return CardKdfParams(
            algorithm = algorithm,
            hashAlgorithm = hashAlgorithm,
            iterationCount = iterationCount,
            userSalt = userSalt,
            resetCodeSalt = field(OpenPgpCard.KDF_TAG_SALT_RESET_CODE),
            adminSalt = field(OpenPgpCard.KDF_TAG_SALT_PW3)
        )
    }

    /**
     * The bytes to place in the data field of a PIN-carrying command.
     *
     * When [params] is disabled this is [pin] unchanged (current 4.0.x
     * behavior, and correct for every card without kdf-setup). Otherwise
     * it is the S2K digest of the salt for [purpose] and [pin].
     */
    fun pinData(params: CardKdfParams, purpose: CardPinPurpose, pin: ByteArray): ByteArray {
        if (!params.isEnabled) return pin
        val salt = params.saltFor(purpose)
            ?: throw OpenPgpCardException.Malformed(
                "Card has a KDF configured but no salt for the ${purpose.name.lowercase()} PIN"
            )
        return derive(params.hashAlgorithm, salt, pin, params.iterationCount)
    }

    /**
     * RFC 4880 §3.7.1.3 iterated-and-salted S2K.
     *
     * `salt || passphrase` is fed into the digest repeatedly until exactly
     * [octetCount] octets have been consumed, truncating the final copy.
     * The single exception in the RFC: when [octetCount] is smaller than
     * one full `salt || passphrase`, the whole thing is hashed once anyway.
     * This matches libgcrypt's iterated_salted_s2k byte for byte, which is
     * what makes a PIN hashed here interchangeable with gpg's.
     */
    fun derive(hashAlgorithm: Int, salt: ByteArray, pin: ByteArray, octetCount: Long): ByteArray {
        val digest = MessageDigest.getInstance(jcaDigestName(hashAlgorithm))
        val block = salt + pin

        // The RFC's one exception: never hash less than a full salt||pin.
        var remaining = if (octetCount < block.size) block.size.toLong() else octetCount

        while (remaining > 0) {
            val n = minOf(remaining, block.size.toLong()).toInt()
            digest.update(block, 0, n)
            remaining -= n
        }
        return digest.digest()
    }

    /**
     * Map an OpenPGP hash-algorithm ID to its JCA name. The card spec
     * permits only SHA-256 and SHA-512 for the KDF, and a card that
     * announces anything else is rejected rather than guessed at — a
     * wrong digest here is indistinguishable from a wrong PIN and would
     * quietly consume the retry counter.
     */
    private fun jcaDigestName(hashAlgorithm: Int): String = when (hashAlgorithm) {
        OpenPgpCard.HASH_SHA256 -> "SHA-256"
        OpenPgpCard.HASH_SHA512 -> "SHA-512"
        else -> throw OpenPgpCardException.Malformed(
            "Card's KDF uses hash algorithm 0x%02X, which PGPony does not support".format(hashAlgorithm)
        )
    }
}
