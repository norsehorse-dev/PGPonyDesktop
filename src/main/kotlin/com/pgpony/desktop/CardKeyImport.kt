// CardKeyImport.kt
// PGPony Desktop — D21: move an existing SOFTWARE key onto the card ("keytocard").
//
// The counterpart to on-card generation. On-card keys can never be backed up (the secret is born
// in the chip); a user who wants a backup-able card key generates the key in SOFTWARE, backs up
// the secret, then imports it here. The secret then exists both in the backup and on the card —
// a deliberate, user-made trade (a key that lived off-card is only as safe as its backup).
//
// This file is the PURE, testable half: extracting the RSA components from a keyring secret key
// and building the OpenPGP-card key-import command (the Extended Header List, DO 4D). The card
// I/O lives in DesktopCardKeyImport. Desktop-only, so it does not touch the vendored crypto; the
// key-import APDU uses the odd PUT DATA instruction the vendored session's putData (even, 0xDA)
// can't send, so it goes through the raw CardTransport.
//
// WHAT CANNOT BE VERIFIED OFFLINE: whether the card accepts the import. There is no gpg-import
// equivalent as there was for keygen's public key. The tests here prove the Extended Header List
// is spec-shaped and the components reconstruct the public key; card acceptance is the hardware
// bar, and the import FORMAT (which components the card wants) is the knob to turn if a card
// refuses — see [RsaImportFormat].

package com.pgpony.desktop

import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter
import java.math.BigInteger

/** Which target slot on the card an imported key lands in (its Control Reference Template tag). */
enum class CardImportSlot(val crtTag: Int) {
    SIGNATURE(0xB6),
    DECRYPTION(0xB8),
    AUTHENTICATION(0xA4)
}

/**
 * The RSA import format: which private-key components the Extended Header List carries, and the
 * algorithm-attributes import-format byte that must match. Both formats include the modulus (n),
 * because a JavaCard OpenPGP applet (SmartPGP and its forks, e.g. Token2) cannot compute n from p
 * and q on-chip, so without it the card leaves the public key uninitialized and refuses the import.
 * `STANDARD` (0x01) sends e, p, q, n; `CRT` (0x03) adds the CRT parameters qInv, dP, dQ. CRT is the
 * reliable choice on JavaCard applets, which cannot derive the CRT parameters on-chip either, so it
 * is the default. This is the knob to try if a card still rejects the import.
 */
enum class RsaImportFormat(val attributeByte: Int) {
    STANDARD(0x01),   // e, p, q, n
    CRT(0x03)         // e, p, q, qInv, dP, dQ, n
}

object CardKeyImport {

    /** The RSA private components pulled from a keyring secret key, ready to import. */
    class RsaComponents(
        val modulus: BigInteger,
        val publicExponent: BigInteger,
        val p: BigInteger,
        val q: BigInteger,
        val qInv: BigInteger,   // q^-1 mod p  (the card's "PQ", DO 0x94)
        val dP: BigInteger,     // d mod (p-1) (DO 0x95)
        val dQ: BigInteger      // d mod (q-1) (DO 0x96)
    ) {
        val modulusBits: Int get() = modulus.bitLength().let { if (it % 8 == 0) it else (it / 8 + 1) * 8 }
    }

    /** Extract the RSA CRT components from a BC PGP private key (unlocked from the keyring). */
    fun rsaComponents(priv: PGPPrivateKey): RsaComponents {
        val params = BcPGPKeyConverter().getPrivateKey(priv) as? RSAPrivateCrtKeyParameters
            ?: throw IllegalArgumentException("not an RSA private key")
        // getDP()/getDQ() called explicitly: BC keeps a private field of the same Kotlin property
        // name, so `params.dP` binds to the field (inaccessible) instead of the getter.
        return RsaComponents(
            modulus = params.modulus,
            publicExponent = params.publicExponent,
            p = params.p,
            q = params.q,
            qInv = params.qInv,
            dP = params.getDP(),
            dQ = params.getDQ()
        )
    }

    /** Algorithm attributes to set on the slot before import: 01 || nbits || 0x0020 || format. */
    fun rsaAttributes(modulusBits: Int, format: RsaImportFormat): ByteArray =
        byteArrayOf(0x01) + u16be(modulusBits) + u16be(32) + byteArrayOf(format.attributeByte.toByte())

    /**
     * Build the key-import command data (the DO 4D Extended Header List) for an RSA key into
     * [slot] with [format]. Components are left-padded to the fixed lengths the card expects
     * (half the modulus for the primes/CRT params, matching gpg's own padding), which the
     * private-key template (7F48) then declares and the private-key data (5F48) carries.
     */
    fun buildRsaImport(slot: CardImportSlot, format: RsaImportFormat, c: RsaComponents): ByteArray {
        val half = c.modulusBits / 8 / 2               // prime/CRT-param length in bytes
        val eBytes = fixed(c.publicExponent, 4)        // e in 4 bytes (65537 → 00 01 00 01)
        val p = fixed(c.p, half)
        val q = fixed(c.q, half)

        // 7F48 declares tag+length for each component; 5F48 concatenates the values, same order.
        val templateParts = ArrayList<ByteArray>()
        val dataParts = ArrayList<ByteArray>()
        fun add(tag: Int, value: ByteArray) {
            templateParts += byteArrayOf(tag.toByte()) + berLength(value.size)
            dataParts += value
        }
        add(0x91, eBytes)
        add(0x92, p)
        add(0x93, q)
        if (format == RsaImportFormat.CRT) {
            add(0x94, fixed(c.qInv, half))
            add(0x95, fixed(c.dP, half))
            add(0x96, fixed(c.dQ, half))
        }
        // The modulus (n). A JavaCard applet cannot compute it from p and q on-chip, so the card
        // needs it supplied or the public key is never initialized and the import is refused (the
        // 6984/6A80 both import formats hit before this DO was added).
        add(0x97, fixed(c.modulus, c.modulusBits / 8))

        val template = tlv2(0x7F48, templateParts.fold(ByteArray(0)) { a, b -> a + b })
        val data = tlv2(0x5F48, dataParts.fold(ByteArray(0)) { a, b -> a + b })
        val crt = byteArrayOf(slot.crtTag.toByte(), 0x00)   // empty Control Reference Template
        return tlv1(0x4D, crt + template + data)
    }

    // ── BER-TLV + byte helpers ────────────────────────────────────────────

    /** BER length octets: short form < 128, else long form (0x81 xx / 0x82 xx xx). */
    internal fun berLength(len: Int): ByteArray = when {
        len < 0x80 -> byteArrayOf(len.toByte())
        len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
        else -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), len.toByte())
    }

    /** One-byte-tag TLV. */
    private fun tlv1(tag: Int, value: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + berLength(value.size) + value

    /** Two-byte-tag TLV (for 7F48 / 5F48). */
    private fun tlv2(tag: Int, value: ByteArray): ByteArray =
        byteArrayOf((tag shr 8).toByte(), (tag and 0xFF).toByte()) + berLength(value.size) + value

    /** Left-pad (or trim a leading sign byte from) [v] to exactly [n] bytes, big-endian. */
    internal fun fixed(v: BigInteger, n: Int): ByteArray {
        var b = v.toByteArray()
        if (b.size > 1 && b[0].toInt() == 0) b = b.copyOfRange(1, b.size) // drop sign byte
        return when {
            b.size == n -> b
            b.size < n -> ByteArray(n - b.size) + b
            else -> throw IllegalArgumentException("value larger than $n bytes")
        }
    }

    private fun u16be(v: Int): ByteArray = byteArrayOf(((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte())
}
