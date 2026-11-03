// KeyToCard.kt
// PGPony Android, 4.7.0 RC4 (item 13, #71)
//
// The pure half of Move to Security Key, gpg's keytocard: which keys of a key
// pair may go to which card slot, the algorithm attributes a slot needs for
// them, the private key import data (OpenPGP card 3.4, 4.4.3.12: PUT DATA with
// odd INS 0xDB, P1P2 3FFF, an Extended Header List 0x4D), and the
// divert-to-card stub gpg writes for a key whose secret now lives on a card.
// No card I/O here (KeyToCardService runs the session); unit-tested on the JVM.
//
// Supported: v4 keys, RSA 2048 to 4096 (any slot by its usage), Ed25519
// (EdDSA, signature and authentication slots) and Cv25519 (ECDH, decryption
// slot). These are the types PGPony can also use on a card afterwards. NIST,
// brainpool, RFC 9580 Ed25519/X25519 (algorithms 25 to 28), v6 and
// post-quantum keys are refused with the reason.
//
// The import data holds private key bytes; every builder here returns arrays
// the caller wipes ([wipe]) once the APDUs are sent. BigInteger values from
// Bouncy Castle cannot be wiped; they are dropped with the unlocked key.

package com.pgpony.android.crypto.card

import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.ECSecretBCPGKey
import org.bouncycastle.bcpg.EdDSAPublicBCPGKey
import org.bouncycastle.bcpg.EdSecretBCPGKey
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.RSAPublicBCPGKey
import org.bouncycastle.bcpg.RSASecretBCPGKey
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import java.math.BigInteger

object KeyToCard {

    // Curve OIDs as dotted strings (Bouncy Castle's ASN1ObjectIdentifier.id).
    private const val OID_ED25519 = "1.3.6.1.4.1.11591.15.1"
    private const val OID_CV25519 = "1.3.6.1.4.1.3029.1.5.1"

    /** The kinds of key this can move. */
    enum class Kind { RSA, ED25519, CV25519 }

    /** Why a key cannot go to a card, shown to the user. */
    enum class Refusal { NOT_V4, ALGORITHM, RSA_SIZE, CURVE }

    /** What a key is, for the slot choice: its kind, or why it cannot move. */
    sealed class Eligibility {
        data class Movable(val kind: Kind, val rsaBits: Int = 0) : Eligibility()
        data class Refused(val reason: Refusal) : Eligibility()
    }

    fun eligibility(pub: PGPPublicKey): Eligibility {
        if (pub.version != 4) return Eligibility.Refused(Refusal.NOT_V4)
        val key = pub.publicKeyPacket.key
        return when (pub.algorithm) {
            PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_SIGN, PublicKeyAlgorithmTags.RSA_ENCRYPT -> {
                val bits = (key as? RSAPublicBCPGKey)?.modulus?.bitLength() ?: return Eligibility.Refused(Refusal.ALGORITHM)
                if (bits !in setOf(2048, 3072, 4096)) Eligibility.Refused(Refusal.RSA_SIZE)
                else Eligibility.Movable(Kind.RSA, bits)
            }
            PublicKeyAlgorithmTags.EDDSA_LEGACY ->
                if ((key as? EdDSAPublicBCPGKey)?.curveOID?.id == OID_ED25519) Eligibility.Movable(Kind.ED25519)
                else Eligibility.Refused(Refusal.CURVE)
            PublicKeyAlgorithmTags.ECDH ->
                if ((key as? ECDHPublicBCPGKey)?.curveOID?.id == OID_CV25519) Eligibility.Movable(Kind.CV25519)
                else Eligibility.Refused(Refusal.CURVE)
            PublicKeyAlgorithmTags.ECDSA -> Eligibility.Refused(Refusal.CURVE)
            else -> Eligibility.Refused(Refusal.ALGORITHM)
        }
    }

    /** Whether a key of [kind] may go to [slot] given what it is for. */
    fun fitsSlot(
        kind: Kind, slot: CardSlot, canSign: Boolean, canEncrypt: Boolean, canAuthenticate: Boolean,
        primaryCanCertify: Boolean = false
    ): Boolean =
        when (slot) {
            // A certify-only primary may go to the Signature slot too, as in gpg;
            // the card's signature slot is what certifies on a card.
            CardSlot.SIGNATURE -> (canSign || primaryCanCertify) && kind != Kind.CV25519
            CardSlot.DECRYPTION -> canEncrypt && (kind == Kind.RSA || kind == Kind.CV25519)
            CardSlot.AUTHENTICATION -> canAuthenticate && kind != Kind.CV25519
        }

    // ── Algorithm attributes (C1, C2, C3) ───────────────────────────────

    private val ED25519_OID_BYTES = CardKeyPacketBuilder.ED25519_OID
    private val CV25519_OID_BYTES = CardKeyPacketBuilder.CV25519_OID

    /** RSA import format 00: standard (e, p, q). */
    const val RSA_FORMAT_STANDARD = 0x00
    /** RSA import format 02: CRT (e, p, q, 1/q mod p, d mod (p-1), d mod (q-1)). */
    const val RSA_FORMAT_CRT = 0x02

    /**
     * The attributes [slot] needs for a key of [kind]: RSA is
     * 01 | n bits | e bits | import format, an EC key is its algorithm ID and
     * curve OID. [rsaFormat] keeps the format the slot already uses when it
     * is RSA (with or without the modulus, 01 and 03, maps to the same data).
     */
    fun attributes(kind: Kind, rsaBits: Int, eBits: Int, rsaFormat: Int): ByteArray = when (kind) {
        Kind.RSA -> byteArrayOf(
            0x01,
            ((rsaBits shr 8) and 0xFF).toByte(), (rsaBits and 0xFF).toByte(),
            ((eBits shr 8) and 0xFF).toByte(), (eBits and 0xFF).toByte(),
            rsaFormat.toByte()
        )
        Kind.ED25519 -> byteArrayOf(OpenPgpCard.ALGO_EDDSA.toByte()) + ED25519_OID_BYTES
        Kind.CV25519 -> byteArrayOf(OpenPgpCard.ALGO_ECDH.toByte()) + CV25519_OID_BYTES
    }

    /** The RSA public exponent length in bits of raw attributes, or null when they are not RSA. */
    fun rsaExponentBitsOf(attr: ByteArray?): Int? {
        if (attr == null || attr.size < 5 || (attr[0].toInt() and 0xFF) != OpenPgpCard.ALGO_RSA) return null
        return ((attr[3].toInt() and 0xFF) shl 8) or (attr[4].toInt() and 0xFF)
    }

    /**
     * Whether [current] (what the slot reports) already is [wanted]. An EC
     * slot may report a trailing import-format octet after the OID, which is
     * ignored here.
     */
    fun sameAttributes(current: ByteArray?, wanted: ByteArray): Boolean {
        if (current == null) return false
        if (current.contentEquals(wanted)) return true
        val isEc = (wanted[0].toInt() and 0xFF) != OpenPgpCard.ALGO_RSA
        return isEc && current.size == wanted.size + 1 && current.copyOf(wanted.size).contentEquals(wanted)
    }

    /** The RSA import format byte of raw attributes, or null when they are not RSA. */
    fun rsaFormatOf(attr: ByteArray?): Int? {
        if (attr == null || attr.size < 6 || (attr[0].toInt() and 0xFF) != OpenPgpCard.ALGO_RSA) return null
        return attr[5].toInt() and 0xFF
    }

    // ── The import data ─────────────────────────────────────────────────

    /** One component of the private key template: its tag (0x91 to 0x99) and value. */
    class Part(val tag: Int, val value: ByteArray)

    /**
     * The Extended Header List for [slot]: 4D L { CRT tag 00, 7F48 L
     * {tag len ...}, 5F48 L {values} }. Lengths are BER (1, 2 or 3 octets).
     */
    fun extendedHeaderList(slot: CardSlot, parts: List<Part>): ByteArray {
        // Built in one exactly sized array, so no stream buffer keeps a copy
        // of the key bytes behind.
        val template = ArrayList<Byte>()
        var dataLen = 0
        for (p in parts) {
            template.add(p.tag.toByte())
            berLength(p.value.size).forEach { template.add(it) }
            dataLen += p.value.size
        }
        val tLenBer = berLength(template.size)
        val dLenBer = berLength(dataLen)
        val bodyLen = 2 + 2 + tLenBer.size + template.size + 2 + dLenBer.size + dataLen
        val bodyLenBer = berLength(bodyLen)
        val out = ByteArray(1 + bodyLenBer.size + bodyLen)
        var i = 0
        fun put(b: Int) { out[i++] = b.toByte() }
        fun put(bs: ByteArray) { System.arraycopy(bs, 0, out, i, bs.size); i += bs.size }
        put(0x4D); put(bodyLenBer)
        put(slot.crtTag); put(0x00)
        put(0x7F); put(0x48); put(tLenBer); template.forEach { put(it.toInt()) }
        put(0x5F); put(0x48); put(dLenBer)
        for (p in parts) put(p.value)
        check(i == out.size)
        return out
    }

    fun berLength(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n <= 0xFF -> byteArrayOf(0x81.toByte(), n.toByte())
        n <= 0xFFFF -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        else -> throw IllegalArgumentException("length $n too long")
    }

    /** [v] as exactly [len] big-endian octets (left-padded); refuses a longer value. */
    fun fixed(v: BigInteger, len: Int): ByteArray {
        val raw = v.toByteArray()
        val start = if (raw.size > 1 && raw[0].toInt() == 0) 1 else 0
        val n = raw.size - start
        require(n <= len) { "value longer than $len octets" }
        val out = ByteArray(len)
        System.arraycopy(raw, start, out, len - n, n)
        wipe(raw)
        return out
    }

    /** The RSA parts for import format [format] (00/01 standard, 02/03 CRT). */
    fun rsaParts(
        e: BigInteger, p: BigInteger, q: BigInteger, d: BigInteger,
        nBits: Int, eBits: Int, format: Int
    ): List<Part> {
        val eLen = (eBits + 7) / 8
        val half = nBits / 16
        val parts = mutableListOf(
            Part(0x91, fixed(e, eLen)),
            Part(0x92, fixed(p, half)),
            Part(0x93, fixed(q, half))
        )
        if (format == RSA_FORMAT_CRT || format == 0x03) {
            parts += Part(0x94, fixed(q.modInverse(p), half))
            parts += Part(0x95, fixed(d.mod(p.subtract(BigInteger.ONE)), half))
            parts += Part(0x96, fixed(d.mod(q.subtract(BigInteger.ONE)), half))
        }
        if (format == 0x01 || format == 0x03) parts += Part(0x97, fixed(p.multiply(q), nBits / 8))
        return parts
    }

    /** The RSA private key parts of [priv] for [pub]: e, p, q, d. */
    fun rsaSecret(pub: PGPPublicKey, priv: PGPPrivateKey): Array<BigInteger> {
        val sec = priv.privateKeyDataPacket as? RSASecretBCPGKey
            ?: throw IllegalArgumentException("not an RSA private key")
        val e = (pub.publicKeyPacket.key as RSAPublicBCPGKey).publicExponent
        return arrayOf(e, sec.primeP, sec.primeQ, sec.privateExponent)
    }

    /** The 32-octet Ed25519 seed of [priv] (the EdDSA secret MPI, big-endian as stored). */
    fun ed25519Seed(priv: PGPPrivateKey): ByteArray {
        val sec = priv.privateKeyDataPacket as? EdSecretBCPGKey
            ?: throw IllegalArgumentException("not an EdDSA private key")
        return fixed(sec.x, 32)
    }

    /**
     * The 32-octet X25519 secret of [priv]. OpenPGP stores it as an MPI in
     * reversed (big-endian) order; [native] gives the RFC 7748 little-endian
     * form, the other gives the octets as stored. Which one a card wants is
     * settled by testing the slot after the import (KeyToCardService).
     */
    fun cv25519Secret(priv: PGPPrivateKey, native: Boolean): ByteArray {
        val sec = priv.privateKeyDataPacket as? ECSecretBCPGKey
            ?: throw IllegalArgumentException("not an ECDH private key")
        val stored = fixed(sec.x, 32)
        if (native) stored.reverse()
        return stored
    }

    /** The parts for an EC key: 92 with the private scalar or seed. */
    fun ecParts(secret: ByteArray): List<Part> = listOf(Part(0x92, secret))

    fun wipe(b: ByteArray?) {
        if (b != null) java.util.Arrays.fill(b, 0)
    }

    fun wipe(parts: List<Part>) = parts.forEach { wipe(it.value) }

    // ── The stub left on the phone ──────────────────────────────────────

    /**
     * [key] with its secret replaced by the stub gpg writes for a key whose
     * secret is on a card: S2K usage 255, cipher 0, the GNU S2K extension in
     * mode 1002 (divert to card), and the card's application ID ([cardAid],
     * 1 to 16 octets) prefixed by its length where the secret was. Exported,
     * it goes back into gpg as `ssb>` (or `sec>`).
     */
    fun divertToCardStub(key: org.bouncycastle.openpgp.PGPSecretKey, cardAid: ByteArray): org.bouncycastle.openpgp.PGPSecretKey {
        require(cardAid.size in 1..16) { "card serial must be 1 to 16 octets" }
        val pub = key.publicKey
        val s2k = org.bouncycastle.bcpg.S2K.gnuDummyS2K(org.bouncycastle.bcpg.S2K.GNUDummyParams.divertToCard())
        val serial = byteArrayOf(cardAid.size.toByte()) + cardAid
        val packet = if (pub.isMasterKey) {
            org.bouncycastle.bcpg.SecretKeyPacket(
                pub.publicKeyPacket, org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.NULL,
                org.bouncycastle.bcpg.SecretKeyPacket.USAGE_CHECKSUM, s2k, null, serial
            )
        } else {
            org.bouncycastle.bcpg.SecretSubkeyPacket(
                pub.publicKeyPacket, org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags.NULL,
                org.bouncycastle.bcpg.SecretKeyPacket.USAGE_CHECKSUM, s2k, null, serial
            )
        }
        return org.bouncycastle.openpgp.PGPSecretKey(packet, pub)
    }

    /** Hex (as CardInfo.aidHex carries it) to octets. */
    fun hexToBytes(hex: String): ByteArray {
        val h = hex.filterNot { it.isWhitespace() }
        require(h.length % 2 == 0) { "odd hex length" }
        return ByteArray(h.length / 2) { i -> h.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
}
