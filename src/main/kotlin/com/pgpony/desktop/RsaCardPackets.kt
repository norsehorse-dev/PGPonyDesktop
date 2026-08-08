// RsaCardPackets.kt
// PGPony Desktop — D20: the pure RSA packet building for on-card key generation (DesktopCardKeygen).
//
// Split out from the card I/O on purpose: no session, no APDUs, signing INJECTED — so an offline
// test stands a software RSA key in for the card, assembles the whole transferable public key,
// and has real gpg import it (validating the self-signatures and, the byte-exact part, matching
// the fingerprint). Reuses the vendored CardKeyPacketBuilder's generic helpers and only adds what
// is RSA-specific; the vendored bodies and signature packets are hardcoded to EdDSA (algo 22).
//
// The public-key BODY must be byte-exact (it feeds the v4 fingerprint); the self-signatures need
// only be valid. MPIs are therefore canonical-minimal (leading zeros stripped), matching gpg.

package com.pgpony.desktop

import com.pgpony.android.crypto.card.CardKeyPacketBuilder
import com.pgpony.android.crypto.card.CardSigningFormat
import java.security.MessageDigest

internal object RsaCardPackets {

    private const val RSA_ALGO = 1
    private const val HASH_SHA256 = 8
    private const val SIG_TYPE_CERT = 0x13
    private const val SIG_TYPE_BIND = 0x18

    /** Card algorithm attributes DO: algo(1) || modulus-bits(2 BE) || exp-bits(2 BE) || fmt(1). */
    fun rsaAttributes(modulusBits: Int): ByteArray {
        val expBits = 32        // e = 65537 fits in 17 bits; cards expect the fixed 0x0020 field
        val importFormat = 0x00 // standard (e, p, q). The one byte most likely to vary by card.
        return byteArrayOf(RSA_ALGO.toByte()) + u16be(modulusBits) + u16be(expBits) + byteArrayOf(importFormat.toByte())
    }

    /** v4 RSA public-key packet body: 4 || creation || algo(1) || MPI(n) || MPI(e). */
    fun buildRsaPublicKeyBody(creationTime: Long, modulus: ByteArray, exponent: ByteArray): ByteArray =
        byteArrayOf(4) + u32be(creationTime) + byteArrayOf(RSA_ALGO.toByte()) + mpi(modulus) + mpi(exponent)

    /**
     * Assemble the whole transferable public key. [signDigestInfo] takes a PKCS#1 DigestInfo and
     * returns the card's raw RSA signature; in production it re-verifies PW1 and calls PSO:CDS,
     * in tests it PKCS#1-signs with a software key. Both self-signatures are RSA (the primary).
     */
    fun assembleTransferableKey(
        creationTime: Long,
        name: String,
        email: String,
        expirationSeconds: Long?,
        primaryBody: ByteArray,
        subkeyBody: ByteArray,
        keyId: ByteArray,
        signDigestInfo: (ByteArray) -> ByteArray
    ): ByteArray {
        val userIdBytes = "$name <$email>".toByteArray(Charsets.UTF_8)
        val issuer = CardKeyPacketBuilder.issuerUnhashedSubpackets(keyId)

        val certHashed = CardKeyPacketBuilder.certificationHashedSubpackets(creationTime, expirationSeconds)
        val certDigest = sha256(certificationHashData(primaryBody, userIdBytes, SIG_TYPE_CERT, certHashed))
        val certSigRaw = signDigestInfo(CardSigningFormat.SHA256_DIGESTINFO_PREFIX + certDigest)
        val certSig = assembleRsaSignaturePacket(SIG_TYPE_CERT, certHashed, issuer, certDigest.copyOfRange(0, 2), certSigRaw)

        val bindHashed = CardKeyPacketBuilder.bindingHashedSubpackets(creationTime)
        val bindDigest = sha256(subkeyBindingHashData(primaryBody, subkeyBody, SIG_TYPE_BIND, bindHashed))
        val bindSigRaw = signDigestInfo(CardSigningFormat.SHA256_DIGESTINFO_PREFIX + bindDigest)
        val bindSig = assembleRsaSignaturePacket(SIG_TYPE_BIND, bindHashed, issuer, bindDigest.copyOfRange(0, 2), bindSigRaw)

        return CardKeyPacketBuilder.buildPacket(6, primaryBody) +
            CardKeyPacketBuilder.buildPacket(13, userIdBytes) +
            CardKeyPacketBuilder.buildPacket(2, certSig) +
            CardKeyPacketBuilder.buildPacket(14, subkeyBody) +
            CardKeyPacketBuilder.buildPacket(2, bindSig)
    }

    /** v4 RSA signature packet body from the card's raw signature (a single PKCS#1 integer). */
    fun assembleRsaSignaturePacket(
        signatureType: Int,
        hashedSubpackets: ByteArray,
        unhashedSubpackets: ByteArray,
        digestPrefix: ByteArray,
        rawSignature: ByteArray
    ): ByteArray {
        require(digestPrefix.size == 2) { "digest prefix must be 2 bytes" }
        return byteArrayOf(4, signatureType.toByte(), RSA_ALGO.toByte(), HASH_SHA256.toByte()) +
            u16be(hashedSubpackets.size) + hashedSubpackets +
            u16be(unhashedSubpackets.size) + unhashedSubpackets +
            digestPrefix +
            mpi(rawSignature)
    }

    // The vendored buildCertificationHashData / buildSubkeyBindingHashData embed the EdDSA algo id
    // in their (private) trailer, so the RSA trailer is rebuilt here with algo 1. The
    // primary/uid/subkey framing is identical.

    private fun certificationHashData(primaryBody: ByteArray, uid: ByteArray, sigType: Int, hashed: ByteArray): ByteArray =
        byteArrayOf(0x99.toByte()) + u16be(primaryBody.size) + primaryBody +
            byteArrayOf(0xB4.toByte()) + u32be(uid.size.toLong()) + uid +
            signatureTrailer(sigType, hashed)

    private fun subkeyBindingHashData(primaryBody: ByteArray, subkeyBody: ByteArray, sigType: Int, hashed: ByteArray): ByteArray =
        byteArrayOf(0x99.toByte()) + u16be(primaryBody.size) + primaryBody +
            byteArrayOf(0x99.toByte()) + u16be(subkeyBody.size) + subkeyBody +
            signatureTrailer(sigType, hashed)

    private fun signatureTrailer(signatureType: Int, hashed: ByteArray): ByteArray {
        val totalHashedLen = 6 + hashed.size
        return byteArrayOf(4, signatureType.toByte(), RSA_ALGO.toByte(), HASH_SHA256.toByte()) +
            u16be(hashed.size) + hashed +
            byteArrayOf(4, 0xFF.toByte()) + u32be(totalHashedLen.toLong())
    }

    // ── byte helpers (private in the vendored builder; re-declared here) ──

    private fun u16be(v: Int): ByteArray = byteArrayOf(((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun u32be(v: Long): ByteArray = byteArrayOf(
        ((v shr 24) and 0xFF).toByte(), ((v shr 16) and 0xFF).toByte(),
        ((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte()
    )

    /** Canonical OpenPGP MPI: leading zero bytes stripped, then 2-byte bit length, then value. */
    fun mpi(value: ByteArray): ByteArray {
        var start = 0
        while (start < value.size && value[start].toInt() == 0) start++
        val b = value.copyOfRange(start, value.size)
        if (b.isEmpty()) return byteArrayOf(0, 0)
        val bits = (b.size - 1) * 8 + (32 - Integer.numberOfLeadingZeros(b[0].toInt() and 0xFF))
        return u16be(bits) + b
    }

    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}
