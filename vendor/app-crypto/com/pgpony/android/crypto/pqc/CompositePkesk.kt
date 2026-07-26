// CompositePkesk.kt
// PGPony Android — 4.0.0 Phase 2b
//
// Encode/parse the v6 Public-Key Encrypted Session Key packet for the
// IETF composite (algorithm 35, ML-KEM-768 + X25519). BouncyCastle can't
// build this (no algo-35 support), so we emit/parse the packet BODY by
// hand; slice 4 wraps the encoded body in a ContainedPacket for BC's
// message generator and detects it on the decrypt side.
//
// v6 PKESK body layout (RFC 9580 §5.1 + draft-ietf-openpgp-pqc §4.3.1):
//   version(1)=6 | keyInfoCount(1) | [keyVersion(1)=6 | fingerprint(32)] |
//   pubkeyAlgo(1)=35 |
//   X25519 ephemeral(32) | ML-KEM ciphertext(1088) |
//   wrappedKeyLen(1) | RFC-3394 wrapped session key
//
// For v6 (used with SEIPD v2) the session key is wrapped bare — NO
// symmetric-algorithm octet is prepended (that's a v3-PKESK-only field).

package com.pgpony.android.crypto.pqc

import java.io.ByteArrayOutputStream

object CompositePkesk {

    const val PKESK_TAG = 1 // Public-Key Encrypted Session Key packet tag
    const val VERSION_6 = 6

    data class Parsed(
        /** Recipient v6 fingerprint (empty when anonymous/wildcard). */
        val recipientFingerprint: ByteArray,
        val ephemeralX25519: ByteArray,
        val mlkemCiphertext: ByteArray,
        val wrappedSessionKey: ByteArray
    )

    /**
     * The algorithm-specific fields of a v6 algo-35 PKESK — everything
     * after the public-key-algorithm octet:
     *   X25519 ephemeral (32) || ML-KEM ct (1088) || len (1) || wrapped key.
     * This is the `data` blob BC's PublicKeyEncSessionPacket writes verbatim,
     * and also the tail of [encodeBody]. Shared so both paths agree.
     */
    fun encodeAlgoFields(
        ephemeralX25519: ByteArray,
        mlkemCiphertext: ByteArray,
        wrappedSessionKey: ByteArray
    ): ByteArray {
        require(ephemeralX25519.size == CompositeKem.X25519_KEY_LEN) { "bad X25519 ephemeral length" }
        require(mlkemCiphertext.size == CompositeKem.MLKEM768_CT_LEN) { "bad ML-KEM ciphertext length" }
        require(wrappedSessionKey.size in 1..255) { "wrapped session key length out of range" }

        val out = ByteArrayOutputStream()
        out.write(ephemeralX25519)
        out.write(mlkemCiphertext)
        out.write(wrappedSessionKey.size)    // one-octet length
        out.write(wrappedSessionKey)
        return out.toByteArray()
    }

    /** Encode the v6 algo-35 PKESK packet BODY (no outer tag/length). */
    fun encodeBody(
        recipientFpV6: ByteArray,
        ephemeralX25519: ByteArray,
        mlkemCiphertext: ByteArray,
        wrappedSessionKey: ByteArray
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(VERSION_6)
        if (recipientFpV6.isEmpty()) {
            out.write(0) // anonymous recipient
        } else {
            require(recipientFpV6.size == 32) { "v6 fingerprint must be 32 bytes" }
            out.write(1 + 32) // count = keyVersion(1) + fingerprint(32) = 33
            out.write(6)      // recipient key version
            out.write(recipientFpV6)
        }
        out.write(CompositeKem.ALGORITHM_ID) // 35
        out.write(encodeAlgoFields(ephemeralX25519, mlkemCiphertext, wrappedSessionKey))
        return out.toByteArray()
    }

    /**
     * Parse a v6 algo-35 PKESK packet BODY. Returns null if the bytes
     * aren't a v6 composite PKESK (wrong version/algo, or truncated).
     */
    fun parseBody(body: ByteArray): Parsed? {
        try {
            var i = 0
            if ((body[i++].toInt() and 0xFF) != VERSION_6) return null
            val count = body[i++].toInt() and 0xFF
            val fp: ByteArray
            if (count == 0) {
                fp = ByteArray(0)
            } else {
                i++ // key version octet
                val fpLen = count - 1
                fp = body.copyOfRange(i, i + fpLen); i += fpLen
            }
            if ((body[i++].toInt() and 0xFF) != CompositeKem.ALGORITHM_ID) return null
            val eph = body.copyOfRange(i, i + CompositeKem.X25519_KEY_LEN)
            i += CompositeKem.X25519_KEY_LEN
            val ct = body.copyOfRange(i, i + CompositeKem.MLKEM768_CT_LEN)
            i += CompositeKem.MLKEM768_CT_LEN
            val skLen = body[i++].toInt() and 0xFF
            val wrapped = body.copyOfRange(i, i + skLen)
            return Parsed(fp, eph, ct, wrapped)
        } catch (e: Exception) {
            return null
        }
    }
}
