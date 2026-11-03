// KeyIdText.kt
// PGPony Android, 4.7.0 (item 48, #79)
//
// The key IDs a decrypt or verify result shows: the 16-hex key ID of the key
// (primary or subkey) that made a signature or unwrapped the session key, the
// same ID gpg prints ("using RSA key 9F1DAF9D9070430F"), and the primary it
// belongs to when that is a different key. Pure Kotlin.

package com.pgpony.android.crypto

object KeyIdText {

    /**
     * The 16-hex key ID of the key with [fingerprint] (hex, any case, spaces
     * allowed): the last 8 bytes of a v4 fingerprint, the first 8 of a v5 or v6
     * one. Null when the input is not a 40 or 64 hex digit fingerprint.
     */
    fun keyIdOf(fingerprint: String?): String? {
        val hex = fingerprint?.filterNot { it.isWhitespace() }?.uppercase() ?: return null
        if (!hex.all { it in '0'..'9' || it in 'A'..'F' }) return null
        return when (hex.length) {
            40 -> hex.takeLast(16)
            64 -> hex.take(16)
            else -> null
        }
    }

    /** [raw] as 16 uppercase hex digits. */
    fun keyIdOf(raw: Long): String = String.format(java.util.Locale.ROOT, "%016X", raw)

    /** A 16-hex key ID normalized to uppercase, or null when it is not one. */
    fun normalizeKeyId(keyId: String?): String? {
        val hex = keyId?.removePrefix("0x")?.removePrefix("0X")?.uppercase() ?: return null
        return hex.takeIf { it.length == 16 && it.all { c -> c in '0'..'9' || c in 'A'..'F' } }
    }

    /**
     * Which key a result names: [keyId] is the key that signed or decrypted,
     * [primaryKeyId] the primary of its certificate when known and different,
     * else null (the key is the primary, or the primary is not known).
     */
    data class Line(val keyId: String, val primaryKeyId: String?)

    /**
     * The line for a signature: [signingKeyFingerprint] (or, without it, the
     * 16-hex [signerKeyId]) is the key that verified, [signerFingerprint] the
     * primary of its certificate. Null when neither key is known.
     */
    fun signingLine(signingKeyFingerprint: String?, signerKeyId: String?, signerFingerprint: String?): Line? {
        val key = keyIdOf(signingKeyFingerprint) ?: normalizeKeyId(signerKeyId) ?: return null
        val primary = keyIdOf(signerFingerprint)
        return Line(key, primary?.takeIf { it != key })
    }

    /** The line for a decrypt: [raw] is the key that unwrapped the session key. */
    fun decryptingLine(raw: Long?, primaryFingerprint: String?): Line? {
        if (raw == null || raw == 0L) return null
        val key = keyIdOf(raw)
        val primary = keyIdOf(primaryFingerprint)
        return Line(key, primary?.takeIf { it != key })
    }
}
