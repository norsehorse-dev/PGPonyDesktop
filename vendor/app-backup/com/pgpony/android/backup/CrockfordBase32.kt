// CrockfordBase32.kt
// PGPony Android — 4.0.0 Phase 3 (encrypted keyring backup)
//
// The backup "recovery code": 120 bits of entropy encoded as 24
// Crockford base32 symbols, displayed grouped 4×6 with hyphens
// (HWX1S7-AY1D3T-…). Matches iOS 8.0.0.
//
// IMPORTANT — the recovery code STRING is the symmetric passphrase fed
// to the OpenPGP S2K, NOT the decoded 120 bits. So cross-platform
// restore only requires that both sides normalize an entered code to
// the same canonical string; the bit→symbol layout is internal to
// generation. Verified empirically against a real iOS backup: the
// canonical (hyphen-stripped, uppercase) string decrypts; the
// hyphenated form does not.
//
// Crockford base32 is deliberately typo-tolerant: case-insensitive, and
// the visually ambiguous glyphs I, L → 1 and O → 0. Normalization on
// entry applies exactly those mappings so a hand-typed code still opens
// the file.

package com.pgpony.android.backup

import java.security.SecureRandom

object CrockfordBase32 {

    /** Canonical Crockford alphabet (no I, L, O, U). */
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /** 120-bit code → 24 symbols, shown as 4 groups of 6. */
    const val SYMBOLS = 24
    private const val GROUP = 6

    /**
     * Generate a fresh recovery code.
     *
     * @return the [canonical] 24-char passphrase (what the S2K uses) and
     *   its [grouped] display form (4×6, hyphenated).
     */
    fun generate(): Recovery {
        val bytes = ByteArray(15) // 15 * 8 = 120 bits
        SecureRandom().nextBytes(bytes)
        val canonical = encode120(bytes)
        return Recovery(canonical = canonical, grouped = group(canonical))
    }

    data class Recovery(val canonical: String, val grouped: String)

    /**
     * Normalize a user-entered code to the canonical passphrase string:
     * uppercase, drop anything that isn't a base32 symbol (hyphens,
     * spaces), and apply Crockford's typo mappings (I/L → 1, O → 0).
     * The result is what gets handed to the S2K.
     *
     * Does not enforce length — callers validate the decrypt outcome,
     * and a wrong length simply fails to decrypt with a clear error.
     */
    fun normalize(input: String): String {
        val sb = StringBuilder(SYMBOLS)
        for (raw in input) {
            val c = raw.uppercaseChar()
            when (c) {
                'O' -> sb.append('0')
                'I', 'L' -> sb.append('1')
                '-', ' ', '\t', '\n', '\r', '_' -> { /* separator, drop */ }
                else -> if (c in ALPHABET) sb.append(c)
                // Anything else (stray punctuation) is dropped rather than
                // rejected, so paste-with-junk still tends to work.
            }
        }
        return sb.toString()
    }

    /** Group a canonical code 4×6 with hyphens for display. */
    fun group(canonical: String): String =
        canonical.chunked(GROUP).joinToString("-")

    /** Is [input] a plausible recovery code (24 canonical symbols)? */
    fun isValid(input: String): Boolean {
        val c = normalize(input)
        return c.length == SYMBOLS && c.all { it in ALPHABET }
    }

    /** Encode exactly 15 bytes (120 bits) MSB-first into 24 symbols. */
    private fun encode120(bytes: ByteArray): String {
        require(bytes.size == 15) { "expected 15 bytes (120 bits)" }
        val out = StringBuilder(SYMBOLS)
        var buffer = 0
        var bits = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                val idx = (buffer ushr bits) and 0x1F
                out.append(ALPHABET[idx])
            }
        }
        // 120 is divisible by 5 → no leftover bits.
        return out.toString()
    }
}
