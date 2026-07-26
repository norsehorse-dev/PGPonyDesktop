// PassTotp.kt
// PGPony — RFC 6238 TOTP for `pass` entries that carry an `otpauth://` URI.
//
// Shared core, written ONCE. This file is pure Kotlin plus javax.crypto (Mac/HMAC), with no
// Android imports, so it compiles verbatim in the Android app and in PGPonyDesktop's vendored
// build — the desktop consumes it from D8, Android from 4.1.0 §7. PassEntryParser already
// surfaces the URI (PassEntryContent.otpauth); this turns it into a live code.
//
// Deliberately narrow:
//   - TOTP only. `otpauth://hotp/…` returns null: a counter-based code has to write the counter
//     back after every use, and the pass integration is READ-ONLY on every platform.
//   - SHA1 / SHA256 / SHA512, 6–8 digits, any sane period (30 by default) — the Key Uri Format
//     that Google Authenticator, Aegis, 1Password and pass-otp all emit.
//   - No clock-skew correction, no network. A code is a pure function of the secret and the
//     epoch second the caller passes in, which is exactly what makes it testable against
//     RFC 6238's Appendix B vectors (see PassTotpTest).
//   - Never throws. A malformed URI, a bad base32 secret, or an unknown algorithm is null, and
//     the UI falls back to showing the URI.
//
// The secret lives in a plain ByteArray for as long as the caller holds the Config — the same
// lifetime as the decrypted entry it came from, which the UIs already drop on relock.

package com.pgpony.android.crypto.pass

import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object PassTotp {

    private const val SCHEME = "otpauth://"

    /**
     * Parsed `otpauth://totp/…` parameters.
     *
     * Not a data class on purpose: [secret] is key material, and a generated `toString()` /
     * `equals()` over a ByteArray would be both misleading (identity comparison) and a leak
     * risk in logs.
     */
    class Config(
        val secret: ByteArray,
        /** "SHA1" | "SHA256" | "SHA512" — the digest name, without the "Hmac" prefix. */
        val algorithm: String,
        /** 6..8. */
        val digits: Int,
        /** > 0, conventionally 30. */
        val periodSeconds: Int,
        val issuer: String?,
        val account: String?
    ) {
        /** Display label, e.g. "GitHub (alice@example.com)". Never includes the secret. */
        val label: String
            get() = when {
                issuer != null && account != null -> "$issuer ($account)"
                issuer != null -> issuer
                account != null -> account
                else -> "One-time password"
            }

        override fun toString(): String =
            "PassTotp.Config(label=$label, algorithm=$algorithm, digits=$digits, " +
                "period=$periodSeconds)"
    }

    // ── Parsing ────────────────────────────────────────────────────────────

    /**
     * Parse an `otpauth://totp/…` URI. Returns null for anything this can't generate from:
     * a different scheme, `hotp`, a missing/invalid secret, an unsupported algorithm, or
     * out-of-range digits/period.
     */
    fun parse(uri: String): Config? {
        val trimmed = uri.trim()
        if (!trimmed.regionMatches(0, SCHEME, 0, SCHEME.length, ignoreCase = true)) return null
        val rest = trimmed.substring(SCHEME.length)

        val queryAt = rest.indexOf('?')
        val pathPart = if (queryAt >= 0) rest.substring(0, queryAt) else rest
        val queryPart = if (queryAt >= 0) rest.substring(queryAt + 1) else ""

        val slash = pathPart.indexOf('/')
        val type = (if (slash >= 0) pathPart.substring(0, slash) else pathPart).lowercase()
        if (type != "totp") return null

        // The label is a path segment: '+' is a literal there, unlike in the query.
        val label = if (slash >= 0) percentDecode(pathPart.substring(slash + 1), false) else ""

        val params = HashMap<String, String>()
        for (pair in queryPart.split('&')) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            if (eq <= 0) continue
            val name = percentDecode(pair.substring(0, eq), true).lowercase()
            val value = percentDecode(pair.substring(eq + 1), true)
            if (!params.containsKey(name)) params[name] = value      // first occurrence wins
        }

        val secret = decodeBase32(params["secret"] ?: return null) ?: return null
        if (secret.isEmpty()) return null

        val algorithm = when ((params["algorithm"] ?: "SHA1").uppercase()) {
            "SHA1" -> "SHA1"
            "SHA256" -> "SHA256"
            "SHA512" -> "SHA512"
            else -> return null
        }
        val digits = (params["digits"] ?: "6").toIntOrNull() ?: return null
        if (digits < 6 || digits > 8) return null
        val period = (params["period"] ?: "30").toIntOrNull() ?: return null
        if (period <= 0 || period > 3600) return null

        // The label is conventionally "Issuer:account" (some writers add a space after the
        // colon). An explicit ?issuer= wins when both are present and disagree.
        val colon = label.indexOf(':')
        val labelIssuer = if (colon > 0) label.substring(0, colon).trim() else null
        val labelAccount = if (colon >= 0) label.substring(colon + 1).trim() else label.trim()
        val issuer = params["issuer"]?.trim()?.ifEmpty { null } ?: labelIssuer?.ifEmpty { null }
        val account = labelAccount.ifEmpty { null }

        return Config(secret, algorithm, digits, period, issuer, account)
    }

    /**
     * RFC 4648 base32 decode, in the lenient spelling every authenticator expects: case
     * insensitive, `=` padding optional, and spaces/tabs/dashes/newlines (how secrets are
     * printed for humans) ignored. Returns null on an invalid character or a truncated final
     * group.
     */
    fun decodeBase32(input: String): ByteArray? {
        val out = ByteArrayOutputStream(input.length * 5 / 8 + 1)
        var buffer = 0
        var bits = 0
        for (raw in input) {
            if (raw == ' ' || raw == '\t' || raw == '-' || raw == '=' ||
                raw == '\n' || raw == '\r'
            ) continue
            val c = raw.uppercaseChar()
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in '2'..'7' -> c - '2' + 26
                else -> return null
            }
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.write((buffer shr bits) and 0xFF)
            }
        }
        // Leftover bits are the encoder's zero padding. Five or more means a whole character's
        // worth of data went nowhere — a truncated secret, not padding.
        if (bits >= 5) return null
        return out.toByteArray()
    }

    // ── Generation ─────────────────────────────────────────────────────────

    /**
     * The code for [epochSeconds] (seconds since the Unix epoch — `System.currentTimeMillis() /
     * 1000` in the UIs, passed in so this stays a pure function). Null only if the JVM has no
     * provider for the HMAC, which no supported platform is missing.
     */
    fun code(config: Config, epochSeconds: Long): String? {
        if (epochSeconds < 0) return null
        return hotp(config.secret, epochSeconds / config.periodSeconds, config.algorithm, config.digits)
    }

    /** Seconds until the current code rolls: `period` at the top of a step, 1 just before it. */
    fun secondsRemaining(config: Config, epochSeconds: Long): Int {
        if (epochSeconds < 0) return config.periodSeconds
        return config.periodSeconds - (epochSeconds % config.periodSeconds).toInt()
    }

    /** "123456" → "123 456" — a middle split for readability. Odd lengths break after the half. */
    fun grouped(code: String): String {
        if (code.length < 6) return code
        val half = code.length / 2
        return code.substring(0, half) + " " + code.substring(half)
    }

    /** RFC 4226 HOTP: HMAC over the big-endian counter, dynamic truncation, mod 10^digits. */
    private fun hotp(secret: ByteArray, counter: Long, algorithm: String, digits: Int): String? {
        val message = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            message[i] = (c and 0xFF).toByte()
            c = c ushr 8
        }
        val name = "Hmac$algorithm"
        val hash = try {
            val mac = Mac.getInstance(name)
            mac.init(SecretKeySpec(secret, name))
            mac.doFinal(message)
        } catch (e: Exception) {
            return null
        }
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        var modulus = 1
        repeat(digits) { modulus *= 10 }                 // digits ≤ 8, so this stays in Int
        return (binary % modulus).toString().padStart(digits, '0')
    }

    // ── URI helpers ────────────────────────────────────────────────────────

    private fun percentDecode(s: String, plusIsSpace: Boolean): String {
        if (!s.contains('%') && !(plusIsSpace && s.contains('+'))) return s
        val out = ByteArrayOutputStream(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 2 < s.length) {
                val hi = hexValue(s[i + 1])
                val lo = hexValue(s[i + 2])
                if (hi >= 0 && lo >= 0) {
                    out.write((hi shl 4) or lo)
                    i += 3
                    continue
                }
            }
            if (plusIsSpace && c == '+') {
                out.write(' '.code)
                i++
                continue
            }
            // Keep surrogate pairs together so non-BMP characters survive the round trip.
            val chunk = if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) {
                i += 2
                s.substring(i - 2, i)
            } else {
                i++
                c.toString()
            }
            val bytes = chunk.toByteArray(Charsets.UTF_8)
            out.write(bytes, 0, bytes.size)
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    private fun hexValue(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }
}
