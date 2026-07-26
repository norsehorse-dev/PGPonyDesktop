// CardKdfTest.kt
// PGPony Android — HW Phase KDF
//
// Vectors for the OpenPGP-card KDF.
//
// PROVENANCE OF THE EXPECTED DIGESTS
//
// Every expected value below was produced by libgcrypt 1.10.3 itself,
// through the exact entry point GnuPG's scdaemon uses to hash a card PIN:
//
//   gcry_kdf_derive(pin, strlen(pin), GCRY_KDF_ITERSALTED_S2K,
//                   GCRY_MD_SHA256 /* or SHA512 */,
//                   salt, 8, count, dlen, out);
//
// So these are not self-generated fixtures that would pass against a
// wrong implementation — they are what gpg puts on the wire for the same
// card, salt, PIN and count. If PGPony agrees with them, a PIN hashed
// here is interchangeable with one hashed by gpg.
//
// The count_* cases pin down RFC 4880 §3.7.1.3's awkward corner: the
// octet count is a count of OCTETS HASHED, the final repetition is
// truncated to hit it exactly, and a count smaller than one full
// salt||pin still hashes the whole thing once. With an 8-byte salt and
// the 6-character PIN "123456" the block is 14 octets, so counts 0, 1,
// 13 and 14 must all produce the SAME digest, and 15 must not.

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CardKdfTest {

    // ── Salts used by the libgcrypt vector generator ───────────────────
    private val saltA = hex("3B1E8A4C77D20591")
    private val saltB = hex("0011223344556677")
    private val saltC = hex("FFEEDDCCBBAA9988")

    /** gpg's `kdf-setup` default octet count. */
    private val defaultCount = 100_000L

    // ── derive(): agreement with libgcrypt ─────────────────────────────

    @Test
    fun `sha256 user pin matches libgcrypt`() {
        assertEquals(
            "ac57610cfc1354a9b674b4e06ff56fcb1bcae2f530e9f46b8771daea3fb6ee4d",
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltA, "123456".toByteArray(), defaultCount))
        )
    }

    @Test
    fun `sha256 admin pin matches libgcrypt`() {
        assertEquals(
            "ff402cd9f955608ddc2d260c2a19148645b0da05af1b0e094a66abcde5b8acc9",
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltC, "12345678".toByteArray(), defaultCount))
        )
    }

    @Test
    fun `sha512 matches libgcrypt and is 64 bytes`() {
        val out = CardKdf.derive(OpenPgpCard.HASH_SHA512, saltB, "123456".toByteArray(), defaultCount)
        assertEquals(64, out.size)
        assertEquals(
            "50934cbac6258aa30c8cbf050b38125d321b78e3ee5fe72e34f738d929dad2f1" +
                "2a1b4eafe3c5b8a85f750b079a422cbe563305052e62b60e25d3a03eb5e28b80",
            toHex(out)
        )
    }

    @Test
    fun `utf8 pin is hashed as utf8 bytes`() {
        assertEquals(
            "fbf67f83c380428e0777703fe90af1b5a032afa06e72b5d20d86bd20106a139f",
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltB, "pässwörd".toByteArray(Charsets.UTF_8), defaultCount))
        )
    }

    // ── derive(): the RFC 4880 octet-count corner ──────────────────────

    @Test
    fun `counts below one full block all hash the block exactly once`() {
        // salt(8) + "123456"(6) = 14 octets.
        val below = "ffd33d8b4d8f11465b2618ab0fed74cea23a3b732001c1a42d1bec7ab3ea5943"
        for (count in listOf(0L, 1L, 13L, 14L)) {
            assertEquals(
                "count=$count should hash salt||pin once",
                below,
                toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltA, "123456".toByteArray(), count))
            )
        }
    }

    @Test
    fun `one octet past a full block truncates the second repetition`() {
        assertEquals(
            "6e251214dc0b2175c2f4d3e5e9c7b62dc5c453a1279c55c4ef7e02234ece7731",
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltA, "123456".toByteArray(), 15L))
        )
    }

    @Test
    fun `two full blocks match libgcrypt`() {
        assertEquals(
            "bbe9fa466a288b29f77b2159864e2bd089bab1c98807a47bdc4f28114d31d3c3",
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltA, "123456".toByteArray(), 28L))
        )
    }

    @Test
    fun `partial trailing block matches libgcrypt`() {
        assertEquals(
            "b6f16b8c1ceaadbe1696b07dcf195b03cf1ea7d62979ce98fa67203f08184442",
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltA, "123456".toByteArray(), 1024L))
        )
    }

    @Test
    fun `count is an octet count not an RFC 4880 coded octet`() {
        // The single most likely way to get this KDF subtly wrong is to run
        // the 0x83 field through RFC 4880's coded-count expansion,
        //   count = (16 + (c and 15)) shl ((c shr 4) + 6)
        // as if it were an S2K packet's count octet. Feeding it the low byte
        // of gpg's default 100000 (0xA0) that way yields 1048576 — a
        // plausible-looking number that produces a completely different
        // digest, and one the card would reject as a wrong PIN.
        val codedOctet = 0xA0
        val misread = ((16L + (codedOctet and 15)) shl ((codedOctet shr 4) + 6))
        assertEquals(1_048_576L, misread)
        assertNotEquals(defaultCount, misread)
        assertNotEquals(
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltA, "123456".toByteArray(), defaultCount)),
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltA, "123456".toByteArray(), misread))
        )
    }

    @Test
    fun `different salts give different digests for the same pin`() {
        assertNotEquals(
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltA, "123456".toByteArray(), defaultCount)),
            toHex(CardKdf.derive(OpenPgpCard.HASH_SHA256, saltB, "123456".toByteArray(), defaultCount))
        )
    }

    @Test
    fun `unsupported hash algorithm is rejected rather than guessed`() {
        try {
            // 0x02 = SHA-1: a real OpenPGP hash ID, but not permitted for the
            // card KDF. Guessing here would silently burn the retry counter.
            CardKdf.derive(0x02, saltA, "123456".toByteArray(), defaultCount)
            fail("expected Malformed for an unsupported KDF hash")
        } catch (e: OpenPgpCardException.Malformed) {
            assertTrue(e.message!!.contains("0x02"))
        }
    }

    // ── parse(): the KDF data object ───────────────────────────────────

    @Test
    fun `parses a full gpg kdf-setup data object`() {
        val params = CardKdf.parse(fullKdfDo())
        assertTrue(params.isEnabled)
        assertEquals(OpenPgpCard.KDF_ALGO_ITERATED_SALTED, params.algorithm)
        assertEquals(OpenPgpCard.HASH_SHA256, params.hashAlgorithm)
        assertEquals(100_000L, params.iterationCount)
        assertArrayEquals(saltA, params.userSalt)
        assertArrayEquals(saltB, params.resetCodeSalt)
        assertArrayEquals(saltC, params.adminSalt)
    }

    @Test
    fun `ignores the optional initial-hash fields 0x87 and 0x88`() {
        // gpg writes 0x87 / 0x88 (initial PW1 / PW3 hashes) alongside the
        // salts. They are not inputs to the derivation and must not upset
        // the parse.
        val withHashes = fullKdfDo() +
            tlv(0x87, ByteArray(32) { 0x11 }) +
            tlv(0x88, ByteArray(32) { 0x22 })
        assertEquals(CardKdf.parse(fullKdfDo()), CardKdf.parse(withHashes))
    }

    @Test
    fun `empty data object means no kdf`() {
        assertEquals(CardKdfParams.DISABLED, CardKdf.parse(ByteArray(0)))
        assertTrue(!CardKdf.parse(ByteArray(0)).isEnabled)
    }

    @Test
    fun `algorithm zero means no kdf`() {
        val params = CardKdf.parse(tlv(OpenPgpCard.KDF_TAG_ALGORITHM, byteArrayOf(0x00)))
        assertEquals(CardKdfParams.DISABLED, params)
        assertTrue(!params.isEnabled)
    }

    @Test
    fun `iteration count is big-endian and may exceed Int MAX_VALUE`() {
        val do_ = tlv(OpenPgpCard.KDF_TAG_ALGORITHM, byteArrayOf(0x03)) +
            tlv(OpenPgpCard.KDF_TAG_HASH, byteArrayOf(0x08)) +
            tlv(OpenPgpCard.KDF_TAG_ITERATIONS, hex("FFFFFFFF")) +
            tlv(OpenPgpCard.KDF_TAG_SALT_PW1, saltA)
        // Read as a signed Int this would be -1 and the derive loop would
        // never execute.
        assertEquals(4_294_967_295L, CardKdf.parse(do_).iterationCount)
    }

    @Test
    fun `unsupported kdf algorithm is rejected`() {
        val do_ = tlv(OpenPgpCard.KDF_TAG_ALGORITHM, byteArrayOf(0x07))
        try {
            CardKdf.parse(do_)
            fail("expected Malformed for an unknown KDF algorithm")
        } catch (e: OpenPgpCardException.Malformed) {
            assertTrue(e.message!!.contains("0x07"))
        }
    }

    @Test
    fun `enabled kdf without a pw1 salt is rejected`() {
        val do_ = tlv(OpenPgpCard.KDF_TAG_ALGORITHM, byteArrayOf(0x03)) +
            tlv(OpenPgpCard.KDF_TAG_HASH, byteArrayOf(0x08)) +
            tlv(OpenPgpCard.KDF_TAG_ITERATIONS, hex("000186A0"))
        try {
            CardKdf.parse(do_)
            fail("expected Malformed when the PW1 salt is missing")
        } catch (e: OpenPgpCardException.Malformed) {
            assertTrue(e.message!!.contains("0x84"))
        }
    }

    @Test
    fun `enabled kdf without an iteration count is rejected`() {
        val do_ = tlv(OpenPgpCard.KDF_TAG_ALGORITHM, byteArrayOf(0x03)) +
            tlv(OpenPgpCard.KDF_TAG_HASH, byteArrayOf(0x08)) +
            tlv(OpenPgpCard.KDF_TAG_SALT_PW1, saltA)
        try {
            CardKdf.parse(do_)
            fail("expected Malformed when the iteration count is missing")
        } catch (e: OpenPgpCardException.Malformed) {
            assertTrue(e.message!!.contains("0x83"))
        }
    }

    // ── saltFor() / pinData(): role routing ────────────────────────────

    @Test
    fun `each role uses its own salt`() {
        val params = CardKdf.parse(fullKdfDo())
        assertArrayEquals(saltA, params.saltFor(CardPinPurpose.USER))
        assertArrayEquals(saltB, params.saltFor(CardPinPurpose.RESET_CODE))
        assertArrayEquals(saltC, params.saltFor(CardPinPurpose.ADMIN))

        val pin = "123456".toByteArray()
        assertNotEquals(
            toHex(CardKdf.pinData(params, CardPinPurpose.USER, pin)),
            toHex(CardKdf.pinData(params, CardPinPurpose.ADMIN, pin))
        )
    }

    @Test
    fun `single-salt card reuses the pw1 salt for every role`() {
        // `kdf-setup single` writes only 0x84.
        val do_ = tlv(OpenPgpCard.KDF_TAG_ALGORITHM, byteArrayOf(0x03)) +
            tlv(OpenPgpCard.KDF_TAG_HASH, byteArrayOf(0x08)) +
            tlv(OpenPgpCard.KDF_TAG_ITERATIONS, hex("000186A0")) +
            tlv(OpenPgpCard.KDF_TAG_SALT_PW1, saltA)
        val params = CardKdf.parse(do_)
        assertNull(params.resetCodeSalt)
        assertNull(params.adminSalt)
        assertArrayEquals(saltA, params.saltFor(CardPinPurpose.RESET_CODE))
        assertArrayEquals(saltA, params.saltFor(CardPinPurpose.ADMIN))
    }

    @Test
    fun `pinData passes the pin through untouched when kdf is disabled`() {
        val pin = "123456".toByteArray()
        val out = CardKdf.pinData(CardKdfParams.DISABLED, CardPinPurpose.USER, pin)
        assertSame("no copy, no hash — this is the non-KDF card path", pin, out)
    }

    @Test
    fun `pinData hashes to the digest length when kdf is enabled`() {
        val params = CardKdf.parse(fullKdfDo())
        val out = CardKdf.pinData(params, CardPinPurpose.USER, "123456".toByteArray())
        assertEquals(32, out.size)
        assertEquals(
            "ac57610cfc1354a9b674b4e06ff56fcb1bcae2f530e9f46b8771daea3fb6ee4d",
            toHex(out)
        )
    }

    // ── helpers ────────────────────────────────────────────────────────

    /** The DO a YubiKey reports after `gpg --edit-card → admin → kdf-setup`. */
    private fun fullKdfDo(): ByteArray =
        tlv(OpenPgpCard.KDF_TAG_ALGORITHM, byteArrayOf(0x03)) +
            tlv(OpenPgpCard.KDF_TAG_HASH, byteArrayOf(0x08)) +
            tlv(OpenPgpCard.KDF_TAG_ITERATIONS, hex("000186A0")) +   // 100000
            tlv(OpenPgpCard.KDF_TAG_SALT_PW1, saltA) +
            tlv(OpenPgpCard.KDF_TAG_SALT_RESET_CODE, saltB) +
            tlv(OpenPgpCard.KDF_TAG_SALT_PW3, saltC)

    private fun tlv(tag: Int, value: ByteArray): ByteArray =
        byteArrayOf(tag.toByte(), value.size.toByte()) + value

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

    private fun toHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}
