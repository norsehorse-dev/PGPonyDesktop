// CompositePkeskTest.kt
// PGPony Android — 4.0.0 Phase 2b
//
// Round-trip tests for the v6 algo-35 PKESK body codec. These prove
// encodeBody → parseBody recovers every field byte-for-byte, that the
// packet rejects malformed input, and that the on-wire byte layout matches
// the draft (fixed offsets). Wire interop against Sequoia `sq` is a
// separate device-side check; these are the pure-JVM structural guarantees.

package com.pgpony.android.crypto.pqc

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class CompositePkeskTest {

    private val rnd = SecureRandom()

    private fun bytes(n: Int): ByteArray = ByteArray(n).also { rnd.nextBytes(it) }

    private fun sampleFields(): List<ByteArray> = listOf(
        bytes(32),                              // v6 fingerprint
        bytes(CompositeKem.X25519_KEY_LEN),     // ephemeral X25519
        bytes(CompositeKem.MLKEM768_CT_LEN),    // ML-KEM ciphertext
        bytes(40)                               // RFC-3394 wrapped 32-byte key = 40
    )

    @Test fun encode_then_parse_recovers_all_fields() {
        val f = sampleFields()
        val fp = f[0]; val eph = f[1]; val ct = f[2]; val wrapped = f[3]

        val body = CompositePkesk.encodeBody(fp, eph, ct, wrapped)
        val parsed = CompositePkesk.parseBody(body)!!

        assertArrayEquals("fingerprint", fp, parsed.recipientFingerprint)
        assertArrayEquals("ephemeral", eph, parsed.ephemeralX25519)
        assertArrayEquals("ml-kem ct", ct, parsed.mlkemCiphertext)
        assertArrayEquals("wrapped key", wrapped, parsed.wrappedSessionKey)
    }

    @Test fun anonymous_recipient_round_trips() {
        val eph = bytes(CompositeKem.X25519_KEY_LEN)
        val ct = bytes(CompositeKem.MLKEM768_CT_LEN)
        val wrapped = bytes(40)

        val body = CompositePkesk.encodeBody(ByteArray(0), eph, ct, wrapped)
        val parsed = CompositePkesk.parseBody(body)!!

        assertEquals("anonymous fingerprint empty", 0, parsed.recipientFingerprint.size)
        assertArrayEquals(eph, parsed.ephemeralX25519)
        assertArrayEquals(ct, parsed.mlkemCiphertext)
        assertArrayEquals(wrapped, parsed.wrappedSessionKey)
    }

    @Test fun byte_layout_matches_draft() {
        val fp = bytes(32)
        val eph = bytes(CompositeKem.X25519_KEY_LEN)
        val ct = bytes(CompositeKem.MLKEM768_CT_LEN)
        val wrapped = bytes(40)

        val body = CompositePkesk.encodeBody(fp, eph, ct, wrapped)

        var i = 0
        assertEquals("version octet", 6, body[i++].toInt() and 0xFF)
        assertEquals("keyInfo count = 33", 33, body[i++].toInt() and 0xFF)
        assertEquals("recipient key version", 6, body[i++].toInt() and 0xFF)
        assertArrayEquals("fingerprint slice", fp, body.copyOfRange(i, i + 32)); i += 32
        assertEquals("pubkey algo = 35", 35, body[i++].toInt() and 0xFF)
        assertArrayEquals("ephemeral slice", eph, body.copyOfRange(i, i + 32)); i += 32
        assertArrayEquals(
            "ml-kem ct slice", ct,
            body.copyOfRange(i, i + CompositeKem.MLKEM768_CT_LEN)
        )
        i += CompositeKem.MLKEM768_CT_LEN
        assertEquals("wrapped-key length octet", 40, body[i++].toInt() and 0xFF)
        assertArrayEquals("wrapped slice", wrapped, body.copyOfRange(i, i + 40)); i += 40
        assertEquals("no trailing bytes", body.size, i)
    }

    @Test fun total_length_is_deterministic() {
        val body = CompositePkesk.encodeBody(bytes(32), bytes(32), bytes(1088), bytes(40))
        // 1 ver + 1 count + 1 keyVer + 32 fp + 1 algo + 32 eph + 1088 ct + 1 len + 40 wrapped
        assertEquals(1 + 1 + 1 + 32 + 1 + 32 + 1088 + 1 + 40, body.size)
    }

    @Test fun wrong_version_returns_null() {
        val body = CompositePkesk.encodeBody(bytes(32), bytes(32), bytes(1088), bytes(40))
        body[0] = 3 // v3
        assertNull(CompositePkesk.parseBody(body))
    }

    @Test fun wrong_algo_returns_null() {
        val body = CompositePkesk.encodeBody(bytes(32), bytes(32), bytes(1088), bytes(40))
        // algo octet sits after ver(1)+count(1)+keyVer(1)+fp(32) = index 35
        body[35] = 18 // ECDH
        assertNull(CompositePkesk.parseBody(body))
    }

    @Test fun truncated_body_returns_null() {
        val body = CompositePkesk.encodeBody(bytes(32), bytes(32), bytes(1088), bytes(40))
        assertNull(CompositePkesk.parseBody(body.copyOfRange(0, body.size - 5)))
    }

    @Test fun rejects_bad_ephemeral_length() {
        var threw = false
        try {
            CompositePkesk.encodeBody(bytes(32), bytes(31), bytes(1088), bytes(40))
        } catch (e: IllegalArgumentException) {
            threw = true
        }
        assertTrue("expected bad-ephemeral rejection", threw)
    }

    @Test fun rejects_bad_ciphertext_length() {
        var threw = false
        try {
            CompositePkesk.encodeBody(bytes(32), bytes(32), bytes(1087), bytes(40))
        } catch (e: IllegalArgumentException) {
            threw = true
        }
        assertTrue("expected bad-ciphertext rejection", threw)
    }
}
