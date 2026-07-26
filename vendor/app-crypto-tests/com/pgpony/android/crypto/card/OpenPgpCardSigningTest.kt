// OpenPgpCardSigningTest.kt
// PGPony Android — HW Phase 2a tests
//
// Exercises the PIN-verify, sign-digest, and change-reference-data
// primitives against a scripted in-memory transport that records the
// command bytes, so we can assert both the responses are handled and the
// correct APDUs are emitted — no device needed.

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class OpenPgpCardSigningTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun sw(hi: Int, lo: Int) = byteArrayOf(hi.toByte(), lo.toByte())

    /** Returns a programmed response per INS byte and records every command sent. */
    private class ScriptedTransport(private val responses: Map<Int, ByteArray>) : CardTransport {
        val sent = mutableListOf<ByteArray>()
        override fun transceive(commandApdu: ByteArray): ByteArray {
            sent.add(commandApdu)
            val ins = commandApdu[1].toInt() and 0xFF
            return responses[ins] ?: byteArrayOf(0x6D.toByte(), 0x00)
        }
    }

    private val PIN_123456 = bytes(0x31, 0x32, 0x33, 0x34, 0x35, 0x36)
    private val PIN_654321 = bytes(0x36, 0x35, 0x34, 0x33, 0x32, 0x31)

    private fun hex(h: String) = ByteArray(h.length / 2) {
        ((h[it * 2].digitToInt(16) shl 4) or h[it * 2 + 1].digitToInt(16)).toByte()
    }

    /**
     * 4.0.4 — GET DATA 00 CA 00 F9 00, the KDF data-object read that now
     * precedes the first PIN command of a session (see CardKdf).
     *
     * ScriptedTransport answers 0x6D00 ("INS not supported") for any INS it
     * was not given, which is exactly how a card without KDF support replies
     * to this read. The PIN must therefore still go out as plain ASCII,
     * byte-identical to 4.0.3 — that fallback is the entire non-regression
     * guarantee for cards that already worked, so these tests assert it
     * rather than just skipping past the extra APDU.
     */
    private val KDF_PROBE = bytes(0x00, 0xCA, 0x00, 0xF9, 0x00)

    @Test
    fun verifySendsCorrectApduOnSuccess() {
        val t = ScriptedTransport(mapOf(OpenPgpCard.INS_VERIFY to sw(0x90, 0x00)))
        OpenPgpCardSession(t).verify(OpenPgpCard.PW1_SIGN, PIN_123456)
        assertEquals("KDF probe, then VERIFY", 2, t.sent.size)
        assertArrayEquals(KDF_PROBE, t.sent[0])
        // 00 20 00 81 06 31 32 33 34 35 36 — plain PIN, unchanged from 4.0.3
        assertArrayEquals(
            bytes(0x00, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36),
            t.sent[1]
        )
    }

    /**
     * The other half of the contract: a card that DOES report a KDF must
     * receive the S2K digest, never the typed characters.
     *
     * The KDF DO below is what `gpg --edit-card → admin → kdf-setup` writes:
     * algorithm 03 (iterated+salted), hash 08 (SHA-256), count 0x000186A0
     * (100000), PW1 salt 3B1E8A4C77D20591. The expected digest is the one
     * libgcrypt produces for that salt and "123456" (see CardKdfTest), so
     * this asserts the exact bytes gpg would put on the wire — and the Lc
     * of 0x20 shows the card sees 32 bytes, not 6.
     */
    @Test
    fun verifySendsHashedPinWhenCardReportsKdf() {
        val kdfDo =
            hex("810103") +               // 81 algorithm  = 03 iterated+salted
                hex("820108") +           // 82 hash       = 08 SHA-256
                hex("8304") + hex("000186A0") +   // 83 count = 100000, big-endian uint32
                hex("8408") + hex("3B1E8A4C77D20591")  // 84 PW1 salt
        val t = ScriptedTransport(
            mapOf(
                OpenPgpCard.INS_GET_DATA to (kdfDo + sw(0x90, 0x00)),
                OpenPgpCard.INS_VERIFY to sw(0x90, 0x00)
            )
        )
        OpenPgpCardSession(t).verify(OpenPgpCard.PW1_SIGN, PIN_123456)

        assertEquals(2, t.sent.size)
        assertArrayEquals(KDF_PROBE, t.sent[0])
        assertArrayEquals(
            bytes(0x00, 0x20, 0x00, 0x81, 0x20) +
                hex("ac57610cfc1354a9b674b4e06ff56fcb1bcae2f530e9f46b8771daea3fb6ee4d"),
            t.sent[1]
        )
    }

    @Test
    fun verifyWrongPinReportsTriesRemaining() {
        val t = ScriptedTransport(mapOf(OpenPgpCard.INS_VERIFY to sw(0x63, 0xC2)))
        try {
            OpenPgpCardSession(t).verify(OpenPgpCard.PW1_SIGN, PIN_123456)
            fail("expected WrongPin")
        } catch (e: OpenPgpCardException.WrongPin) {
            assertEquals(2, e.triesRemaining)
        }
    }

    @Test
    fun verifyBlockedThrowsCardStatus() {
        val t = ScriptedTransport(mapOf(OpenPgpCard.INS_VERIFY to sw(0x69, 0x83)))
        try {
            OpenPgpCardSession(t).verify(OpenPgpCard.PW1_SIGN, PIN_123456)
            fail("expected CardStatus")
        } catch (e: OpenPgpCardException.CardStatus) {
            assertEquals(0x6983, e.sw)
        }
    }

    @Test
    fun signDigestReturnsSignatureBytes() {
        val signature = ByteArray(64) { 0xAB.toByte() }
        val t = ScriptedTransport(
            mapOf(OpenPgpCard.INS_PERFORM_SECURITY_OPERATION to (signature + sw(0x90, 0x00)))
        )
        val digest = ByteArray(32) { 0x11 }
        val out = OpenPgpCardSession(t).signDigest(digest)
        assertArrayEquals(signature, out)
        // 00 2A 9E 9A <Lc=32> <digest> <Le=00>
        val cmd = t.sent[0]
        assertEquals(0x2A, cmd[1].toInt() and 0xFF)
        assertEquals(0x9E, cmd[2].toInt() and 0xFF)
        assertEquals(0x9A, cmd[3].toInt() and 0xFF)
    }

    @Test
    fun changeReferenceDataConcatenatesOldThenNew() {
        val t = ScriptedTransport(mapOf(OpenPgpCard.INS_CHANGE_REFERENCE_DATA to sw(0x90, 0x00)))
        OpenPgpCardSession(t).changeReferenceData(OpenPgpCard.CRD_PW1, PIN_123456, PIN_654321)
        assertEquals("KDF probe, then CHANGE REFERENCE DATA", 2, t.sent.size)
        assertArrayEquals(KDF_PROBE, t.sent[0])
        // 00 24 00 81 0C <old(6)><new(6)> — both halves plain, as in 4.0.3
        val cmd = t.sent[1]
        assertEquals(0x24, cmd[1].toInt() and 0xFF)
        assertEquals(0x81, cmd[3].toInt() and 0xFF)
        assertEquals(0x0C, cmd[4].toInt() and 0xFF)
        assertArrayEquals(PIN_123456 + PIN_654321, cmd.copyOfRange(5, 5 + 12))
    }

    @Test
    fun changeUserPinSelectsThenChanges() {
        val t = ScriptedTransport(
            mapOf(
                OpenPgpCard.INS_SELECT to sw(0x90, 0x00),
                OpenPgpCard.INS_CHANGE_REFERENCE_DATA to sw(0x90, 0x00)
            )
        )
        OpenPgpCardSession(t).changeUserPin("123456", "654321")
        assertEquals(3, t.sent.size)
        assertEquals(0xA4, t.sent[0][1].toInt() and 0xFF) // SELECT first
        assertArrayEquals(KDF_PROBE, t.sent[1])           // then the 4.0.4 KDF probe
        assertEquals(0x24, t.sent[2][1].toInt() and 0xFF) // then CHANGE REFERENCE DATA
        assertArrayEquals(PIN_123456 + PIN_654321, t.sent[2].copyOfRange(5, 5 + 12))
    }

    @Test
    fun wrongPinZeroTriesReportsBlocked() {
        val e = OpenPgpCardException.CardStatus.of(0x63C0)
        // 0x63C0 → WrongPin(0)
        if (e is OpenPgpCardException.WrongPin) {
            assertEquals(0, e.triesRemaining)
        } else {
            fail("expected WrongPin for 0x63C0")
        }
    }
}
