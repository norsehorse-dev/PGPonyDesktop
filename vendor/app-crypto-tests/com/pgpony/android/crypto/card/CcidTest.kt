// CcidTest.kt
// PGPony Android — USB Phase 0 tests
//
// The CCID layer is pure and has no device behind it, so every byte offset
// and every endianness decision is checkable here. That is the whole point of
// splitting it out: the parts of a USB transport that are easy to get subtly
// wrong are the parts that need no USB to test.
//
// Little-endian is the theme. Every length in CCID runs the opposite way to
// every other length in this codebase, and a byte-order mistake produces a
// message the reader silently ignores rather than an error.

package com.pgpony.android.crypto.card

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CcidTest {

    // ── Command framing ────────────────────────────────────────────────

    @Test
    fun `xfrBlock writes a ten byte header then the apdu`() {
        val apdu = byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, 0x06)
        val out = CcidCommand.xfrBlock(sequence = 7, apdu = apdu).toBytes()

        assertEquals(Ccid.HEADER_LEN + apdu.size, out.size)
        assertEquals(Ccid.PC_TO_RDR_XFR_BLOCK, out[0].toInt() and 0xFF)
        assertEquals(0, out[5].toInt())          // bSlot
        assertEquals(7, out[6].toInt())          // bSeq
        assertArrayEquals(apdu, out.copyOfRange(Ccid.HEADER_LEN, out.size))
    }

    @Test
    fun `dwLength is little-endian and counts only the payload`() {
        // 0x0102 = 258 bytes: little-endian writes 02 01 00 00, and the
        // 10-byte header is NOT included in the count.
        val apdu = ByteArray(0x0102) { 0x41 }
        val out = CcidCommand.xfrBlock(sequence = 0, apdu = apdu).toBytes()

        assertEquals(0x02, out[1].toInt() and 0xFF)
        assertEquals(0x01, out[2].toInt() and 0xFF)
        assertEquals(0x00, out[3].toInt() and 0xFF)
        assertEquals(0x00, out[4].toInt() and 0xFF)
        assertEquals(0x0102 + Ccid.HEADER_LEN, out.size)
    }

    @Test
    fun `a large extended apdu still frames correctly`() {
        // RSA-4096 PSO:DECIPHER sends 1 + 512 bytes of data plus the APDU
        // header — the case HW Phase AR-1 added extended-length encoding for.
        val apdu = ByteArray(520) { (it and 0xFF).toByte() }
        val out = CcidCommand.xfrBlock(sequence = 3, apdu = apdu).toBytes()

        assertEquals(520, (out[1].toInt() and 0xFF) or ((out[2].toInt() and 0xFF) shl 8))
        assertArrayEquals(apdu, out.copyOfRange(Ccid.HEADER_LEN, out.size))
    }

    @Test
    fun `wLevelParameter is split little-endian across offsets eight and nine`() {
        val out = CcidCommand.xfrBlock(
            sequence = 1, apdu = ByteArray(0), levelParameter = 0x0010
        ).toBytes()
        assertEquals(0x10, out[8].toInt() and 0xFF)
        assertEquals(0x00, out[9].toInt() and 0xFF)
    }

    @Test
    fun `power on requests automatic voltage selection by default`() {
        val out = CcidCommand.powerOn(sequence = 0).toBytes()
        assertEquals(Ccid.PC_TO_RDR_ICC_POWER_ON, out[0].toInt() and 0xFF)
        assertEquals(0x00, out[7].toInt())       // bPowerSelect = automatic
        assertEquals(Ccid.HEADER_LEN, out.size)  // no payload
    }

    @Test
    fun `power off and slot status carry no payload`() {
        assertEquals(Ccid.HEADER_LEN, CcidCommand.powerOff(1).toBytes().size)
        assertEquals(Ccid.HEADER_LEN, CcidCommand.getSlotStatus(2).toBytes().size)
        assertEquals(
            Ccid.PC_TO_RDR_GET_SLOT_STATUS,
            CcidCommand.getSlotStatus(2).toBytes()[0].toInt() and 0xFF
        )
    }

    // ── Response parsing ───────────────────────────────────────────────

    private fun dataBlock(
        seq: Int = 0, status: Int = 0, error: Int = 0, data: ByteArray = ByteArray(0)
    ): ByteArray {
        val out = ByteArray(Ccid.HEADER_LEN + data.size)
        out[0] = Ccid.RDR_TO_PC_DATA_BLOCK.toByte()
        out[1] = (data.size and 0xFF).toByte()
        out[2] = ((data.size ushr 8) and 0xFF).toByte()
        out[6] = seq.toByte()
        out[7] = status.toByte()
        out[8] = error.toByte()
        data.copyInto(out, Ccid.HEADER_LEN)
        return out
    }

    @Test
    fun `a successful data block yields the card's response bytes`() {
        val sw9000 = byteArrayOf(0x90.toByte(), 0x00)
        val r = CcidResponse.parse(dataBlock(seq = 5, data = sw9000))

        assertTrue(r.isSuccess)
        assertFalse(r.isFailed)
        assertFalse(r.isTimeExtensionRequest)
        assertTrue(r.cardPresent)
        assertEquals(5, r.sequence)
        assertArrayEquals(sw9000, r.data)
    }

    @Test
    fun `time extension is not an error`() {
        // bmCommandStatus = 2 in bits 6-7, card present and active.
        val r = CcidResponse.parse(dataBlock(status = 0x80))

        assertTrue(r.isTimeExtensionRequest)
        assertFalse(r.isFailed)
        assertFalse(r.isSuccess)
        assertEquals(Ccid.CMD_STATUS_TIME_EXTENSION, r.commandStatus)
    }

    @Test
    fun `a failed response reports the reader's error in words`() {
        // bmCommandStatus = 1, bError 0xFE = ICC_MUTE.
        val r = CcidResponse.parse(dataBlock(status = 0x40, error = 0xFE))

        assertTrue(r.isFailed)
        assertTrue(r.errorText().contains("mute"))
    }

    @Test
    fun `an absent card is reported as absent, not as a failure`() {
        // bmICCStatus = 2 in bits 0-1.
        val r = CcidResponse.parse(dataBlock(status = 0x02))
        assertFalse(r.cardPresent)
        assertEquals(Ccid.ICC_ABSENT, r.iccStatus)
    }

    @Test
    fun `dwLength decides where the data ends, not the buffer size`() {
        // A bulk read returns whatever the endpoint had buffered, so trailing
        // bytes past dwLength must be ignored rather than handed to the caller.
        val msg = dataBlock(data = byteArrayOf(0x90.toByte(), 0x00))
        val padded = msg + byteArrayOf(0x7F, 0x7F, 0x7F)

        assertArrayEquals(byteArrayOf(0x90.toByte(), 0x00), CcidResponse.parse(padded).data)
    }

    @Test
    fun `a short read is an error rather than a silent truncation`() {
        val msg = dataBlock(data = ByteArray(64))
        val truncated = msg.copyOfRange(0, Ccid.HEADER_LEN + 10)
        try {
            CcidResponse.parse(truncated)
            fail("expected a Communication error")
        } catch (e: OpenPgpCardException.Communication) {
            assertTrue(e.message!!.contains("declared"))
        }
    }

    @Test
    fun `a runt buffer is rejected`() {
        try {
            CcidResponse.parse(ByteArray(4))
            fail("expected a Communication error")
        } catch (e: OpenPgpCardException.Communication) {
            assertTrue(e.message!!.contains("too short"))
        }
    }

    @Test
    fun `a hostile dwLength cannot wrap into a negative length`() {
        // 0xFFFFFFFF little-endian would be -1 as a signed Int.
        val msg = dataBlock()
        msg[1] = 0xFF.toByte(); msg[2] = 0xFF.toByte()
        msg[3] = 0xFF.toByte(); msg[4] = 0xFF.toByte()
        try {
            CcidResponse.parse(msg)
            fail("expected a Communication error")
        } catch (e: OpenPgpCardException.Communication) {
            assertTrue(e.message!!.contains("declared"))
        }
    }

    // ── Class descriptor ───────────────────────────────────────────────

    private fun descriptor(features: Long, maxMsg: Long = 271L): ByteArray {
        val d = ByteArray(CcidDescriptor.LENGTH)
        d[0] = CcidDescriptor.LENGTH.toByte()
        d[1] = CcidDescriptor.DESCRIPTOR_TYPE.toByte()
        d[4] = 0  // bMaxSlotIndex
        for (i in 0 until 4) d[40 + i] = ((features ushr (8 * i)) and 0xFF).toByte()
        for (i in 0 until 4) d[44 + i] = ((maxMsg ushr (8 * i)) and 0xFF).toByte()
        return d
    }

    @Test
    fun `exchange level is read out of dwFeatures`() {
        assertEquals(
            CcidExchangeLevel.SHORT_AND_EXTENDED_APDU,
            CcidDescriptor.parse(descriptor(0x00040000L)).exchangeLevel
        )
        assertEquals(
            CcidExchangeLevel.SHORT_APDU,
            CcidDescriptor.parse(descriptor(0x00020000L)).exchangeLevel
        )
        assertEquals(
            CcidExchangeLevel.TPDU,
            CcidDescriptor.parse(descriptor(0x00010000L)).exchangeLevel
        )
        assertEquals(
            CcidExchangeLevel.CHARACTER,
            CcidDescriptor.parse(descriptor(0x00000000L)).exchangeLevel
        )
    }

    @Test
    fun `unrelated feature bits do not disturb the exchange level`() {
        // Automatic voltage selection, clock change, PPS — all commonly set.
        val d = CcidDescriptor.parse(descriptor(0x000406BAL))
        assertEquals(CcidExchangeLevel.SHORT_AND_EXTENDED_APDU, d.exchangeLevel)
        assertTrue(d.exchangeLevel.acceptsApdus)
    }

    @Test
    fun `only apdu-level readers are usable without extra framing`() {
        assertTrue(CcidExchangeLevel.SHORT_AND_EXTENDED_APDU.acceptsApdus)
        assertTrue(CcidExchangeLevel.SHORT_APDU.acceptsApdus)
        assertFalse(CcidExchangeLevel.TPDU.acceptsApdus)
        assertFalse(CcidExchangeLevel.CHARACTER.acceptsApdus)
    }

    @Test
    fun `max apdu length subtracts the header from the message limit`() {
        val d = CcidDescriptor.parse(descriptor(0x00040000L, maxMsg = 271L))
        assertEquals(261L, d.maxApduLength)
        assertTrue(d.fitsInOneTransfer(261))
        // An RSA-4096 decipher does not fit on a 271-byte reader — the case
        // that needs CCID-level chaining rather than a hopeful large write.
        assertFalse(d.fitsInOneTransfer(520))
    }

    @Test
    fun `a generous reader takes the whole extended apdu`() {
        val d = CcidDescriptor.parse(descriptor(0x00040000L, maxMsg = 65544L))
        assertTrue(d.fitsInOneTransfer(520))
    }

    @Test
    fun `findIn walks the descriptor chain by length rather than scanning`() {
        // A preceding interface descriptor whose payload contains a stray
        // 0x21 byte — a naive scan would match it and misparse.
        val decoy = byteArrayOf(
            0x09, 0x04, 0x00, 0x00, 0x03, 0x0B, 0x00, 0x21, 0x00
        )
        val blob = decoy + descriptor(0x00040000L)

        assertEquals(decoy.size, CcidDescriptor.findIn(blob))
        assertEquals(
            CcidExchangeLevel.SHORT_AND_EXTENDED_APDU,
            CcidDescriptor.parse(blob, CcidDescriptor.findIn(blob)).exchangeLevel
        )
    }

    @Test
    fun `findIn returns -1 when there is no ccid descriptor`() {
        val blob = byteArrayOf(0x09, 0x04, 0x00, 0x00, 0x03, 0x0B, 0x00, 0x00, 0x00)
        assertEquals(-1, CcidDescriptor.findIn(blob))
    }

    @Test
    fun `a zero length record cannot loop forever`() {
        assertEquals(-1, CcidDescriptor.findIn(byteArrayOf(0x00, 0x21, 0x00, 0x00)))
    }

    @Test
    fun `the wrong descriptor type is rejected`() {
        val d = descriptor(0x00040000L)
        d[1] = 0x24  // a class-specific interface descriptor, not CCID
        try {
            CcidDescriptor.parse(d)
            fail("expected a Malformed error")
        } catch (e: OpenPgpCardException.Malformed) {
            assertTrue(e.message!!.contains("Not a CCID"))
        }
    }
}
