// CcidDescriptor.kt
// PGPony Android — USB Phase 0
//
// The CCID class descriptor (bDescriptorType 0x21) that a reader publishes on
// its smart-card interface. Two fields in it decide what the transport is
// allowed to do, so it is parsed rather than assumed:
//
//   • dwFeatures carries the EXCHANGE LEVEL. At short-APDU level or above the
//     host hands the reader whole APDUs and the reader does T=0/T=1 framing.
//     At TPDU or character level that framing becomes the host's job — a
//     different and much larger piece of work. Knowing which one we are
//     talking to is the difference between "send the APDU" and "cannot
//     support this reader yet", and the honest answer to a user is the second
//     rather than a hang.
//
//   • dwMaxCCIDMessageLength caps a single XfrBlock. RSA-4096 PSO:DECIPHER
//     sends 1 + 512 bytes of data, so the extended-length APDU that HW Phase
//     AR-1 added for NFC is exactly the case that can exceed a small reader's
//     limit and need CCID-level chaining.
//
// Pure Kotlin, no Android imports — the descriptor is just bytes, and where
// they came from is Phase 1's problem.

package com.pgpony.android.crypto.card

/**
 * How much of the T=0/T=1 protocol the reader handles on the host's behalf.
 * Ordered by how much work is left to us, least first.
 */
enum class CcidExchangeLevel {
    /** Host sends whole APDUs, including extended-length ones. Ideal. */
    SHORT_AND_EXTENDED_APDU,

    /** Host sends whole APDUs up to 261 bytes; longer ones need chaining. */
    SHORT_APDU,

    /** Host must do T=1 block framing itself. Not supported yet. */
    TPDU,

    /** Host must drive the protocol character by character. Not supported. */
    CHARACTER;

    /** True when the reader accepts whole APDUs, which is what we build. */
    val acceptsApdus: Boolean
        get() = this == SHORT_AND_EXTENDED_APDU || this == SHORT_APDU
}

/**
 * The subset of the CCID class descriptor this transport actually uses.
 * The descriptor has 54 bytes; the rest describe clock and baud negotiation
 * that a reader at APDU exchange level performs without us.
 */
data class CcidDescriptor(
    val maxSlotIndex: Int,
    val features: Long,
    val maxMessageLength: Long
) {
    val exchangeLevel: CcidExchangeLevel
        get() = when (features and EXCHANGE_LEVEL_MASK) {
            0x00040000L -> CcidExchangeLevel.SHORT_AND_EXTENDED_APDU
            0x00020000L -> CcidExchangeLevel.SHORT_APDU
            0x00010000L -> CcidExchangeLevel.TPDU
            else -> CcidExchangeLevel.CHARACTER
        }

    /** Largest APDU that fits in one XfrBlock, after the 10-byte header. */
    val maxApduLength: Long
        get() = (maxMessageLength - Ccid.HEADER_LEN).coerceAtLeast(0L)

    /**
     * True when an APDU of [size] bytes fits in a single transfer. A false
     * here on an extended-length APDU is the signal to chain rather than to
     * fail — see the note at the top of this file.
     */
    fun fitsInOneTransfer(size: Int): Boolean = size <= maxApduLength

    companion object {
        const val DESCRIPTOR_TYPE = 0x21
        const val LENGTH = 54
        private const val EXCHANGE_LEVEL_MASK = 0x00070000L

        private fun le32(b: ByteArray, at: Int): Long =
            (b[at].toLong() and 0xFF) or
                ((b[at + 1].toLong() and 0xFF) shl 8) or
                ((b[at + 2].toLong() and 0xFF) shl 16) or
                ((b[at + 3].toLong() and 0xFF) shl 24)

        /**
         * Parse the class descriptor out of [raw], which is normally the whole
         * configuration-descriptor blob read from the device — Android's USB
         * API exposes no typed accessor for class-specific descriptors, so the
         * caller hands over the raw bytes and this finds the right one.
         *
         * [offset] is where the descriptor starts. Use [findIn] to locate it.
         */
        fun parse(raw: ByteArray, offset: Int = 0): CcidDescriptor {
            if (offset < 0 || raw.size - offset < LENGTH) {
                throw OpenPgpCardException.Malformed(
                    "CCID class descriptor needs $LENGTH bytes, found ${raw.size - offset}"
                )
            }
            val type = raw[offset + 1].toInt() and 0xFF
            if (type != DESCRIPTOR_TYPE) {
                throw OpenPgpCardException.Malformed(
                    "Not a CCID class descriptor: bDescriptorType 0x%02X".format(type)
                )
            }
            return CcidDescriptor(
                maxSlotIndex = raw[offset + 4].toInt() and 0xFF,
                features = le32(raw, offset + 40),
                maxMessageLength = le32(raw, offset + 44)
            )
        }

        /**
         * Walk a configuration-descriptor blob and return the offset of the
         * first CCID class descriptor, or -1.
         *
         * USB descriptors are a chain of (bLength, bDescriptorType, …) records,
         * so this walks by bLength rather than scanning for 0x21 — the byte
         * 0x21 appears constantly inside other descriptors and a scan would
         * match noise. A zero bLength would loop forever, so it terminates.
         */
        fun findIn(raw: ByteArray): Int {
            var i = 0
            while (i + 1 < raw.size) {
                val len = raw[i].toInt() and 0xFF
                if (len == 0) return -1
                val type = raw[i + 1].toInt() and 0xFF
                if (type == DESCRIPTOR_TYPE && len >= LENGTH && i + LENGTH <= raw.size) {
                    return i
                }
                i += len
            }
            return -1
        }
    }
}
