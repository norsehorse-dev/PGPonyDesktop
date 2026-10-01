// QrChunking.kt
// PGPony Desktop 3.0.0, stage 4 checkpoint 4c (plan section 7; Android 4.1.0 issue #3, 4.4.1
// audit item 10, 4.5.1 #63). The desktop port of Android's QrChunking (app layer, so not
// vendored). The format must stay byte-identical to Android's: a key split here is scanned by
// PGPony on a phone, and one split there is imported here.
//
// A single QR symbol holds about 2,953 bytes at error correction L. A post-quantum certificate
// does not fit, and a symbol near that ceiling has modules too small for a phone to read (#63).
// So a key over SINGLE_MAX characters is split into frames of PAYLOAD_MAX characters, each
// "PGPONY1:<seq>:<total>:<id>:<payload>", where id is the first four bytes of SHA-256 over the
// whole text in hex. The 4.5.1 density: more frames of roomier symbols, not fewer dense ones.
// Anything at or under SINGLE_MAX stays one unheadered symbol that any QR reader can scan.
// Multi-part transfer is PGPony to PGPony only.

package com.pgpony.desktop

import java.security.MessageDigest

object QrChunking {

    /** Frame marker. The digit is the format version, not the frame number. */
    const val PREFIX = "PGPONY1:"

    /** At or under this, one unheadered symbol. */
    const val SINGLE_MAX = 1_200

    /** Payload characters per frame (4.5.1). */
    const val PAYLOAD_MAX = 1_000

    /** Ceiling on frames: about 32 KB, room for the largest post-quantum certificates. */
    const val MAX_FRAMES = 32

    private const val ID_LEN = 8
    private const val HEX = "0123456789abcdef"

    data class Frame(val seq: Int, val total: Int, val id: String, val payload: String)

    sealed interface Outcome {
        data class Complete(val text: String) : Outcome
        data class Progress(val have: Int, val total: Int) : Outcome
        data class Duplicate(val have: Int, val total: Int) : Outcome

        /** A frame of a different sequence arrived; what was collected was dropped. */
        data class Restarted(val have: Int, val total: Int) : Outcome

        /**
         * A frame carried a different payload for a part already held. The held part is kept;
         * two sources are mixed, so the result cannot be trusted to be one key.
         */
        data class Conflict(val seq: Int, val have: Int, val total: Int) : Outcome
        data object NotAFrame : Outcome
        data object Malformed : Outcome
    }

    /**
     * [text] as one symbol when it fits, framed chunks when it does not, or null when even
     * [MAX_FRAMES] frames cannot hold it.
     */
    fun split(text: String): List<String>? {
        if (text.length <= SINGLE_MAX) return listOf(text)
        val total = (text.length + PAYLOAD_MAX - 1) / PAYLOAD_MAX
        if (total > MAX_FRAMES) return null
        val id = idFor(text)
        return (0 until total).map { i ->
            val from = i * PAYLOAD_MAX
            val to = minOf(from + PAYLOAD_MAX, text.length)
            PREFIX + (i + 1) + ":" + total + ":" + id + ":" + text.substring(from, to)
        }
    }

    fun isFrame(raw: String): Boolean = raw.startsWith(PREFIX)

    /**
     * One frame, or null. The payload is everything after the fourth colon: armor headers
     * (Comment:, Version:) carry colons of their own.
     */
    fun parse(raw: String): Frame? {
        if (!raw.startsWith(PREFIX)) return null
        val rest = raw.substring(PREFIX.length)
        val c1 = rest.indexOf(':')
        if (c1 <= 0) return null
        val c2 = rest.indexOf(':', c1 + 1)
        if (c2 <= c1 + 1) return null
        val c3 = rest.indexOf(':', c2 + 1)
        if (c3 <= c2 + 1) return null
        val seq = rest.substring(0, c1).toIntOrNull() ?: return null
        val total = rest.substring(c1 + 1, c2).toIntOrNull() ?: return null
        val id = rest.substring(c2 + 1, c3)
        val payload = rest.substring(c3 + 1)
        if (seq < 1 || total < 1 || seq > total || total > MAX_FRAMES) return null
        if (id.length != ID_LEN || !id.all { it in HEX }) return null
        return Frame(seq, total, id, payload)
    }

    /**
     * Reassembly. Frames arrive in any order and more than once. A part already held is never
     * replaced, and a completed sequence must hash to its id. Not thread-safe.
     */
    class Collector {
        private var id: String? = null
        private var total: Int = 0
        private val parts = mutableMapOf<Int, String>()

        val have: Int get() = parts.size
        val expected: Int get() = total

        fun reset() {
            id = null
            total = 0
            parts.clear()
        }

        fun offer(raw: String): Outcome {
            if (!isFrame(raw)) return Outcome.NotAFrame
            val frame = parse(raw) ?: return Outcome.Malformed
            val switching = id != null && (frame.id != id || frame.total != total)
            if (switching) reset()
            if (id == null) {
                id = frame.id
                total = frame.total
            }
            val held = parts[frame.seq]
            if (held != null && held != frame.payload) return Outcome.Conflict(frame.seq, parts.size, total)
            val fresh = held == null
            if (fresh) parts[frame.seq] = frame.payload
            if (parts.size == total) {
                val text = buildString { for (i in 1..total) append(parts[i]) }
                // The id is the hash of the whole text: parts that do not add up to it came
                // from more than one source (or were damaged), and are not a key.
                if (idFor(text) != id) {
                    reset()
                    return Outcome.Malformed
                }
                return Outcome.Complete(text)
            }
            return when {
                switching -> Outcome.Restarted(parts.size, total)
                fresh -> Outcome.Progress(parts.size, total)
                else -> Outcome.Duplicate(parts.size, total)
            }
        }
    }

    /** Sequence tag: the first four bytes of SHA-256 over the whole text, hex. */
    fun idFor(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(ID_LEN)
        for (i in 0 until ID_LEN / 2) {
            val b = digest[i].toInt() and 0xFF
            sb.append(HEX[b ushr 4]).append(HEX[b and 0x0F])
        }
        return sb.toString()
    }
}
