// ProgressStreamTest.kt
// D17 validation — the counting + cancellable stream (src/main/kotlin/com/pgpony/desktop/
// ProgressStream.kt) that gives §3b its moving bar and its interruptible pass. The end-to-end
// "10 GB encrypt cancels and leaves no partial" is a manual matrix row (§8); here we pin the
// stream contract the engine relies on: it counts every byte, reports no more than once per
// tick, and throws promptly when the flag trips.

package com.pgpony.desktop

import java.io.ByteArrayInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ProgressStreamTest {

    @Test
    fun countsEveryByteAndReportsAFinalTotalOnFinish() {
        val data = ByteArray(5000) { it.toByte() }
        var lastDone = -1L
        var lastTotal = -1L
        val ps = ProgressInputStream(
            ByteArrayInputStream(data), total = data.size.toLong(),
            isCancelled = { false }, onProgress = { d, t -> lastDone = d; lastTotal = t },
            tick = 1024
        )
        val sink = ps.readBytes()
        ps.finish()
        assertEquals(data.size, sink.size, "the wrapper is transparent — all bytes pass through")
        assertEquals(data.size.toLong(), ps.bytesRead)
        assertEquals(data.size.toLong(), lastDone, "finish() reports the final byte total")
        assertEquals(data.size.toLong(), lastTotal)
    }

    @Test
    fun throttlesReportsToOncePerTick() {
        // 4096 bytes read one KiB-buffer at a time with a 1 KiB tick → about 4 reports, not 4096.
        val data = ByteArray(4096)
        var reports = 0
        val ps = ProgressInputStream(
            ByteArrayInputStream(data), total = data.size.toLong(),
            isCancelled = { false }, onProgress = { _, _ -> reports++ }, tick = 1024
        )
        val buf = ByteArray(1024)
        while (ps.read(buf) >= 0) { /* drain */ }
        assertTrue(reports in 1..6, "expected a handful of throttled reports, got $reports")
    }

    @Test
    fun throwsCancelledWhenTheFlagTripsMidStream() {
        val data = ByteArray(1 shl 20)          // 1 MiB
        var readSoFar = 0L
        var cancel = false
        val ps = ProgressInputStream(
            ByteArrayInputStream(data), total = data.size.toLong(),
            isCancelled = { cancel }, onProgress = { d, _ -> readSoFar = d }, tick = 4096
        )
        val buf = ByteArray(4096)
        // Read a few chunks, then trip cancel and expect the very next read to throw.
        repeat(3) { ps.read(buf) }
        cancel = true
        assertFailsWith<CancelledException> { ps.read(buf) }
        assertTrue(readSoFar < data.size, "cancel landed before the stream was exhausted")
    }

    @Test
    fun anUnknownTotalIsCarriedThroughForTheIndeterminateBar() {
        val ps = ProgressInputStream(
            ByteArrayInputStream(ByteArray(10)), total = -1L,
            isCancelled = { false }, onProgress = { _, _ -> }, tick = 1
        )
        var seenTotal = 0L
        ps.readBytes()
        ProgressInputStream(ByteArrayInputStream(ByteArray(2)), total = -1L, isCancelled = { false },
            onProgress = { _, t -> seenTotal = t }, tick = 1).use { it.readBytes() }
        assertEquals(-1L, seenTotal, "an unknown total propagates as -1 for the UI to read")
    }
}
