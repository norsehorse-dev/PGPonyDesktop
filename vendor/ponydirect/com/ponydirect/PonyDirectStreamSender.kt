package com.ponydirect

import kotlin.math.abs

/** One thing the sender wants to put on the wire. The driver turns these into SDATA / SFIN frames. */
sealed class StreamOut {
    class Data(val seq: Long, val payload: ByteArray) : StreamOut()
    class Fin(val finalSeq: Long) : StreamOut()
}

/**
 * Sender half of the stream ARQ, with congestion control. Chunk-aligned windowed send over the
 * outgoing byte buffer:
 *   - RFC 6298 RTO retransmit (Karn's algorithm: no RTT sample on retransmits).
 *   - Congestion window: slow start (exponential) up to ssthresh, then AIMD congestion avoidance
 *     (about one MSS per RTT). A timeout halves ssthresh and restarts slow start at one MSS.
 *   - Packet pacing: a token bucket at cwnd/srtt spreads a window across the RTT instead of bursting.
 *   - Receiver flow control (rwnd): the effective window is min(cwnd, rwnd).
 * Crypto-free: it emits (seq, payload) segments and a FIN marker, so it composes with
 * PonyDirectStreamReceiver in tests and the driver builds the wire frames. Byte-identical intent to
 * the Swift twin.
 */
class PonyDirectStreamSender(
    initialCwndBytes: Int = 10 * PonyDirectStream.MAX_PAYLOAD,        // IW10
    initialSsthreshBytes: Int = 64 * PonyDirectStream.MAX_PAYLOAD,
    private val maxCwndBytes: Int = 4 * 1024 * 1024,
    private val minRtoMs: Long = 200,
    private val maxRtoMs: Long = 10_000,
    initialRtoMs: Long = 1000,
) {
    private val chunk = PonyDirectStream.MAX_PAYLOAD   // 1024

    private var data = ByteArray(0)
    private var finished = false

    private var baseChunk = 0
    private val acked = HashSet<Int>()
    private class InFlight(var sentAt: Long, var retransmitted: Boolean)
    private val inflight = HashMap<Int, InFlight>()

    private var rwndBytes = 1 shl 20

    private var cwnd = initialCwndBytes
    private var ssthresh = initialSsthreshBytes
    private var lastLossMs: Long? = null

    private var pacingTokens = initialCwndBytes.toDouble()
    private var lastPollMs = Long.MIN_VALUE

    private var rtoMs = initialRtoMs
    private var srtt = -1.0
    private var rttvar = 0.0

    val cwndBytes: Int get() = cwnd
    val ssthreshBytes: Int get() = ssthresh

    fun write(bytes: ByteArray) { if (finished) return; data += bytes }
    fun finish() { finished = true }

    private fun chunksReady(): Int = if (finished) (data.size + chunk - 1) / chunk else data.size / chunk
    private fun chunkBytes(i: Int): ByteArray = data.copyOfRange(i * chunk, minOf((i + 1) * chunk, data.size))
    private fun totalBytes(): Long = data.size.toLong()

    fun isDone(): Boolean = finished && baseChunk >= chunksReady()

    fun poll(nowMs: Long): List<StreamOut> {
        refillTokens(nowMs)
        val out = ArrayList<StreamOut>()
        val windowChunks = maxOf(1, minOf(cwnd, rwndBytes) / chunk)
        val ready = chunksReady()
        val last = minOf(baseChunk + windowChunks, ready)
        var i = baseChunk
        while (i < last) {
            if (!acked.contains(i)) {
                val inf = inflight[i]
                if (inf == null) {
                    if (pacingTokens < chunk) break              // paced out; remaining are new/acked
                    out.add(StreamOut.Data(i.toLong() * chunk, chunkBytes(i)))
                    inflight[i] = InFlight(nowMs, false)
                    pacingTokens -= chunk
                } else if (nowMs - inf.sentAt >= rtoMs) {
                    onLoss(nowMs)
                    out.add(StreamOut.Data(i.toLong() * chunk, chunkBytes(i)))
                    inf.sentAt = nowMs
                    inf.retransmitted = true
                    rtoMs = minOf(rtoMs * 2, maxRtoMs)           // exponential backoff on timeout
                }
            }
            i++
        }
        if (finished && baseChunk >= ready) out.add(StreamOut.Fin(totalBytes()))
        return out
    }

    fun onAck(nowMs: Long, cumAck: Long, rwnd: Int, blocks: List<PonyDirectStream.SackBlock>) {
        rwndBytes = rwnd
        var newlyAcked = 0
        val ready = chunksReady()
        val newBase = if (finished && cumAck >= totalBytes()) ready else (cumAck / chunk).toInt()
        var i = baseChunk
        while (i < newBase) { acked.remove(i); if (ackChunk(i, nowMs)) newlyAcked += chunk; i++ }
        baseChunk = maxOf(baseChunk, newBase)
        for (b in blocks) {
            val first = (b.start / chunk).toInt()
            val count = ((b.end - b.start + chunk - 1) / chunk).toInt()
            for (k in first until first + count) {
                if (k >= baseChunk && !acked.contains(k)) { if (ackChunk(k, nowMs)) newlyAcked += chunk; acked.add(k) }
            }
        }
        while (acked.contains(baseChunk)) { acked.remove(baseChunk); baseChunk++ }
        if (newlyAcked > 0) grow(newlyAcked)
    }

    /** @return true if this chunk was outstanding (genuinely newly acked). */
    private fun ackChunk(i: Int, nowMs: Long): Boolean {
        val inf = inflight.remove(i) ?: return false
        if (!inf.retransmitted) sampleRtt(nowMs - inf.sentAt)   // Karn: skip retransmits
        return true
    }

    private fun grow(newlyAckedBytes: Int) {
        cwnd = if (cwnd < ssthresh) cwnd + newlyAckedBytes                     // slow start (exponential)
        else cwnd + maxOf(1, chunk * newlyAckedBytes / cwnd)                   // congestion avoidance (~1 MSS/RTT)
        if (cwnd > maxCwndBytes) cwnd = maxCwndBytes
    }

    private fun onLoss(nowMs: Long) {
        val guard = if (srtt > 0) srtt else 1000.0
        val last = lastLossMs
        if (last == null || nowMs - last >= guard) {            // one reduction per loss window
            ssthresh = maxOf(cwnd / 2, 2 * chunk)
            cwnd = chunk                                        // timeout: restart slow start at 1 MSS
            lastLossMs = nowMs
            if (pacingTokens > cwnd) pacingTokens = cwnd.toDouble()
        }
    }

    private fun refillTokens(nowMs: Long) {
        if (lastPollMs == Long.MIN_VALUE) { lastPollMs = nowMs; return }
        val dt = nowMs - lastPollMs
        if (dt > 0) {
            val rtt = if (srtt > 0) srtt else 50.0
            val rate = cwnd / rtt                              // bytes per ms
            pacingTokens = minOf(cwnd.toDouble(), pacingTokens + rate * dt)
            lastPollMs = nowMs
        }
    }

    private fun sampleRtt(r: Long) {
        val rd = r.toDouble()
        if (srtt < 0) { srtt = rd; rttvar = rd / 2 }
        else { rttvar = 0.75 * rttvar + 0.25 * abs(srtt - rd); srtt = 0.875 * srtt + 0.125 * rd }
        rtoMs = (srtt + 4 * rttvar).toLong().coerceIn(minRtoMs, maxRtoMs)
    }
}
