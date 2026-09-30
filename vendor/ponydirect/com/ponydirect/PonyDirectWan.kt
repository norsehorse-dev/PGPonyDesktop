package com.ponydirect

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * The WAN path manager: one shared UDP socket, per-peer hole-punch sessions.
 * Gathers host + STUN-reflexive candidates, exchanges them over the app's sealed
 * signaling, punches with authenticated PROBE/PONG, and holds the mapping with
 * KEEPALIVE. M2 proves an authenticated path; envelope delivery is M3. The state
 * machine mirrors PonyDirectWan (Swift).
 */
class PonyDirectWan(
    private val stun: StunServer,
    private val keys: PonyDirectKeyProvider,
    private val signaling: PonyDirectSignaling,
) {

    enum class PathState { IDLE, GATHERING, PUNCHING, CONNECTED, FAILED }
    enum class Role { INITIATOR, RESPONDER }

    data class StunServer(val host: String, val port: Int)

    interface Delegate {
        fun onPathState(peerID: String, state: PathState)
        fun onPayload(peerID: String, payload: ByteArray)
        /** Bytes delivered in order over a reliable stream (bulk transfer). Default: ignored. */
        fun onStreamBytes(peerID: String, bytes: ByteArray) {}
        /** The inbound stream from this peer finished (all bytes delivered). Default: ignored. */
        fun onStreamReceiveComplete(peerID: String) {}
        /** The outbound stream to this peer finished (true) or gave up (false). Default: ignored. */
        fun onStreamSendComplete(peerID: String, success: Boolean) {}
    }

    var delegate: Delegate? = null

    private class Session(val peerID: String, val role: Role, var sessionNonce: ByteArray) {
        var remoteCandidates: MutableList<String> = ArrayList()
        var activeRemote: PonyDirectUdpSocket.Source? = null
        var state: PathState = PathState.IDLE
        var probeRounds = 0
        var offerRounds = 0
    }

    private class OutgoingMsg(
        val peerID: String,
        val sessionNonce: ByteArray,
        val chunks: List<ByteArray>,
        var roundsLeft: Int,
        val onComplete: ((Boolean) -> Unit)?,
    ) {
        val ackedBitmap = ByteArray(PonyDirectArq.bitmapLen(chunks.size))
    }

    private class Reassembly(val chunkCount: Int) {
        val chunks = arrayOfNulls<ByteArray>(chunkCount)
        val bitmap = ByteArray(PonyDirectArq.bitmapLen(chunkCount))
        var received = 0
    }

    private val socket = PonyDirectUdpSocket()
    private val exec = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "ponydirect-wan").apply { isDaemon = true }
    }
    private val sessions = ConcurrentHashMap<String, Session>()
    @Volatile private var stunTxn: ByteArray? = null
    @Volatile private var reflexive: String? = null
    private var hostCandidates: List<String> = emptyList()
    private var probeTask: ScheduledFuture<*>? = null
    private var offerTask: ScheduledFuture<*>? = null
    private var keepaliveTask: ScheduledFuture<*>? = null
    private var arqTask: ScheduledFuture<*>? = null
    private var nextMsgSeq = 1
    private val outgoing = HashMap<Int, OutgoingMsg>()
    private val incoming = HashMap<String, Reassembly>()
    private val completed = ArrayDeque<String>()
    private val completedKeys = HashSet<String>()
    private val streamEngines = HashMap<String, PonyDirectStreamEngine>()
    private val streamRecvDone = HashSet<String>()
    private val streamSendDone = HashSet<String>()
    private var streamTask: ScheduledFuture<*>? = null
    private val streamIntervalMs = 20L

    private val probeIntervalMs = 250L
    private val maxProbeRounds = 40
    private val keepaliveIntervalMs = 15_000L
    private val offerIntervalMs = 2_000L     // re-send the offer until answered
    private val maxOfferRounds = 15          // fast-retry burst (~30s), then slow back-off
    private val arqIntervalMs = 500L         // retransmit unacked chunks this often
    private val arqRounds = 20               // ~10s to deliver before giving up (relay covers it)
    private val maxChunks = 256              // 256 KB cap; larger payloads go by relay
    private val completedCap = 256

    init {
        socket.onDatagram = { data, source -> exec.execute { handleDatagram(data, source) } }
        socket.start()
    }

    /** Open a path to [peerID]. Initiator mints the session nonce and sends the offer. */
    fun open(peerID: String, role: Role) = exec.execute {
        val existing = sessions[peerID]
        if (existing != null) {
            // Already tracking this peer; if it is a not-yet-connected initiator,
            // make sure it is still offering (recover a stalled session without a
            // manual re-toggle).
            if (existing.role == Role.INITIATOR && existing.state != PathState.CONNECTED) ensureOfferTimer()
            return@execute
        }
        val nonce = if (role == Role.INITIATOR) PonyDirectWire.randomBytes(16) else ByteArray(0)
        val session = Session(peerID, role, nonce)
        sessions[peerID] = session
        setState(session, PathState.GATHERING)
        gatherCandidates()
        if (role == Role.INITIATOR) {
            // Send the offer now, then re-send on a timer until an answer arrives,
            // so the order the two sides enable WAN does not matter.
            sendOffer(session)
            ensureOfferTimer()
        }
    }

    fun close(peerID: String) = exec.execute {
        val s = sessions.remove(peerID) ?: return@execute
        setState(s, PathState.IDLE)
        streamEngines.remove(peerID)
        streamRecvDone.remove(peerID)
        streamSendDone.remove(peerID)
        if (sessions.isEmpty()) stopTimers()
    }

    fun handleSignal(signal: PonyDirectSignal, peerID: String) = exec.execute {
        when (signal.kind) {
            PonyDirectSignal.Kind.OFFER -> {
                val session = sessions.getOrPut(peerID) {
                    Session(peerID, Role.RESPONDER, signal.sessionNonce ?: ByteArray(0)).also {
                        setState(it, PathState.GATHERING); gatherCandidates()
                    }
                }
                signal.sessionNonce?.let { session.sessionNonce = it }
                session.remoteCandidates = merge(session.remoteCandidates, signal.candidates)
                sendAnswer(session)
                startPunching(session)
            }
            PonyDirectSignal.Kind.ANSWER -> {
                val session = sessions[peerID] ?: return@execute
                signal.sessionNonce?.let { session.sessionNonce = it }
                session.remoteCandidates = merge(session.remoteCandidates, signal.candidates)
                startPunching(session)
            }
            PonyDirectSignal.Kind.ICE -> {
                val session = sessions[peerID] ?: return@execute
                val c = signal.candidate ?: return@execute
                session.remoteCandidates = merge(session.remoteCandidates, listOf(c))
                startPunching(session)
            }
        }
    }

    // Candidate gathering ---------------------------------------------------

    /** Human-readable snapshot for on-device debugging. No secrets: candidates are ip:port only. */
    fun diagnostics(): String {
        val sb = StringBuilder()
        sb.append("STUN reflexive: ").append(reflexive ?: "NONE (no public addr)").append('\n')
        sb.append("host candidates: ").append(hostCandidates.size).append('\n')
        if (sessions.isEmpty()) sb.append("(no sessions yet)\n")
        for ((pid, s) in sessions) {
            sb.append("peer ").append(pid.take(10)).append("\u2026 state=").append(s.state.name.lowercase())
              .append(" remoteCands=").append(s.remoteCandidates.size)
              .append(" probe=").append(s.probeRounds).append('/').append(maxProbeRounds).append('\n')
        }
        return sb.toString().trimEnd()
    }

    private fun gatherCandidates() {
        if (hostCandidates.isEmpty()) {
            hostCandidates = PonyDirectUdpSocket.hostIPv4Addresses().map { "$it:${socket.localPort}" }
        }
        if (reflexive == null && stunTxn == null) {
            val txn = PonyDirectStun.newTransactionID()
            stunTxn = txn
            socket.send(PonyDirectStun.bindingRequest(txn), stun.host, stun.port)
            exec.schedule({
                if (reflexive == null) { stunTxn = null; flushPending() }
            }, 1, TimeUnit.SECONDS)
        }
    }

    private fun localCandidates(): List<String> {
        val all = ArrayList(hostCandidates)
        reflexive?.let { all.add(it) }
        return all
    }

    private fun sendOffer(session: Session) {
        signaling.sendSignal(
            PonyDirectSignal(PonyDirectSignal.Kind.OFFER, localCandidates(), session.sessionNonce), session.peerID
        )
    }

    private fun sendAnswer(session: Session) {
        signaling.sendSignal(
            PonyDirectSignal(PonyDirectSignal.Kind.ANSWER, localCandidates(), session.sessionNonce), session.peerID
        )
    }

    private fun flushPending() {
        for (s in sessions.values) {
            when (s.role) {
                Role.INITIATOR -> if (s.state == PathState.GATHERING) sendOffer(s)
                Role.RESPONDER -> if (s.state == PathState.GATHERING) sendAnswer(s)
            }
        }
    }

    // Punching --------------------------------------------------------------

    private fun startPunching(session: Session) {
        if (session.state != PathState.GATHERING && session.state != PathState.PUNCHING) return
        if (session.state != PathState.PUNCHING) setState(session, PathState.PUNCHING)
        ensureProbeTimer()
    }

    private fun ensureOfferTimer() {
        if (offerTask != null) return
        offerTask = exec.scheduleAtFixedRate({ offerTick() }, offerIntervalMs, offerIntervalMs, TimeUnit.MILLISECONDS)
    }

    private fun offerTick() {
        var anyWaiting = false
        for (session in sessions.values) {
            if (session.role != Role.INITIATOR || session.state != PathState.GATHERING) continue
            anyWaiting = true
            session.offerRounds++
            // Fast-retry burst (~30s), then back off to about every 16s and keep
            // trying while WAN is on and unanswered, so the peer can enable WAN at
            // any later time and still connect.
            if (session.offerRounds <= maxOfferRounds || session.offerRounds % 8 == 0) sendOffer(session)
        }
        if (!anyWaiting) { offerTask?.cancel(false); offerTask = null }
    }

    private fun ensureProbeTimer() {
        if (probeTask != null) return
        probeTask = exec.scheduleAtFixedRate({ probeTick() }, 0, probeIntervalMs, TimeUnit.MILLISECONDS)
    }

    private fun probeTick() {
        var anyPunching = false
        for (session in sessions.values) {
            if (session.state != PathState.PUNCHING) continue
            anyPunching = true
            val pairKey = keys.pairKey(session.peerID) ?: continue
            session.probeRounds++
            if (session.probeRounds > maxProbeRounds) {
                // Punch attempt exhausted. Fall back to re-offering (fresh candidates)
                // rather than a terminal failure, so it keeps trying while WAN is on
                // and reconnects on its own after a network change, no re-toggle.
                session.probeRounds = 0
                session.remoteCandidates = ArrayList()
                setState(session, PathState.GATHERING)
                ensureOfferTimer()
                continue
            }
            for (cand in session.remoteCandidates) {
                val hp = splitHostPort(cand) ?: continue
                val probeNonce = PonyDirectWire.randomBytes(16)
                socket.send(PonyDirectPunch.probe(pairKey, session.sessionNonce, probeNonce), hp.first, hp.second)
            }
        }
        if (!anyPunching) stopProbeTimer()
    }

    private fun stopProbeTimer() { probeTask?.cancel(false); probeTask = null }

    // Datagram intake -------------------------------------------------------

    private fun handleDatagram(data: ByteArray, source: PonyDirectUdpSocket.Source) {
        if (data.isEmpty()) return
        val txn = stunTxn
        if (txn != null) {
            val mapped = PonyDirectStun.parseResponse(data, txn)
            if (mapped != null) {
                stunTxn = null
                reflexive = "${mapped.ip}:${mapped.port}"
                for (s in sessions.values) {
                    signaling.sendSignal(PonyDirectSignal(PonyDirectSignal.Kind.ICE, candidate = reflexive), s.peerID)
                }
                flushPending()
                return
            }
        }
        when (data[0]) {
            PonyDirectArq.DATA -> {
                val dp = PonyDirectArq.parseData(data) ?: return
                val session = sessions.values.firstOrNull { PonyDirectWire.constantTimeEquals(it.sessionNonce, dp.sessionNonce) } ?: return
                val pairKey = keys.pairKey(session.peerID) ?: return
                if (!PonyDirectArq.verifyData(dp, pairKey)) return
                handleData(dp, session, pairKey)
                return
            }
            PonyDirectArq.ACK -> {
                val ap = PonyDirectArq.parseAck(data) ?: return
                val session = sessions.values.firstOrNull { PonyDirectWire.constantTimeEquals(it.sessionNonce, ap.sessionNonce) } ?: return
                val pairKey = keys.pairKey(session.peerID) ?: return
                if (!PonyDirectArq.verifyAck(ap, pairKey)) return
                handleAck(ap, session)
                return
            }
        }
        val b0 = data[0]
        if (b0 == PonyDirectStream.SDATA || b0 == PonyDirectStream.SACK || b0 == PonyDirectStream.SFIN || b0 == PonyDirectStream.SRST) {
            if (data.size < 17) return
            val nonce = data.copyOfRange(1, 17)
            val session = sessions.values.firstOrNull { PonyDirectWire.constantTimeEquals(it.sessionNonce, nonce) } ?: return
            val e = streamEngine(session) ?: return
            e.onWireDatagram(nowMs(), data)
            return
        }
        val parsed = PonyDirectPunch.parse(data) ?: return
        val session = sessions.values.firstOrNull {
            PonyDirectWire.constantTimeEquals(it.sessionNonce, parsed.sessionNonce)
        } ?: return
        val pairKey = keys.pairKey(session.peerID) ?: return

        when (parsed.type) {
            PonyDirectPunch.PROBE -> {
                if (!PonyDirectPunch.verifyProbe(parsed, pairKey)) return
                val pong = PonyDirectPunch.pong(pairKey, session.sessionNonce, parsed.probeNonce)
                socket.send(pong, source.host, source.port)
                markConnected(session, source)
            }
            PonyDirectPunch.PONG -> {
                if (!PonyDirectPunch.verifyPong(parsed, pairKey)) return
                markConnected(session, source)
            }
            PonyDirectPunch.KEEPALIVE -> { /* NAT-hold only */ }
        }
    }

    private fun markConnected(session: Session, remote: PonyDirectUdpSocket.Source) {
        session.activeRemote = remote
        if (session.state != PathState.CONNECTED) setState(session, PathState.CONNECTED)
        ensureKeepalive()
        if (sessions.values.none { it.state == PathState.PUNCHING }) stopProbeTimer()
    }

    // Keepalive -------------------------------------------------------------

    private fun ensureKeepalive() {
        if (keepaliveTask != null) return
        keepaliveTask = exec.scheduleAtFixedRate(
            { keepaliveTick() }, keepaliveIntervalMs, keepaliveIntervalMs, TimeUnit.MILLISECONDS
        )
    }

    private fun keepaliveTick() {
        for (session in sessions.values) {
            if (session.state != PathState.CONNECTED) continue
            val r = session.activeRemote ?: continue
            socket.send(PonyDirectPunch.keepalive(session.sessionNonce), r.host, r.port)
        }
    }

    private fun stopTimers() {
        stopProbeTimer()
        offerTask?.cancel(false); offerTask = null
        keepaliveTask?.cancel(false); keepaliveTask = null
        arqTask?.cancel(false); arqTask = null
        streamTask?.cancel(false); streamTask = null
    }

    // Public helpers --------------------------------------------------------

    /** Queue a payload for reliable delivery over the connected direct path. Returns
     *  false (so the caller uses the relay) if there is no live path or the payload
     *  exceeds the direct-path size cap. */
    fun sendPayload(payload: ByteArray, peerID: String, onComplete: ((Boolean) -> Unit)? = null): Boolean = try {
        exec.submit(java.util.concurrent.Callable {
            val s = sessions[peerID] ?: return@Callable false
            val remote = s.activeRemote ?: return@Callable false
            if (s.state != PathState.CONNECTED) return@Callable false
            val pairKey = keys.pairKey(peerID) ?: return@Callable false
            val chunks = PonyDirectArq.chunk(payload)
            if (chunks.size > maxChunks) return@Callable false
            val seq = nextMsgSeq++
            val msg = OutgoingMsg(peerID, s.sessionNonce, chunks, arqRounds, onComplete)
            outgoing[seq] = msg
            sendUnacked(seq, msg, pairKey, remote)
            ensureArqTimer()
            true
        }).get()
    } catch (e: Exception) { false }

    private fun sendUnacked(seq: Int, msg: OutgoingMsg, pairKey: ByteArray, remote: PonyDirectUdpSocket.Source) {
        val count = msg.chunks.size
        for (i in 0 until count) {
            if (PonyDirectArq.bitmapGet(msg.ackedBitmap, i)) continue
            socket.send(
                PonyDirectArq.data(pairKey, msg.sessionNonce, seq, i, count, msg.chunks[i]),
                remote.host, remote.port
            )
        }
    }

    private fun ensureArqTimer() {
        if (arqTask != null) return
        arqTask = exec.scheduleAtFixedRate({ arqTick() }, arqIntervalMs, arqIntervalMs, TimeUnit.MILLISECONDS)
    }

    private fun arqTick() {
        val it = outgoing.entries.iterator()
        while (it.hasNext()) {
            val (seq, msg) = it.next()
            val s = sessions[msg.peerID]
            val remote = s?.activeRemote
            val pairKey = keys.pairKey(msg.peerID)
            if (s == null || s.state != PathState.CONNECTED || remote == null || pairKey == null) { it.remove(); msg.onComplete?.invoke(false); continue }
            msg.roundsLeft--
            if (msg.roundsLeft <= 0) { it.remove(); msg.onComplete?.invoke(false); continue }
            sendUnacked(seq, msg, pairKey, remote)
        }
        if (outgoing.isEmpty()) { arqTask?.cancel(false); arqTask = null }
    }

    private fun markCompleted(key: String) {
        if (completedKeys.add(key)) {
            completed.addLast(key)
            while (completed.size > completedCap) { completedKeys.remove(completed.removeFirst()) }
        }
    }

    private fun handleData(dp: PonyDirectArq.DataPacket, session: Session, pairKey: ByteArray) {
        val key = "${session.peerID}#${dp.msgSeq}"
        val count = dp.chunkCount
        if (count <= 0 || count > maxChunks) return
        if (completedKeys.contains(key)) {
            val full = ByteArray(PonyDirectArq.bitmapLen(count)) { 0xFF.toByte() }
            session.activeRemote?.let { remote ->
                socket.send(PonyDirectArq.ack(pairKey, session.sessionNonce, dp.msgSeq, count, full), remote.host, remote.port)
            }
            return
        }
        val r = incoming.getOrPut(key) { Reassembly(count) }
        val idx = dp.chunkIndex
        if (idx < r.chunkCount && r.chunks[idx] == null) {
            r.chunks[idx] = dp.payload
            PonyDirectArq.bitmapSet(r.bitmap, idx)
            r.received++
        }
        session.activeRemote?.let { remote ->
            socket.send(PonyDirectArq.ack(pairKey, session.sessionNonce, dp.msgSeq, r.chunkCount, r.bitmap), remote.host, remote.port)
        }
        if (r.received == r.chunkCount) {
            val out = java.io.ByteArrayOutputStream()
            for (c in r.chunks) if (c != null) out.write(c)
            incoming.remove(key)
            markCompleted(key)
            delegate?.onPayload(session.peerID, out.toByteArray())
        }
    }

    private fun handleAck(ap: PonyDirectArq.AckPacket, session: Session) {
        val msg = outgoing[ap.msgSeq] ?: return
        if (msg.peerID != session.peerID) return
        val count = msg.chunks.size
        for (i in 0 until count) if (PonyDirectArq.bitmapGet(ap.bitmap, i)) PonyDirectArq.bitmapSet(msg.ackedBitmap, i)
        var allAcked = true
        for (i in 0 until count) if (!PonyDirectArq.bitmapGet(msg.ackedBitmap, i)) { allAcked = false; break }
        if (allAcked) { outgoing.remove(ap.msgSeq); msg.onComplete?.invoke(true) }
    }

    // Reliable stream (bulk transfer) ---------------------------------------

    /** Open (or reuse) a reliable byte-stream to a connected peer. */
    fun openStream(peerID: String) = exec.execute {
        val s = sessions[peerID] ?: return@execute
        streamEngine(s)
    }

    /** Append bytes to the outbound stream to a peer. */
    fun writeStream(bytes: ByteArray, peerID: String) = exec.execute {
        val s = sessions[peerID] ?: return@execute
        streamEngine(s)?.write(bytes)
    }

    /** Signal end-of-stream for the outbound stream to a peer. */
    fun finishStream(peerID: String) = exec.execute {
        val s = sessions[peerID] ?: return@execute
        streamEngine(s)?.finishSending()
    }

    private fun streamEngine(session: Session): PonyDirectStreamEngine? {
        streamEngines[session.peerID]?.let { return it }
        val pairKey = keys.pairKey(session.peerID) ?: return null
        val peerID = session.peerID
        val e = PonyDirectStreamEngine(pairKey, session.sessionNonce) { frame ->
            val remote = sessions[peerID]?.activeRemote
            if (remote != null) socket.send(frame, remote.host, remote.port)
        }
        streamEngines[peerID] = e
        ensureStreamTimer()
        return e
    }

    private fun ensureStreamTimer() {
        if (streamTask != null) return
        streamTask = exec.scheduleAtFixedRate({ streamTick() }, streamIntervalMs, streamIntervalMs, TimeUnit.MILLISECONDS)
    }

    private fun streamTick() {
        for ((peerID, e) in streamEngines) {
            e.tick(nowMs())
            val bytes = e.read(1 shl 20)
            if (bytes.isNotEmpty()) delegate?.onStreamBytes(peerID, bytes)
            if (e.recvComplete() && streamRecvDone.add(peerID)) delegate?.onStreamReceiveComplete(peerID)
            if (e.sendComplete() && streamSendDone.add(peerID)) delegate?.onStreamSendComplete(peerID, true)
        }
        if (streamEngines.isEmpty()) { streamTask?.cancel(false); streamTask = null }
    }

    private fun nowMs(): Long = System.nanoTime() / 1_000_000L

    fun stateOf(peerID: String): PathState = sessions[peerID]?.state ?: PathState.IDLE

    private fun setState(session: Session, state: PathState) {
        session.state = state
        delegate?.onPathState(session.peerID, state)
    }

    private fun merge(a: MutableList<String>, b: List<String>): MutableList<String> {
        val seen = HashSet(a)
        for (c in b) if (seen.add(c)) a.add(c)
        return a
    }

    private fun splitHostPort(s: String): Pair<String, Int>? {
        val idx = s.lastIndexOf(':')
        if (idx <= 0) return null
        val host = s.substring(0, idx)
        val port = s.substring(idx + 1).toIntOrNull() ?: return null
        return host to port
    }
}
