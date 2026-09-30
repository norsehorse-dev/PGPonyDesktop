package com.ponydirect

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import kotlin.concurrent.thread

/**
 * A single bound UDP socket with a background receive loop. One instance backs one
 * WAN session so the STUN-reflexive mapping and the punch traffic share one port.
 * The Swift twin is a POSIX socket; here it is java.net.DatagramSocket. For WAN we
 * use the default route (the internet-facing interface), so no interface pinning.
 */
class PonyDirectUdpSocket {

    data class Source(val host: String, val port: Int)

    private val socket = DatagramSocket()   // binds an ephemeral port on 0.0.0.0
    @Volatile private var running = false
    private var recvThread: Thread? = null

    /** Called on the receive thread for every datagram. */
    var onDatagram: ((ByteArray, Source) -> Unit)? = null

    /** The local port the OS bound (host candidates advertise this). */
    val localPort: Int get() = socket.localPort

    fun send(data: ByteArray, host: String, port: Int) {
        try {
            val addr = InetAddress.getByName(host)
            socket.send(DatagramPacket(data, data.size, InetSocketAddress(addr, port)))
        } catch (_: Exception) { /* drop; the ARQ/retry layer handles loss */ }
    }

    fun start() {
        if (running) return
        running = true
        recvThread = thread(name = "ponydirect-udp-recv", isDaemon = true) { loop() }
    }

    private fun loop() {
        val buf = ByteArray(2048)
        while (running) {
            try {
                val pkt = DatagramPacket(buf, buf.size)
                socket.receive(pkt)
                val data = buf.copyOfRange(0, pkt.length)
                val src = Source(pkt.address.hostAddress ?: "", pkt.port)
                onDatagram?.invoke(data, src)
            } catch (_: Exception) {
                if (!running) break
            }
        }
    }

    fun close() {
        running = false
        try { socket.close() } catch (_: Exception) {}
    }

    companion object {
        /** Local IPv4 host candidates (non-loopback interface addresses). */
        fun hostIPv4Addresses(): List<String> {
            val out = ArrayList<String>()
            try {
                for (nif in NetworkInterface.getNetworkInterfaces()) {
                    if (!nif.isUp || nif.isLoopback) continue
                    for (addr in nif.inetAddresses) {
                        if (addr is Inet4Address && !addr.isLoopbackAddress) {
                            val ip = addr.hostAddress ?: continue
                            if (ip.isNotEmpty() && ip != "0.0.0.0") out.add(ip)
                        }
                    }
                }
            } catch (_: Exception) {}
            return out
        }
    }
}
