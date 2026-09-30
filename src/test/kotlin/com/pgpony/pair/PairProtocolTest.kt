// PairProtocolTest.kt
// PGPony Desktop 3.0.0, F1: the pairing protocol (docs/F1_PAIRING_PROTOCOL.md) end to end over
// loopback sockets, plus the published test vectors.

package com.pgpony.pair

import com.ponydirect.PonyDirectWire
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PairProtocolTest {

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private val threads = java.util.concurrent.Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }

    private fun <T> async(block: () -> T): CompletableFuture<T> = CompletableFuture.supplyAsync(block, threads)

    private fun hostOn(server: ServerSocket): CompletableFuture<PairAttempt> = async {
        val s = server.accept()
        PairProtocol.host(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() })
    }

    private fun joinTo(port: Int): PairAttempt {
        val s = Socket(InetAddress.getLoopbackAddress(), port)
        return PairProtocol.join(s.getInputStream(), s.getOutputStream(), { s.soTimeout = it }, { s.close() })
    }

    private fun pair(): Pair<PairSession, PairSession> {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val host = hostOn(server)
            val joiner = joinTo(server.localPort)
            val h = host.get(10, TimeUnit.SECONDS)
            assertEquals(h.code, joiner.code)
            assertTrue(Regex("^\\d{3} \\d{3}$").matches(h.code))
            val hs = async { h.confirm() }
            val js = joiner.confirm()
            return hs.get(10, TimeUnit.SECONDS) to js
        }
    }

    @Test
    fun pairsAndMovesItemsBothWays() {
        val (host, joiner) = pair()
        host.sendInfo(PairInfo("Office Mac", "PGPony Desktop 3.0.0"))
        joiner.sendInfo(PairInfo("Linux box", "PGPony Desktop 3.0.0"))
        assertEquals("Linux box", (host.receive() as PairMessage.Info).info.name)
        assertEquals("Office Mac", (joiner.receive() as PairMessage.Info).info.name)

        // Host offers two items; the joiner takes one of them.
        val big = PairCrypto.randomBytes(2_500_000)
        val cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n".toByteArray()
        host.sendOffer(PairOffer(listOf(
            PairItem(1, PairItem.BACKUP, "backup.pgpony", null, big.size.toLong()),
            PairItem(2, PairItem.PUBLIC_KEY, "Alice", "AB".repeat(20), cert.size.toLong())
        )))
        val offer = (joiner.receive() as PairMessage.Offer).offer
        assertEquals(2, offer.items.size)
        joiner.sendAnswer(PairAnswer(listOf(1)))
        assertEquals(listOf(1), (host.receive() as PairMessage.Answer).answer.accept)

        val sent = async { host.sendItem(1, big) }
        var lastProgress = 0L
        val item = joiner.receive(mapOf(1 to big.size.toLong())) { _, n -> lastProgress = n } as PairMessage.Item
        sent.get(10, TimeUnit.SECONDS)
        assertEquals(1, item.id)
        assertContentEquals(big, item.bytes)
        assertEquals(big.size.toLong(), lastProgress)
        joiner.sendResult(PairResult(1, true))
        assertEquals(PairResult(1, true), (host.receive() as PairMessage.Result).result)

        // The other direction, in the same session.
        joiner.sendOffer(PairOffer(listOf(PairItem(7, PairItem.PUBLIC_KEY, "Bob", null, cert.size.toLong()))))
        (host.receive() as PairMessage.Offer)
        host.sendAnswer(PairAnswer(listOf(7)))
        (joiner.receive() as PairMessage.Answer)
        joiner.sendItem(7, cert)
        assertContentEquals(cert, (host.receive(mapOf(7 to cert.size.toLong())) as PairMessage.Item).bytes)

        joiner.sendBye()
        assertEquals(PairMessage.Bye, host.receive())
        joiner.close()
    }

    @Test
    fun anItemThatWasNotAcceptedEndsTheSession() {
        val (host, joiner) = pair()
        host.sendItem(3, "unasked".toByteArray())
        val e = assertFailsWith<PairException> { joiner.receive(emptyMap()) }
        assertEquals(PairFailure.PROTOCOL, e.failure)
        host.close()
    }

    @Test
    fun aRefusalOnEitherSideEndsTheAttempt() {
        for (refuser in PairRole.entries) {
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
                val hostF = hostOn(server)
                val joiner = joinTo(server.localPort)
                val host = hostF.get(10, TimeUnit.SECONDS)
                val (no, yes) = if (refuser == PairRole.HOST) host to joiner else joiner to host
                no.reject()
                assertEquals(PairFailure.REFUSED, yes.peerRefused.get(10, TimeUnit.SECONDS))
                val e = assertFailsWith<PairException> { yes.confirm() }
                assertEquals(PairFailure.REFUSED, e.failure, "$refuser refused")
            }
        }
    }

    @Test
    fun someoneInTheMiddleGetsTwoDifferentCodes() {
        // A relays between the joiner and the host, running its own exchange with each.
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { realHost ->
            ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { fakeHost ->
                val host = hostOn(realHost)
                val middleAsHost = hostOn(fakeHost)
                val middleAsJoiner = async { joinTo(realHost.localPort) }
                val joiner = joinTo(fakeHost.localPort)
                val codeOnJoiner = joiner.code
                val codeOnHost = host.get(10, TimeUnit.SECONDS).code
                assertEquals(codeOnJoiner, middleAsHost.get(10, TimeUnit.SECONDS).code)
                assertEquals(codeOnHost, middleAsJoiner.get(10, TimeUnit.SECONDS).code)
                assertNotEquals(codeOnJoiner, codeOnHost)
            }
        }
    }

    @Test
    fun aHostThatChangesItsNonceIsCaught() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val fake = async {
                server.accept().use { s ->
                    val wire = PairWire(s.getInputStream(), s.getOutputStream()) { s.close() }
                    wire.readExact(4)
                    wire.writeRaw(PairProtocol.MAGIC)
                    val join = wire.readFrame().second
                    val pk = PairCrypto.keyPair().public
                    wire.writeFrame(PairProtocol.ACCEPT, pk + PairCrypto.commit(ByteArray(32), pk, join.copyOfRange(1, 33)))
                    wire.readFrame()
                    wire.writeFrame(PairProtocol.NONCE_H, ByteArray(32) { 1 })
                    runCatching { wire.readFrame() }
                }
            }
            val e = assertFailsWith<PairException> { joinTo(server.localPort) }
            assertEquals(PairFailure.HANDSHAKE, e.failure)
            fake.get(10, TimeUnit.SECONDS)
        }
    }

    @Test
    fun aJoinerThatDoesNotSpeakPairingIsTurnedAway() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val host = hostOn(server)
            Socket(InetAddress.getLoopbackAddress(), server.localPort).use { it.getOutputStream().write("GET / HTTP/1.1\r\n\r\n".toByteArray()) }
            val e = assertFailsWith<Exception> { host.get(10, TimeUnit.SECONDS) }
            assertEquals(PairFailure.PROTOCOL, (e.cause as PairException).failure)
        }
    }

    @Test
    fun sealedMessagesMustArriveInOrder() {
        val key = PairCrypto.randomBytes(32)
        val m0 = PairCrypto.seal(key, 0, byteArrayOf(1, 2, 3))
        val m1 = PairCrypto.seal(key, 1, byteArrayOf(4))
        assertContentEquals(byteArrayOf(1, 2, 3), PairCrypto.open(key, 0, m0))
        assertFailsWith<PairException> { PairCrypto.open(key, 0, m1) }
        assertFailsWith<PairException> { PairCrypto.open(key, 1, m0) }
        m1[m1.size - 1] = (m1[m1.size - 1].toInt() xor 1).toByte()
        assertFailsWith<PairException> { PairCrypto.open(key, 1, m1) }
    }

    @Test
    fun theKeyConfirmationIsThePonyDirectIdentifyHandshake() {
        val k = PairCrypto.randomBytes(32)
        val nonce = PairCrypto.randomBytes(16)
        assertEquals(32, PonyDirectWire.identifyTag(k, nonce).size)
    }

    @Test
    fun publishedVectorsReproduce() {
        val text = javaClass.getResourceAsStream("/pairing/v1-vectors.json")!!.readBytes().toString(Charsets.UTF_8)
        val v = Json.parseToJsonElement(text).jsonObject.mapValues { it.value.jsonPrimitive.content }
        val skJ = unhex(v.getValue("sk_J"))
        val skH = unhex(v.getValue("sk_H"))
        val j = PairCrypto.keyPair(skJ)
        val h = PairCrypto.keyPair(skH)
        assertEquals(v["pk_J"], hex(j.public))
        assertEquals(v["pk_H"], hex(h.public))
        val nJ = unhex(v.getValue("n_J"))
        val nH = unhex(v.getValue("n_H"))
        assertEquals(v["commit"], hex(PairCrypto.commit(nH, h.public, j.public)))
        val t = PairCrypto.transcript(j.public, h.public, nJ, nH)
        assertEquals(v["T"], hex(t))
        val z = PairCrypto.agree(skH, j.public)!!
        assertEquals(v["Z"], hex(z))
        val keys = PairCrypto.derive(z, t)
        assertEquals(v["K"], hex(keys.pairKey))
        assertEquals(v["k_HJ"], hex(keys.hostToJoiner))
        assertEquals(v["k_JH"], hex(keys.joinerToHost))
        assertEquals(v["code"], PairCrypto.code(t))
        assertEquals(v["host_msg_0_sealed"], hex(PairCrypto.seal(keys.hostToJoiner, 0, unhex(v.getValue("host_msg_0_plaintext")))))
        assertEquals(v["joiner_msg_0_sealed"], hex(PairCrypto.seal(keys.joinerToHost, 0, unhex(v.getValue("joiner_msg_0_plaintext")))))
    }
}
