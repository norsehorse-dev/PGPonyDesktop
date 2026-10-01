// SocksBridgeTest.kt
// SUPPLY-1 and SUPPLY-6 regressions: with a SOCKS proxy set, every request reaches the proxy
// with the host NAME (SOCKS5 address type 3), never an address looked up on this machine,
// and the SOCKS sign-in never carries the OS login name. A fake SOCKS5 server records what
// each connection asked for and then answers as a tiny HTTP origin.
//
// "localhost" is the probe: it resolves locally, so a client that looks names up before the
// SOCKS handshake would send address type 1 (127.0.0.1) instead of the name.

package com.pgpony.desktop

import com.pgpony.android.network.HttpClientFactory
import com.pgpony.android.network.OfflineMode
import com.pgpony.android.network.ProxyPrefs
import com.pgpony.android.network.SocksBridge
import com.pgpony.android.network.UrlKeyFetcher
import com.pgpony.android.PGPonyApp
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SocksBridgeTest {

    /** What one SOCKS connection asked for. */
    class Seen(
        val methods: List<Int>,
        val user: String?,
        val pass: String?,
        val atyp: Int,
        val host: String,
        val port: Int,
        @Volatile var head: String? = null
    )

    /**
     * A SOCKS5 server that, like a hostile listener, picks user/password whenever it is
     * offered, and otherwise no-auth. After CONNECT it answers one HTTP request.
     */
    class FakeSocks : Closeable {
        private val server = ServerSocket(0, 50, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
        val port: Int get() = server.localPort
        val seen = CopyOnWriteArrayList<Seen>()

        init {
            val t = Thread {
                while (!server.isClosed) {
                    val s = try { server.accept() } catch (e: IOException) { break }
                    Thread { serve(s) }.apply { isDaemon = true }.start()
                }
            }
            t.isDaemon = true
            t.start()
        }

        private fun serve(s: Socket) {
            s.use {
                s.soTimeout = 10_000
                val input = DataInputStream(s.getInputStream())
                val out = s.getOutputStream()
                if (input.readUnsignedByte() != 5) return
                val n = input.readUnsignedByte()
                val methods = (0 until n).map { input.readUnsignedByte() }
                var user: String? = null
                var pass: String? = null
                if (2 in methods) {
                    out.write(byteArrayOf(5, 2)); out.flush()
                    input.readUnsignedByte()
                    user = String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                    pass = String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                    out.write(byteArrayOf(1, 0)); out.flush()
                } else if (0 in methods) {
                    out.write(byteArrayOf(5, 0)); out.flush()
                } else {
                    out.write(byteArrayOf(5, 0xFF.toByte())); out.flush(); return
                }
                input.readUnsignedByte(); input.readUnsignedByte(); input.readUnsignedByte()
                val atyp = input.readUnsignedByte()
                val host = when (atyp) {
                    1 -> ByteArray(4).also { input.readFully(it) }.joinToString(".") { (it.toInt() and 0xff).toString() }
                    3 -> String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                    4 -> InetAddress.getByAddress(ByteArray(16).also { input.readFully(it) }).hostAddress
                    else -> return
                }
                val port = (input.readUnsignedByte() shl 8) or input.readUnsignedByte()
                val record = Seen(methods, user, pass, atyp, host, port)
                seen.add(record)
                out.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)); out.flush()
                // Now the origin: one plain HTTP answer. A TLS ClientHello (0x16) is just closed.
                val first = try { input.read() } catch (e: IOException) { -1 }
                if (first < 0 || first == 0x16) return
                val rest = try { SocksBridge.readHead(input, 64 * 1024) } catch (e: IOException) { null } ?: return
                val head = first.toChar() + rest
                record.head = head
                out.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello".toByteArray())
                out.flush()
                // Hold the connection open: the bridge must still end the exchange.
                try { while (input.read() >= 0) { } } catch (e: IOException) { }
            }
        }

        override fun close() = server.close()
    }

    private lateinit var fake: FakeSocks

    @BeforeTest
    fun setUp() {
        ProxyPrefs.prefsOverride = MemoryPreferences()
        OfflineMode.prefsOverride = MemoryPreferences()
        fake = FakeSocks()
        HttpClientFactory.invalidate()
    }

    @AfterTest
    fun tearDown() {
        HttpClientFactory.invalidate()
        fake.close()
        ProxyPrefs.prefsOverride = null
        OfflineMode.prefsOverride = null
    }

    private fun useFakeProxy(user: String = "", pass: String = "") {
        val app = PGPonyApp.instance
        ProxyPrefs.setMode(app, ProxyPrefs.MODE_CUSTOM)
        ProxyPrefs.setCustom(app, "127.0.0.1", fake.port)
        ProxyPrefs.setCredentials(app, user, pass)
        HttpClientFactory.invalidate()
    }

    @Test
    fun supply1PlainHttpReachesTheProxyByName() = runBlocking {
        useFakeProxy()
        val body = HttpClientFactory.client().get("http://localhost:8123/pks/lookup?op=get").bodyAsText()
        assertEquals("hello", body)
        val s = fake.seen.single()
        assertEquals(3, s.atyp, "the host must go to the proxy as a name")
        assertEquals("localhost", s.host)
        assertEquals(8123, s.port)
        val head = assertNotNull(s.head)
        assertEquals("GET /pks/lookup?op=get HTTP/1.1", head.lines().first())
        assertTrue(head.contains("\r\nConnection: close"), head)
        assertFalse(head.lowercase().contains("proxy-connection"), head)
    }

    @Test
    fun supply1HttpsReachesTheProxyByName() {
        useFakeProxy()
        runCatching { runBlocking { HttpClientFactory.client().get("https://localhost:8443/") } }
        val s = fake.seen.single()
        assertEquals(3, s.atyp)
        assertEquals("localhost", s.host)
        assertEquals(8443, s.port)
    }

    @Test
    fun supply1OnionNameGoesToTheProxyUnresolved() = runBlocking {
        useFakeProxy()
        val onion = "pgponyisur7gxcrfw5ofpjr2sepqul3zgbs66rrd3ughk5qvi4a3t5id.onion"
        HttpClientFactory.client().get("http://$onion/vks/v1/by-email/a%40example.org").bodyAsText()
        val s = fake.seen.single()
        assertEquals(3, s.atyp)
        assertEquals(onion, s.host)
        assertEquals(80, s.port)
    }

    @Test
    fun supply1RequestsInARowEachReachTheProxyByName() = runBlocking {
        useFakeProxy()
        val client = HttpClientFactory.client()
        assertEquals("hello", client.get("http://localhost:8124/a").bodyAsText())
        assertEquals("hello", client.get("http://localhost:8125/b").bodyAsText())
        assertEquals(listOf("localhost:8124", "localhost:8125"), fake.seen.map { "${it.host}:${it.port}" })
        assertTrue(fake.seen.all { it.atyp == 3 })
    }

    @Test
    fun supply1OnionWithoutAProxyIsRefusedBeforeAnySocket() {
        val e = assertFailsWith<IOException> {
            runBlocking { HttpClientFactory.client().get("http://pgponyisur7gxcrfw5ofpjr2sepqul3zgbs66rrd3ughk5qvi4a3t5id.onion/") }
        }
        assertTrue(e.message!!.contains(".onion"), e.message)
        assertTrue(fake.seen.isEmpty())
    }

    @Test
    fun supply1OnionLinksNeedAProxy() {
        val link = "http://pgponyisur7gxcrfw5ofpjr2sepqul3zgbs66rrd3ughk5qvi4a3t5id.onion/key.asc"
        assertNotNull(UrlKeyFetcher.allowedUri(link, onionReachable = true))
        assertNull(UrlKeyFetcher.allowedUri(link, onionReachable = false))
        assertNull(UrlKeyFetcher.allowedUri(link.replace("http:", "https:"), onionReachable = false))
        assertNotNull(UrlKeyFetcher.allowedUri("https://example.org/key.asc", onionReachable = false))
    }

    @Test
    fun supply1DeadProxyFailsClosed() {
        val dead = ServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { it.localPort }
        val app = PGPonyApp.instance
        ProxyPrefs.setMode(app, ProxyPrefs.MODE_CUSTOM)
        ProxyPrefs.setCustom(app, "127.0.0.1", dead)
        HttpClientFactory.invalidate()
        assertFailsWith<IOException> {
            runBlocking { HttpClientFactory.client().get("https://localhost:8443/") }
        }
        val status = runBlocking { HttpClientFactory.client().get("http://localhost:8123/").status.value }
        assertEquals(502, status)
    }

    @Test
    fun supply6NoCredentialsOffersOnlyNoAuth() = runBlocking {
        useFakeProxy()
        HttpClientFactory.client().get("http://localhost:8123/").bodyAsText()
        val s = fake.seen.single()
        assertEquals(listOf(0), s.methods, "only no-auth may be offered without a user/pass pair")
        assertNull(s.user, "no user name may be sent")
    }

    @Test
    fun supply6CredentialsAreUsedWhenSet() = runBlocking {
        useFakeProxy("isolation-id", "secret")
        HttpClientFactory.client().get("http://localhost:8123/").bodyAsText()
        val s = fake.seen.single()
        assertTrue(2 in s.methods)
        assertEquals("isolation-id", s.user)
        assertEquals("secret", s.pass)
    }

    @Test
    fun addressEncoding() {
        fun enc(host: String) = ByteArrayOutputStream().also { SocksBridge.writeAddress(it, host) }.toByteArray().toList()
        assertEquals(listOf<Byte>(1, 10, 0, 0, 5), enc("10.0.0.5"))
        assertEquals(4.toByte(), enc("[::1]")[0])
        assertEquals(17, enc("::1").size)
        val name = enc("keys.pgpony.app")
        assertEquals(3.toByte(), name[0])
        assertEquals(15.toByte(), name[1])
        assertEquals(3.toByte(), enc("bücher.example")[0])
        assertFailsWith<IOException> { SocksBridge.writeAddress(ByteArrayOutputStream(), "300.1.1.1") }
        assertFailsWith<IOException> { SocksBridge.writeAddress(ByteArrayOutputStream(), "") }
        // Text that only looks like an IPv6 address is refused, never handed to a resolver.
        assertFailsWith<IOException> { SocksBridge.writeAddress(ByteArrayOutputStream(), "[abc:def]") }
        assertFailsWith<IOException> { SocksBridge.writeAddress(ByteArrayOutputStream(), "1::2::3") }
    }

    @Test
    fun ipv6LiteralsParseWithoutALookup() {
        fun v6(text: String) = SocksBridge.parseIpv6(text)?.toList()
        fun jdk(text: String) = InetAddress.getByName("[$text]").address.let { a ->
            if (a.size == 4) (ByteArray(10) + byteArrayOf(-1, -1) + a).toList() else a.toList()
        }
        for (text in listOf("::", "::1", "1::", "2001:db8::1", "2001:db8:0:0:0:0:2:1", "fe80::1:2:3:4:5",
            "1:2:3:4:5:6:7:8", "::ffff:192.0.2.1", "64:ff9b::192.0.2.33", "ABCD:ef01::")) {
            assertEquals(jdk(text), v6(text), text)
        }
        for (bad in listOf("", ":", ":::", "1:2", "1::2::3", ":1::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8",
            "12345::", "g::1", "1.2.3.4::", "::1.2.3.256", "::1.2.3.4:5", "fe80::1%eth0")) {
            assertNull(v6(bad), bad)
        }
    }

    @Test
    fun requestTargets() {
        assertEquals(Pair("example.org", 443), SocksBridge.splitHostPort("example.org:443", -1))
        assertEquals(Pair("::1", 8080), SocksBridge.splitHostPort("[::1]:8080", -1))
        assertNull(SocksBridge.splitHostPort("example.org", -1))
        assertNull(SocksBridge.splitHostPort("user@example.org:443", -1))
        assertNull(SocksBridge.splitHostPort("example.org:99999", -1))
        val a = assertNotNull(SocksBridge.parseAbsoluteHttp("http://Example.org/pks/lookup?op=get#x"))
        assertEquals("Example.org", a.host)
        assertEquals(80, a.port)
        assertEquals("/pks/lookup?op=get", a.path)
        val b = assertNotNull(SocksBridge.parseAbsoluteHttp("http://example.org:11371?x=1"))
        assertEquals(11371, b.port)
        assertEquals("/?x=1", b.path)
        assertNull(SocksBridge.parseAbsoluteHttp("https://example.org/"))
        assertNull(SocksBridge.parseAbsoluteHttp("/relative"))
    }

    @Test
    fun responseHeadIsMadeClosing() {
        val out = SocksBridge.closingResponseHead("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nContent-Length: 5")
        assertEquals("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\nProxy-Connection: close\r\n\r\n", out)
    }
}
