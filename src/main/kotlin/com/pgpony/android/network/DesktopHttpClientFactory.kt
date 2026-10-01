// DesktopHttpClientFactory.kt — DESKTOP TWIN of network/HttpClientFactory.kt (vendored copy
// excluded: Context-typed). Declares the same `object HttpClientFactory`; the body mirrors the
// Android build verbatim: same ktor Android engine (plain JVM), same timeout split, same
// SOCKS wiring through the shared SocksBridge, same signature-keyed cache. File name differs
// from the excluded file (D1 Fix1 rule). Vendored callers use the no-arg client(); a
// PGPonyApp-typed overload covers the rest.

package com.pgpony.android.network

import com.pgpony.android.PGPonyApp
import io.ktor.client.HttpClient
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin

/** Thrown when a request is attempted while offline mode is on. The network
 *  call sites already catch IOException and degrade to a null/failed result,
 *  so no request escapes and nothing crashes. */
class OfflineModeException : java.io.IOException(
    "PGPony offline mode is on; no network request was made"
)

object HttpClientFactory {

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val SOCKET_TIMEOUT_MS = 15_000
    private const val REQUEST_TIMEOUT_MS = 20_000L
    private const val TOR_CONNECT_TIMEOUT_MS = 30_000
    private const val TOR_SOCKET_TIMEOUT_MS = 30_000
    private const val TOR_REQUEST_TIMEOUT_MS = 45_000L

    @Volatile private var cached: HttpClient? = null
    @Volatile private var cachedSignature: String? = null

    // Offline switch: fail every request fast, before any socket, when offline
    // mode is on. This is the single choke point the whole network layer routes
    // through, so one guard here covers keyserver lookup/search/publish, WKD, and
    // the update check. Checked per request, not per client build, so a mid-session
    // toggle takes effect immediately even though the client is cached.
    private val offlineGuard = createClientPlugin("PGPonyOfflineGuard") {
        onRequest { _, _ ->
            if (OfflineMode.isEnabled()) throw OfflineModeException()
        }
    }

    // The loopback bridge that carries proxied requests over SOCKS5 with the
    // host name resolved by the proxy (see SocksBridge). One per proxied
    // client; replaced with the client when the proxy config changes. It also
    // does the SOCKS5 sign-in itself: the user/pass pair when one is set (a
    // distinct pair puts PGPony on its own Tor circuit, IsolateSOCKSAuth),
    // otherwise no authentication, so the OS login name is never sent.
    @Volatile private var bridge: SocksBridge? = null

    private fun closeBridge() {
        bridge?.close()
        bridge = null
    }

    // An .onion address only exists inside Tor. With no proxy set, refuse it
    // before any socket so the name is never handed to the local resolver or
    // tried in the clear.
    private val onionGuard = createClientPlugin("PGPonyOnionGuard") {
        onRequest { request, _ ->
            if (request.url.host.trimEnd('.').lowercase().endsWith(".onion")) {
                throw java.io.IOException("An .onion address can only be reached through Tor, and no proxy is set, so nothing was sent")
            }
        }
    }

    fun client(): HttpClient = client(PGPonyApp.instance)

    @Synchronized
    fun client(context: PGPonyApp): HttpClient {
        val cfg = ProxyPrefs.config(context)
        val sig = cfg.signature
        val existing = cached
        if (existing != null && cachedSignature == sig) return existing

        existing?.close()
        val built = build(cfg)
        cached = built
        cachedSignature = sig
        return built
    }

    // Android 4.6.0 (item 17.8): ask every server for an unencoded body, so a
    // hostile key server or WKD host cannot turn a small compressed response into
    // a large one before any size cap sees it.
    private val identityEncoding = createClientPlugin("PGPonyIdentityEncoding") {
        onRequest { request, _ ->
            request.headers.remove("Accept-Encoding")
            request.headers.append("Accept-Encoding", "identity")
        }
    }

    private fun build(cfg: ProxyPrefs.Config): HttpClient {
        // Android 4.6.0 (item 17.8): a proxy mode with no usable host (Custom
        // picked before a host was typed, the host cleared, or a restored backup
        // with a blank host) used to build a DIRECT client while Settings showed a
        // proxy. Fail closed instead: every request errors, nothing leaves.
        closeBridge()
        if (cfg.enabled && cfg.host.isNullOrBlank()) {
            return failClosedClient("A proxy is turned on but no proxy host is set, so nothing was sent")
        }
        val proxied = cfg.enabled && cfg.host != null
        val via = if (proxied) {
            try {
                SocksBridge(cfg.host!!, cfg.port, cfg.username, cfg.password, TOR_CONNECT_TIMEOUT_MS)
            } catch (e: java.io.IOException) {
                return failClosedClient("The proxy connection could not be set up, so nothing was sent")
            }
        } else {
            null
        }
        bridge = via
        return HttpClient(Android) {
            // Offline switch: block outright when offline mode is on, before any
            // other plugin or the socket.
            install(offlineGuard)
            if (!proxied) install(onionGuard)
            install(identityEncoding)
            install(HttpTimeout) {
                requestTimeoutMillis =
                    if (proxied) TOR_REQUEST_TIMEOUT_MS else REQUEST_TIMEOUT_MS
                connectTimeoutMillis =
                    (if (proxied) TOR_CONNECT_TIMEOUT_MS else CONNECT_TIMEOUT_MS).toLong()
                socketTimeoutMillis =
                    (if (proxied) TOR_SOCKET_TIMEOUT_MS else SOCKET_TIMEOUT_MS).toLong()
            }
            engine {
                if (via != null) {
                    // An HTTP proxy at the loopback bridge, which opens the
                    // SOCKS5 connection by host name. No direct fallback.
                    proxy = via.proxy
                    connectTimeout = TOR_CONNECT_TIMEOUT_MS
                    socketTimeout = TOR_SOCKET_TIMEOUT_MS
                } else {
                    connectTimeout = CONNECT_TIMEOUT_MS
                    socketTimeout = SOCKET_TIMEOUT_MS
                }
            }
        }
    }

    // A client that sends nothing: every request fails with [reason].
    private fun failClosedClient(reason: String): HttpClient = HttpClient(Android) {
        install(offlineGuard)
        install(createClientPlugin("PGPonyProxyMissing") {
            onRequest { _, _ ->
                throw java.io.IOException(reason)
            }
        })
    }

    /** Force a rebuild on the next client() (call after a settings change). */
    @Synchronized
    fun invalidate() {
        closeBridge()
        cached?.close()
        cached = null
        cachedSignature = null
    }
}
