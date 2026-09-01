// DesktopHttpClientFactory.kt — DESKTOP TWIN of network/HttpClientFactory.kt (vendored copy
// excluded: Context-typed). Declares the same `object HttpClientFactory`; the body mirrors the
// Android build verbatim — same ktor Android engine (plain JVM), same timeout split, same
// SOCKS wiring, same signature-keyed cache. File name differs from the excluded file (D1 Fix1
// rule). Vendored callers use the no-arg client(); a PGPonyApp-typed overload covers the rest.

package com.pgpony.android.network

import com.pgpony.android.PGPonyApp
import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
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

    // Proxy stream isolation: SOCKS5 user/pass auth. Java exposes no per-client
    // SOCKS credentials, so a single default Authenticator, scoped to the active
    // proxy's port and the PROXY requestor type, hands the pair to the SOCKS
    // handshake. It returns null for everything else, so it is inert when no
    // proxy auth is configured. Distinct credentials put PGPony on its own Tor
    // circuit (Orbot IsolateSOCKSAuth).
    private val socksAuthenticator = object : java.net.Authenticator() {
        @Volatile var port: Int = -1
        @Volatile var auth: java.net.PasswordAuthentication? = null
        override fun getPasswordAuthentication(): java.net.PasswordAuthentication? {
            val a = auth ?: return null
            if (requestorType != RequestorType.PROXY) return null
            if (requestingPort != port) return null
            return a
        }
    }
    @Volatile private var authenticatorInstalled = false

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

    private fun applyProxyAuth(cfg: ProxyPrefs.Config) {
        if (cfg.enabled && cfg.host != null && cfg.hasAuth) {
            socksAuthenticator.port = cfg.port
            socksAuthenticator.auth =
                java.net.PasswordAuthentication(cfg.username, cfg.password!!.toCharArray())
            if (!authenticatorInstalled) {
                java.net.Authenticator.setDefault(socksAuthenticator)
                authenticatorInstalled = true
            }
        } else {
            socksAuthenticator.auth = null
            socksAuthenticator.port = -1
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

    private fun build(cfg: ProxyPrefs.Config): HttpClient {
        val proxied = cfg.enabled && cfg.host != null
        // Scope the SOCKS Authenticator to this config before the client makes
        // its first connection (fail-closed: bad auth fails the SOCKS handshake).
        applyProxyAuth(cfg)
        return HttpClient(Android) {
            // Offline switch: block outright when offline mode is on, before any
            // other plugin or the socket.
            install(offlineGuard)
            install(HttpTimeout) {
                requestTimeoutMillis =
                    if (proxied) TOR_REQUEST_TIMEOUT_MS else REQUEST_TIMEOUT_MS
                connectTimeoutMillis =
                    (if (proxied) TOR_CONNECT_TIMEOUT_MS else CONNECT_TIMEOUT_MS).toLong()
                socketTimeoutMillis =
                    (if (proxied) TOR_SOCKET_TIMEOUT_MS else SOCKET_TIMEOUT_MS).toLong()
            }
            engine {
                if (proxied) {
                    proxy = ProxyBuilder.socks(cfg.host!!, cfg.port)
                    connectTimeout = TOR_CONNECT_TIMEOUT_MS
                    socketTimeout = TOR_SOCKET_TIMEOUT_MS
                } else {
                    connectTimeout = CONNECT_TIMEOUT_MS
                    socketTimeout = SOCKET_TIMEOUT_MS
                }
            }
        }
    }

    /** Force a rebuild on the next client() (call after a settings change). */
    @Synchronized
    fun invalidate() {
        cached?.close()
        cached = null
        cachedSignature = null
    }
}
