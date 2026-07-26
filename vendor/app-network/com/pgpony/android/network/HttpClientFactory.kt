// HttpClientFactory.kt
// PGPony Android — 4.0.0 Phase 6 (SOCKS/Tor proxy)
//
// The single source of HTTP clients for the whole network layer
// (KeyServerRepository, WkdService, MultiKeyServerService). Replaces
// each service's private HttpClient(Android) so proxy configuration is
// applied uniformly — turn the proxy on once and keyserver lookup,
// publish, WKD, and the background refresh worker all route through it.
//
// The client is cached and rebuilt only when the proxy config changes
// (compared by Config.signature), so per-request retrieval is cheap.
// When a proxy is set, the Ktor Android engine routes through it and a
// dead proxy makes requests FAIL — fail-closed, no direct fallback
// (plan §6). Context comes from PGPonyApp.instance so the shared,
// context-less service singletons can use it.

package com.pgpony.android.network

import android.content.Context
import com.pgpony.android.PGPonyApp
import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.HttpTimeout

object HttpClientFactory {

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val SOCKET_TIMEOUT_MS = 15_000
    // Hard per-request ceiling so a stalled call can never hang the UI
    // forever (the old per-service clients had this via HttpTimeout; the
    // shared client dropped it). WKD overrides this with a tight 8s
    // per-request timeout so it fast-fails and falls through to Hagrid.
    private const val REQUEST_TIMEOUT_MS = 20_000L
    // Tor adds latency; give proxied requests more headroom.
    private const val TOR_CONNECT_TIMEOUT_MS = 30_000
    private const val TOR_SOCKET_TIMEOUT_MS = 30_000
    private const val TOR_REQUEST_TIMEOUT_MS = 45_000L

    @Volatile private var cached: HttpClient? = null
    @Volatile private var cachedSignature: String? = null

    /** The shared client for the current proxy config (context-less). */
    fun client(): HttpClient = client(PGPonyApp.instance)

    @Synchronized
    fun client(context: Context): HttpClient {
        val cfg = ProxyPrefs.config(context)
        val sig = cfg.signature
        val existing = cached
        if (existing != null && cachedSignature == sig) return existing

        // Config changed — close the old client and build a fresh one.
        existing?.close()
        val built = build(cfg)
        cached = built
        cachedSignature = sig
        return built
    }

    private fun build(cfg: ProxyPrefs.Config): HttpClient {
        val proxied = cfg.enabled && cfg.host != null
        return HttpClient(Android) {
            // A hard request ceiling so a stalled lookup (common over Tor)
            // can never leave the search spinner running forever. Per-call
            // sites (WKD) tighten this with a request-scoped timeout {}.
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
                    // SOCKS5 through Orbot / custom. A dead proxy → the
                    // request fails; there is no direct fallback.
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
