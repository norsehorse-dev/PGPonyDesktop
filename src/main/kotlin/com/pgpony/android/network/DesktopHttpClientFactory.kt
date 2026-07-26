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

object HttpClientFactory {

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val SOCKET_TIMEOUT_MS = 15_000
    private const val REQUEST_TIMEOUT_MS = 20_000L
    private const val TOR_CONNECT_TIMEOUT_MS = 30_000
    private const val TOR_SOCKET_TIMEOUT_MS = 30_000
    private const val TOR_REQUEST_TIMEOUT_MS = 45_000L

    @Volatile private var cached: HttpClient? = null
    @Volatile private var cachedSignature: String? = null

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
        return HttpClient(Android) {
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
