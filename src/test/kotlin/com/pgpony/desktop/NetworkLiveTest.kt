// NetworkLiveTest.kt
// D4 validation, live half — REAL network traffic, so gated: ./gradlew test -DrunNetwork=true
// (forwarded to the test JVM by build.gradle.kts). Reference targets chosen for stability:
// the Tor Browser Developers signing key has been continuously published for years, and
// torproject.org runs WKD. Prefs are overridden in-memory so the run uses proxy OFF + the
// seed directory regardless of what the machine's real settings say.

package com.pgpony.desktop

import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.network.KeyServerRepository
import com.pgpony.android.network.ProxyPrefs
import com.pgpony.android.network.WkdService
import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NetworkLiveTest {

    private val enabled = System.getProperty("runNetwork") == "true"

    private fun skipUnlessEnabled(): Boolean {
        if (!enabled) {
            println("NetworkLiveTest skipped — enable with -DrunNetwork=true (live traffic)")
            return true
        }
        return false
    }

    @BeforeTest
    fun hookPrefs() {
        ProxyPrefs.prefsOverride = MemoryPreferences()          // proxy OFF
        KeyServerDirectory.prefsOverride = MemoryPreferences()  // seed directory
        com.pgpony.android.network.HttpClientFactory.invalidate()
    }

    @AfterTest
    fun unhookPrefs() {
        ProxyPrefs.prefsOverride = null
        KeyServerDirectory.prefsOverride = null
        com.pgpony.android.network.HttpClientFactory.invalidate()
    }

    @Test
    fun hagridServesTheTorBrowserKeyByFingerprint() {
        if (skipUnlessEnabled()) return
        runBlocking {
            val armor = assertNotNull(
                KeyServerRepository.shared.searchByFingerprint(TOR_BROWSER_FP),
                "keys.openpgp.org should serve $TOR_BROWSER_FP"
            )
            assertTrue(armor.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        }
    }

    @Test
    fun wkdResolvesTorprojectAddress() {
        if (skipUnlessEnabled()) return
        runBlocking {
            val hit = assertNotNull(
                WkdService.shared.lookup("torbrowser@torproject.org"),
                "torproject.org runs WKD; expected a hit"
            )
            assertTrue(hit.armoredKey.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
            println("WKD source: ${hit.source.displayName}")
        }
    }

    @Test
    fun unifiedLookupFindsByEmailWithSourceAttribution() {
        if (skipUnlessEnabled()) return
        runBlocking {
            val hit = assertNotNull(
                KeyServerRepository.shared.findByEmail("torbrowser@torproject.org"),
                "WKD → directory → Hagrid should resolve this address"
            )
            println("findByEmail source: ${hit.source.displayName}")
            // The armor must parse and carry the expected fingerprint.
            val parsed = com.pgpony.android.crypto.PGPCryptoService.shared
                .importArmoredKey(hit.armoredKey)
            assertTrue(
                parsed.fingerprint.equals(TOR_BROWSER_FP, ignoreCase = true),
                "expected $TOR_BROWSER_FP, got ${parsed.fingerprint}"
            )
        }
    }

    private companion object {
        /** Tor Browser Developers (signing key), published on keys.openpgp.org + WKD. */
        const val TOR_BROWSER_FP = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
    }
}
