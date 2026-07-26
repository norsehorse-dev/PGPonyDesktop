// KeyServerDirectoryTest.kt
// D4 validation, offline half: the KeyServer JSON codec + R5 capability check are
// byte-compatible with Android; the directory twin persists/edits/orders over prefs; the
// ProxyPrefs twin's config model and onion-mirror URL rewrite behave. Everything runs on an
// in-memory Preferences node via the prefsOverride hooks — the suite never touches the real
// user prefs tree.

package com.pgpony.desktop

import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.keyserver.KeyServer
import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.network.ProxyPrefs
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import java.util.prefs.AbstractPreferences
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** In-memory java.util.prefs node — no on-disk side effects. */
internal class MemoryPreferences : AbstractPreferences(null, "") {
    private val values = mutableMapOf<String, String>()
    override fun putSpi(key: String, value: String) { values[key] = value }
    override fun getSpi(key: String): String? = values[key]
    override fun removeSpi(key: String) { values.remove(key) }
    override fun removeNodeSpi() { values.clear() }
    override fun keysSpi(): Array<String> = values.keys.toTypedArray()
    override fun childrenNamesSpi(): Array<String> = emptyArray()
    override fun childSpi(name: String): AbstractPreferences =
        throw UnsupportedOperationException("flat test node")
    override fun syncSpi() {}
    override fun flushSpi() {}
}

class KeyServerDirectoryTest {

    private lateinit var directoryPrefs: MemoryPreferences
    private lateinit var proxyPrefs: MemoryPreferences

    @BeforeTest
    fun hookPrefs() {
        directoryPrefs = MemoryPreferences()
        proxyPrefs = MemoryPreferences()
        KeyServerDirectory.prefsOverride = directoryPrefs
        ProxyPrefs.prefsOverride = proxyPrefs
    }

    @AfterTest
    fun unhookPrefs() {
        KeyServerDirectory.prefsOverride = null
        ProxyPrefs.prefsOverride = null
    }

    private val directory get() = KeyServerDirectory.get(PGPonyApp.instance)

    // ── KeyServer codec + capability ────────────────────────────────────

    @Test
    fun keyServerJsonRoundTripsAllFields() {
        val server = KeyServer(
            id = "example.test", label = "Example", baseUrl = "https://example.test",
            isFirstParty = true, lookupEnabled = false, publishEnabled = true,
            acceptsAllKeyTypes = false
        )
        assertEquals(server, KeyServer.fromJson(JSONObject(server.toJson().toString())))
    }

    @Test
    fun keyServerJsonDefaultsMatchAndroidOptionals() {
        // Android fromJson defaults: isFirstParty=false, both toggles=true, acceptsAll=true.
        val minimal = JSONObject()
            .put("id", "x").put("label", "X").put("baseUrl", "https://x.example")
        val parsed = KeyServer.fromJson(minimal)
        assertFalse(parsed.isFirstParty)
        assertTrue(parsed.lookupEnabled)
        assertTrue(parsed.publishEnabled)
        assertTrue(parsed.acceptsAllKeyTypes)
    }

    @Test
    fun mayNotAcceptFlagsExactlyTheNonClassicAlgorithms() {
        val openpgpOrg = KeyServerDirectory.DEFAULTS.first { it.id == KeyServerDirectory.ID_OPENPGP }
        val pgponyApp = KeyServerDirectory.DEFAULTS.first { it.id == KeyServerDirectory.ID_PGPONY }
        // Classic v4 shapes pass everywhere.
        listOf(KeyAlgorithm.RSA_2048, KeyAlgorithm.RSA_4096, KeyAlgorithm.ED25519_CV25519)
            .forEach { algo ->
                assertFalse(openpgpOrg.mayNotAccept(algo), "openpgp.org should take $algo")
                assertFalse(pgponyApp.mayNotAccept(algo))
            }
        // v6 + PQC composites flag on the verified-email VKS, never on first-party.
        listOf(
            KeyAlgorithm.V6_ED25519, KeyAlgorithm.V6_ED448,
            KeyAlgorithm.MLKEM768_X25519_V6, KeyAlgorithm.MLKEM768_X25519_LIBREPGP
        ).forEach { algo ->
            assertTrue(openpgpOrg.mayNotAccept(algo), "openpgp.org should flag $algo")
            assertFalse(pgponyApp.mayNotAccept(algo), "first-party never flags")
        }
    }

    // ── Directory persistence ───────────────────────────────────────────

    @Test
    fun emptyPrefsYieldTheSeedList() = runBlocking {
        assertEquals(KeyServerDirectory.DEFAULTS, directory.readOnce())
        // Lookup priority: the mature server first, first-party second (plan §1 constraint).
        assertEquals(KeyServerDirectory.ID_OPENPGP, directory.readOnce().first().id)
    }

    @Test
    fun saveTogglesMoveResetPersist() = runBlocking {
        directory.setLookupEnabled(KeyServerDirectory.ID_OPENPGP, false)
        directory.setPublishEnabled(KeyServerDirectory.ID_PGPONY, false)
        var list = directory.readOnce()
        assertFalse(list.first { it.id == KeyServerDirectory.ID_OPENPGP }.lookupEnabled)
        assertFalse(list.first { it.id == KeyServerDirectory.ID_PGPONY }.publishEnabled)

        // Move first-party to the front; bounds moves are no-ops.
        directory.move(KeyServerDirectory.ID_PGPONY, up = true)
        list = directory.readOnce()
        assertEquals(KeyServerDirectory.ID_PGPONY, list.first().id)
        directory.move(KeyServerDirectory.ID_PGPONY, up = true) // already first
        assertEquals(KeyServerDirectory.ID_PGPONY, directory.readOnce().first().id)

        // A user-added server persists through the codec.
        directory.save(
            directory.readOnce() + KeyServer(
                id = "custom-1", label = "Custom", baseUrl = "https://keys.custom.example",
                isFirstParty = false, lookupEnabled = true, publishEnabled = false,
                acceptsAllKeyTypes = true
            )
        )
        assertEquals(3, directory.readOnce().size)
        assertEquals("custom-1", directory.readOnce().last().id)

        directory.resetToDefaults()
        assertEquals(KeyServerDirectory.DEFAULTS, directory.readOnce())
    }

    @Test
    fun corruptJsonFallsBackToDefaults() = runBlocking {
        directoryPrefs.put("servers_json", "{not json")
        assertEquals(KeyServerDirectory.DEFAULTS, directory.readOnce())
        directoryPrefs.put("servers_json", "[]") // empty list also yields DEFAULTS
        assertEquals(KeyServerDirectory.DEFAULTS, directory.readOnce())
    }

    // ── ProxyPrefs twin ─────────────────────────────────────────────────

    @Test
    fun proxyDefaultsOffAndModesCarryHosts() {
        val app = PGPonyApp.instance
        val off = ProxyPrefs.config(app)
        assertEquals(ProxyPrefs.MODE_OFF, off.mode)
        assertFalse(off.enabled)

        ProxyPrefs.setMode(app, ProxyPrefs.MODE_ORBOT)
        val tor = ProxyPrefs.config(app)
        assertTrue(tor.enabled)
        assertEquals(ProxyPrefs.ORBOT_HOST, tor.host)
        assertEquals(ProxyPrefs.ORBOT_PORT, tor.port)

        ProxyPrefs.setMode(app, ProxyPrefs.MODE_CUSTOM)
        ProxyPrefs.setCustom(app, "10.0.0.5", 1080)
        val custom = ProxyPrefs.config(app)
        assertTrue(custom.enabled)
        assertEquals("10.0.0.5", custom.host)
        assertEquals(1080, custom.port)
        // The HttpClientFactory cache key changes with the mode/host/port.
        assertTrue(off.signature != tor.signature && tor.signature != custom.signature)
    }

    @Test
    fun onionMirrorRewritesOnlyFirstPartyAndOnlyWhenProxied() {
        val app = PGPonyApp.instance
        val clearnet = "https://${ProxyPrefs.PGPONY_CLEARNET_HOST}"
        val thirdParty = "https://keys.openpgp.org"

        // Proxy off → never rewritten (mirror defaults true but requires an active proxy).
        assertEquals(clearnet, ProxyPrefs.effectiveBaseUrl(app, clearnet))

        ProxyPrefs.setMode(app, ProxyPrefs.MODE_ORBOT)
        assertEquals(ProxyPrefs.PGPONY_ONION_BASE, ProxyPrefs.effectiveBaseUrl(app, clearnet))
        assertEquals(thirdParty, ProxyPrefs.effectiveBaseUrl(app, thirdParty), "third-party untouched")

        ProxyPrefs.setOnionMirror(app, false)
        assertEquals(clearnet, ProxyPrefs.effectiveBaseUrl(app, clearnet), "mirror off → clearnet")
    }
}
