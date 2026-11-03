// KeyIdTextTest.kt
// PGPony Android, 4.7.0 (item 48, #79): the key IDs decrypt and verify
// results show for the key that signed or decrypted, and its primary.

package com.pgpony.android.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KeyIdTextTest {

    private val primaryV4 = "FB84750EED51F530BA94AE0ECB0A431F1DB1A626"
    private val subkeyV4 = "7AAE2D9541BCEDBD453A3E499F1DAF9D9070430F"
    private val v6 = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"

    @Test
    fun `key IDs come from the right end of the fingerprint`() {
        assertEquals("CB0A431F1DB1A626", KeyIdText.keyIdOf(primaryV4))
        assertEquals("9F1DAF9D9070430F", KeyIdText.keyIdOf(subkeyV4.lowercase()))
        assertEquals("CB186C4F0609A697", KeyIdText.keyIdOf(v6))
        assertEquals("CB0A431F1DB1A626", KeyIdText.keyIdOf("FB84 750E ED51 F530 BA94  AE0E CB0A 431F 1DB1 A626"))
        assertNull(KeyIdText.keyIdOf("1234"))
        assertNull(KeyIdText.keyIdOf("Z".repeat(40)))
        assertNull(KeyIdText.keyIdOf(null as String?))
        assertEquals("00000000DEADBEEF", KeyIdText.keyIdOf(0xDEADBEEFL))
        assertEquals("F0F9AB15B82320BB", KeyIdText.keyIdOf(0xF0F9AB15B82320BBuL.toLong()))
    }

    @Test
    fun `a subkey signature names the subkey and its primary`() {
        assertEquals(
            KeyIdText.Line("9F1DAF9D9070430F", "CB0A431F1DB1A626"),
            KeyIdText.signingLine(subkeyV4, null, primaryV4)
        )
    }

    @Test
    fun `a primary signature names only the primary`() {
        assertEquals(KeyIdText.Line("CB0A431F1DB1A626", null), KeyIdText.signingLine(primaryV4, null, primaryV4))
    }

    @Test
    fun `without the signing fingerprint the long key ID is used`() {
        assertEquals(
            KeyIdText.Line("9F1DAF9D9070430F", "CB0A431F1DB1A626"),
            KeyIdText.signingLine(null, "9f1daf9d9070430f", primaryV4)
        )
        assertEquals(KeyIdText.Line("9F1DAF9D9070430F", null), KeyIdText.signingLine(null, "0x9F1DAF9D9070430F", null))
        assertNull(KeyIdText.signingLine(null, "short", primaryV4))
        assertNull(KeyIdText.signingLine(null, null, primaryV4))
    }

    @Test
    fun `the decrypting line names the subkey that unwrapped the session key`() {
        assertEquals(
            KeyIdText.Line("F0F9AB15B82320BB", "CB0A431F1DB1A626"),
            KeyIdText.decryptingLine(0xF0F9AB15B82320BBuL.toLong(), primaryV4)
        )
        assertEquals(
            KeyIdText.Line("CB0A431F1DB1A626", null),
            KeyIdText.decryptingLine(0xCB0A431F1DB1A626uL.toLong(), primaryV4)
        )
        assertNull(KeyIdText.decryptingLine(null, primaryV4))
        assertNull(KeyIdText.decryptingLine(0L, primaryV4))
    }
}
