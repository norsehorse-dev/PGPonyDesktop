// HiddenRecipientTest.kt
// PGPony Android — 4.1.0 (hidden recipient / `gpg -R`)
//
// Regression net for the routing half of the hidden-recipient report:
// a message whose PKESK carries the wildcard key ID must decrypt with a key
// we hold, must be REPORTED as hidden so the UI can offer the card, and must
// fail as NoMatchingKey (not as a lookup miss) when we hold nothing for it.
//
// How the fixtures are built: PGPony has no "-R" switch, so an ordinary
// addressed message is written and its PKESK key ID overwritten with zeros —
// byte-for-byte what `gpg -R` emits, since the wildcard IS the all-zero key
// ID and nothing else about the packet changes. Writing with armor = false
// keeps the key ID present verbatim in the packet stream, so the rewrite is a
// plain byte search with no packet re-encoding to get wrong.
//
// The CARD half of the fix (CardDecryptService's trial pass) is not covered
// here: it needs a card that can perform PSO:DECIPHER, so it is a device
// check — see PHASE_4.1.0-1_NOTES.md.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream

class HiddenRecipientTest {

    private val svc = PGPCryptoService.shared
    private val pass = "correct horse battery staple"
    private val plaintext = "the recipient of this message is nobody's business"

    private class Party(val pub: PGPPublicKeyRing, val sec: PGPSecretKeyRing)

    private fun party(name: String, email: String): Party {
        val r = svc.generateKeyPair(
            name = name,
            email = email,
            algorithm = KeyAlgorithm.ED25519_CV25519,
            passphrase = pass
        )
        return Party(
            PGPPublicKeyRing(ByteArrayInputStream(r.publicKeyData), JcaKeyFingerprintCalculator()),
            PGPSecretKeyRing(ByteArrayInputStream(r.privateKeyData), JcaKeyFingerprintCalculator())
        )
    }

    private fun addressedTo(party: Party): ByteArray =
        svc.encrypt(
            data = plaintext.toByteArray(Charsets.UTF_8),
            recipientPublicKeys = listOf(party.pub),
            armor = false
        )

    /** Zero the PKESK key ID, turning an addressed message into a `gpg -R` one. */
    private fun hideRecipient(ciphertext: ByteArray): ByteArray {
        val ids = svc.recipientKeyIDs(ciphertext)
        assertEquals("fixture should have exactly one PKESK", 1, ids.size)
        val id = ids[0]
        val idBytes = ByteArray(8) { i -> ((id ushr (56 - 8 * i)) and 0xFF).toByte() }
        val at = indexOf(ciphertext, idBytes)
        assertTrue("PKESK key ID not found in the packet stream", at >= 0)
        val out = ciphertext.copyOf()
        for (i in 0 until 8) out[at + i] = 0
        // Sanity: the rewrite produced a wildcard and nothing else.
        assertEquals(listOf(0L), svc.recipientKeyIDs(out))
        return out
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    // ── Inspection ─────────────────────────────────────────────────────

    @Test
    fun `inspection reports a wildcard and no addressed recipient`() {
        val alice = party("Alice", "alice@pgpony.test")
        val info = svc.inspectEncryptedMessage(hideRecipient(addressedTo(alice)))

        assertTrue("wildcard PKESK should be flagged", info.hasHiddenRecipient)
        assertTrue(
            "the wildcard must not be offered as something to look up",
            info.addressedKeyIDs.isEmpty()
        )
        assertFalse("a hidden recipient is still a public-key message", info.isSymmetricOnly)
    }

    @Test
    fun `an addressed message is not reported as hidden`() {
        val alice = party("Alice", "alice@pgpony.test")
        val info = svc.inspectEncryptedMessage(addressedTo(alice))

        assertFalse(info.hasHiddenRecipient)
        assertEquals(1, info.addressedKeyIDs.size)
    }

    // ── Decryption ─────────────────────────────────────────────────────

    @Test
    fun `a hidden-recipient message decrypts with the key it was written to`() {
        val alice = party("Alice", "alice@pgpony.test")
        val hidden = hideRecipient(addressedTo(alice))

        val result = svc.decrypt(hidden, listOf(alice.sec), pass)
        assertEquals(plaintext, String(result.data, Charsets.UTF_8))
    }

    @Test
    fun `a stranger's key reports NoMatchingKey and says the recipient was hidden`() {
        val alice = party("Alice", "alice@pgpony.test")
        val bob = party("Bob", "bob@pgpony.test")
        val hidden = hideRecipient(addressedTo(alice))

        try {
            svc.decrypt(hidden, listOf(bob.sec), pass)
            fail("expected NoMatchingKey")
        } catch (e: PGPCryptoError.NoMatchingKey) {
            assertTrue(
                "the UI needs this flag to know a card is worth offering",
                e.hiddenRecipient
            )
        }
    }

    @Test
    fun `an addressed message reports NoMatchingKey without the hidden flag`() {
        val alice = party("Alice", "alice@pgpony.test")
        val bob = party("Bob", "bob@pgpony.test")

        try {
            svc.decrypt(addressedTo(alice), listOf(bob.sec), pass)
            fail("expected NoMatchingKey")
        } catch (e: PGPCryptoError.NoMatchingKey) {
            assertFalse(
                "no wildcard was present, so there is nothing to fall back to",
                e.hiddenRecipient
            )
        }
    }

    // ── The routing probe ──────────────────────────────────────────────

    @Test
    fun `canOpenWithSecretKeys separates the holder from a stranger`() {
        val alice = party("Alice", "alice@pgpony.test")
        val bob = party("Bob", "bob@pgpony.test")
        val hidden = hideRecipient(addressedTo(alice))

        assertTrue(svc.canOpenWithSecretKeys(hidden, listOf(alice.sec), pass))
        assertFalse(svc.canOpenWithSecretKeys(hidden, listOf(bob.sec), pass))
        assertFalse(svc.canOpenWithSecretKeys(hidden, emptyList(), pass))
    }

    @Test
    fun `a locked key with no passphrase still counts as a candidate`() {
        // "Ask the user to unlock this" is the right next step; routing
        // straight past it to a card prompt would be wrong.
        val alice = party("Alice", "alice@pgpony.test")
        val hidden = hideRecipient(addressedTo(alice))

        assertTrue(svc.canOpenWithSecretKeys(hidden, listOf(alice.sec), null))
    }

    @Test
    fun `the probe does not consume the message`() {
        // The provider path asks the probe first and decrypts after, from the
        // same bytes. If the probe left anything half-read, this would fail.
        val alice = party("Alice", "alice@pgpony.test")
        val hidden = hideRecipient(addressedTo(alice))

        assertTrue(svc.canOpenWithSecretKeys(hidden, listOf(alice.sec), pass))
        val result = svc.decrypt(hidden, listOf(alice.sec), pass)
        assertEquals(plaintext, String(result.data, Charsets.UTF_8))
    }
}
