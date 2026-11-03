// SigningSubkeyPinsTest.kt
// PGPony Android, 4.7.0 (item 46, #82): Use for signing. A pinned signing
// subkey signs while it is valid, and the automatic pick (newest valid
// subkey, item 39) comes back once it is not. Uses the passphrase-less
// /signsub fixtures from SigningKeyPickTest.

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.util.encoders.Hex
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

class SigningSubkeyPinsTest {

    private val svc = PGPCryptoService.shared
    private lateinit var dir: File

    @Before
    fun setUp() {
        dir = Files.createTempDirectory("pins").toFile()
        SigningSubkeyPins.dirOverride = dir
    }

    @After
    fun tearDown() {
        SigningSubkeyPins.dirOverride = null
        dir.deleteRecursively()
    }

    private fun ring(name: String) = PGPSecretKeyRing(
        javaClass.getResourceAsStream("/signsub/$name")!!.use { it.readBytes() },
        JcaKeyFingerprintCalculator()
    )

    private fun fp(sk: PGPSecretKey) = Hex.toHexString(sk.publicKey.fingerprint).uppercase()
    private fun primaryFp(r: PGPSecretKeyRing) = Hex.toHexString(r.publicKey.fingerprint).uppercase()

    @Test
    fun `with no pin the newest valid subkey signs`() {
        val r = ring("two-current.pgp")
        val auto = svc.signingSecretKeys(r, applyPin = false)
        assertTrue(auto.size >= 2)
        assertEquals(auto.first().keyID, svc.pickSigningSecretKey(r)?.keyID)
    }

    @Test
    fun `a pinned older subkey signs instead, and unpinning restores the automatic pick`() {
        val r = ring("two-current.pgp")
        val auto = svc.signingSecretKeys(r, applyPin = false)
        val older = auto.last { !it.publicKey.isMasterKey }
        SigningSubkeyPins.set(primaryFp(r), fp(older))
        assertEquals(older.keyID, svc.pickSigningSecretKey(r)?.keyID)
        assertEquals(older.keyID, svc.signingKeyOptions(r).first().keyId)
        assertEquals(auto.first().keyID, svc.signingKeyOptions(r, applyPin = false).first().keyId)
        SigningSubkeyPins.set(primaryFp(r), null)
        assertEquals(auto.first().keyID, svc.pickSigningSecretKey(r)?.keyID)
        assertTrue(!File(dir, SigningSubkeyPins.FILE).exists())
    }

    @Test
    fun `a chosen key for this send still wins over the pin`() {
        val r = ring("two-current.pgp")
        val auto = svc.signingSecretKeys(r, applyPin = false)
        SigningSubkeyPins.set(primaryFp(r), fp(auto.last()))
        assertEquals(auto.first().keyID, svc.pickSigningSecretKey(r, auto.first().keyID)?.keyID)
    }

    @Test
    fun `a pinned subkey that expired falls back to the automatic pick`() {
        val r = ring("expired-first.pgp")
        val expired = r.secretKeys.asSequence().first {
            !it.publicKey.isMasterKey && svc.signingSecretKeys(r, applyPin = false).none { v -> v.keyID == it.keyID }
        }
        SigningSubkeyPins.set(primaryFp(r), fp(expired))
        assertEquals(svc.signingSecretKeys(r, applyPin = false).first().keyID, svc.pickSigningSecretKey(r)?.keyID)
    }

    @Test
    fun `pins are stored per key, survive a reread and are cleared with the key`() {
        val a = "A".repeat(40)
        val b = "b".repeat(64)
        SigningSubkeyPins.set(a, "1".repeat(40))
        SigningSubkeyPins.set(b, "2".repeat(64))
        assertEquals("1".repeat(40), SigningSubkeyPins.pinnedFor(a.lowercase()))
        assertEquals("2".repeat(64), SigningSubkeyPins.pinnedFor(b))
        SigningSubkeyPins.clear(a)
        assertNull(SigningSubkeyPins.pinnedFor(a))
        assertEquals("2".repeat(64), SigningSubkeyPins.pinnedFor(b))
        SigningSubkeyPins.clearAll()
        assertNull(SigningSubkeyPins.pinnedFor(b))
    }

    @Test
    fun `malformed lines and fingerprints are ignored`() {
        val text = "nonsense\n${"A".repeat(40)} ${"B".repeat(40)}\n${"C".repeat(40)}\n${"Z".repeat(40)} ${"D".repeat(40)}\n"
        assertEquals(mapOf("A".repeat(40) to "B".repeat(40)), SigningSubkeyPins.parse(text))
        SigningSubkeyPins.set("A".repeat(40), "short")
        assertNull(SigningSubkeyPins.pinnedFor("A".repeat(40)))
    }
}
