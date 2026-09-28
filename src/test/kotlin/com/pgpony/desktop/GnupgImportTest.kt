// GnupgImportTest.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5b (plan F3): reading a GnuPG home. The parsers for
// the keybox, trustdb.gpg, `--export-ownertrust` and `--with-colons` output, the trust mapping,
// and a whole import from a home without gpg. The gpg-driven path is exercised by hand (it needs
// a real gpg and its pinentry).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GnupgImportTest {

    private val crypto = PGPCryptoService.shared

    private fun be32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    /** A keybox with its header blob and one OpenPGP blob per keyblock. */
    private fun keybox(vararg keyblocks: ByteArray): ByteArray {
        var out = be32(32) + byteArrayOf(1, 1, 0, 0) + "KBXf".toByteArray() + ByteArray(20)
        for (kb in keyblocks) {
            // A real blob carries more fields before the keyblock; the offset says where it is.
            val filler = ByteArray(12)
            val kbOff = 16 + filler.size
            out += be32(kbOff + kb.size) + byteArrayOf(2, 1, 0, 0) + be32(kbOff) + be32(kb.size) + filler + kb
        }
        return out
    }

    /** One 40-byte trustdb record: type, reserved, fingerprint, ownertrust. */
    private fun trustRecord(fpHex: String, ownertrust: Int): ByteArray {
        val r = ByteArray(40)
        r[0] = 12
        fpHex.chunked(2).forEachIndexed { i, h -> r[2 + i] = h.toInt(16).toByte() }
        r[22] = ownertrust.toByte()
        return r
    }

    @Test
    fun keyboxBlobsGiveTheirKeyblocks() {
        val a = byteArrayOf(0x99.toByte(), 1, 2)
        val b = byteArrayOf(0x99.toByte(), 3, 4, 5)
        val blocks = GnupgImport.keyboxKeyblocks(keybox(a, b))
        assertEquals(2, blocks.size)
        assertContentEquals(a, blocks[0])
        assertContentEquals(b, blocks[1])
        assertEquals(emptyList(), GnupgImport.keyboxKeyblocks(byteArrayOf(0, 0, 0, 3, 1)), "a truncated file gives nothing")
        val lying = be32(16) + byteArrayOf(2, 1, 0, 0) + be32(8) + be32(1_000_000)
        assertEquals(emptyList(), GnupgImport.keyboxKeyblocks(lying), "a keyblock past its blob is ignored")
    }

    @Test
    fun trustRecordsAndTheOwnertrustExport() {
        val fp = "0123456789ABCDEF0123456789ABCDEF01234567"
        val db = ByteArray(40).also { it[0] = 1 } + trustRecord(fp, 0x26) + ByteArray(40).also { it[0] = 13 }
        assertEquals(mapOf(fp to 6), GnupgImport.trustdbOwnertrust(db), "the flags nibble is dropped")

        val export = """
            # List of assigned trustvalues, created Mon Sep 28 2026
            # (Use "gpg --import-ownertrust" to restore them)
            0123456789abcdef0123456789abcdef01234567:6:
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:4:
            not a line
        """.trimIndent()
        assertEquals(
            mapOf(fp to 6, "A".repeat(40) to 4),
            GnupgImport.parseOwnertrustExport(export)
        )
    }

    @Test
    fun colonListingsAndTheTrustMapping() {
        val listing = """
            tru::1:1727500000:0:3:1:5
            pub:u:255:22:1111111111111111:1727500000:::u:::scESC:::::ed25519:::0:
            fpr:::::::::AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111:
            uid:u::::1727500000::HASH::Alice \x3a Lovelace <alice@example.org>::::::::::0:
            sub:u:255:18:2222222222222222:1727500000::::::e:::::cv25519::
            fpr:::::::::BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222:
            sec:f:255:22:3333333333333333:1727500000:::-:::scESC:::#:::ed25519:::0:
            fpr:::::::::CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333:
            uid:f::::1727500000::HASH::Bob <bob@example.org>::::::::::0:
            sec:-:255:22:4444444444444444:1727500000:::-:::scESC:::D2760001240100000006:::ed25519:::0:
            fpr:::::::::DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444:
        """.trimIndent()
        val keys = GnupgImport.parseColons(listing)
        assertEquals(listOf("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111", "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333", "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"), keys.map { it.fingerprint }, "the primary's fingerprint, not the subkey's")
        assertEquals("Alice : Lovelace <alice@example.org>", keys[0].userId)
        assertEquals('u', keys[0].validity)
        assertEquals("#", keys[1].serial)
        assertEquals("D2760001240100000006", keys[2].serial)

        assertEquals(TrustLevel.ULTIMATE, GnupgImport.trustFor(6, null))
        assertEquals(TrustLevel.ULTIMATE, GnupgImport.trustFor(null, 'u'))
        assertEquals(TrustLevel.VERIFIED, GnupgImport.trustFor(5, null))
        assertEquals(TrustLevel.VERIFIED, GnupgImport.trustFor(2, 'f'))
        assertNull(GnupgImport.trustFor(4, 'm'), "marginal is not carried over")
        assertNull(GnupgImport.trustFor(3, '-'))
    }

    @Test
    fun aHomeWithoutGpgImportsPublicKeysAndRaisesTrustOnly() = runBlocking {
        val dir = Files.createTempDirectory("pgpony-gnupg-test")
        val home = Files.createDirectories(dir.resolve("gnupg"))
        val mine = crypto.generateKeyPair("Mine", "mine@example.org", KeyAlgorithm.ED25519_CV25519, null)
        val friend = crypto.generateKeyPair("Friend", "friend@example.org", KeyAlgorithm.ED25519_CV25519, null)
        val other = crypto.generateKeyPair("Other", "other@example.org", KeyAlgorithm.ED25519_CV25519, null)
        Files.write(home.resolve("pubring.kbx"), keybox(mine.publicKeyData, friend.publicKeyData, other.publicKeyData))
        Files.write(
            home.resolve("trustdb.gpg"),
            ByteArray(40).also { it[0] = 1 } + trustRecord(mine.fingerprint, 6) + trustRecord(friend.fingerprint, 5) + trustRecord(other.fingerprint, 3)
        )
        assertTrue(GnupgImport.looksLikeHome(home))
        assertFalse(GnupgImport.looksLikeHome(dir))

        val db = Db.open(dir.resolve("pgpony.db"))
        val repo = DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
        // Already verified in PGPony: a lower GnuPG trust must not lower it.
        repo.importBytes(other.publicKeyData)
        repo.updateTrustLevel(other.fingerprint, TrustLevel.VERIFIED)

        val scan = GnupgImport.scan(home, gpg = null)
        assertEquals(3, scan.publicKeys)
        assertEquals(emptyList(), scan.secretKeys)

        val result = GnupgImport.import(repo, scan, withTrust = true, withSecrets = true)
        assertEquals(2, result.report.inserted)
        assertEquals(2, result.trustSet)
        assertEquals(0, result.secretsImported, "no gpg, no secret keys")
        assertEquals(TrustLevel.ULTIMATE, repo.byFingerprint(mine.fingerprint)!!.trustLevel)
        assertEquals(TrustLevel.VERIFIED, repo.byFingerprint(friend.fingerprint)!!.trustLevel)
        assertEquals(TrustLevel.VERIFIED, repo.byFingerprint(other.fingerprint)!!.trustLevel)

        val again = GnupgImport.import(repo, scan, withTrust = true, withSecrets = false)
        assertEquals(0, again.report.inserted)
        assertEquals(0, again.trustSet, "nothing to raise the second time")
        db.close()
    }
}
