// GnupgImportTest.kt
// PGPony Desktop 3.0.0, stage 5 checkpoint 5b (plan F3): reading a GnuPG home. The parsers for
// the keybox, trustdb.gpg, `--export-ownertrust` and `--with-colons` output, the trust rules,
// where gpg is looked for, and whole imports from a home read without gpg. The gpg-driven path
// is in GnupgImportGpgTest (it needs a real gpg).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
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

    private fun repoIn(dir: Path) = Db.open(dir.resolve("pgpony.db")).let { db ->
        db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    private fun key(name: String) = crypto.generateKeyPair(name, "${name.lowercase()}@example.org", KeyAlgorithm.ED25519_CV25519, null)

    @Test
    fun keyboxBlobsGiveTheirKeyblocks() {
        val a = byteArrayOf(0x99.toByte(), 1, 2)
        val b = byteArrayOf(0x99.toByte(), 3, 4, 5)
        val blocks = GnupgImport.keyboxKeyblocks(keybox(a, b))
        assertEquals(2, blocks.size)
        assertContentEquals(a, blocks[0])
        assertContentEquals(b, blocks[1])
        assertContentEquals(a + b, GnupgImport.keyboxPacketStream(keybox(a, b)))
        assertEquals(emptyList(), GnupgImport.keyboxKeyblocks(byteArrayOf(0, 0, 0, 3, 1)), "a truncated file gives nothing")
        val lying = be32(16) + byteArrayOf(2, 1, 0, 0) + be32(8) + be32(1_000_000)
        assertEquals(emptyList(), GnupgImport.keyboxKeyblocks(lying), "a keyblock past its blob is ignored")
        val overlapping = be32(16) + byteArrayOf(2, 1, 0, 0) + be32(0) + be32(16)
        assertEquals(emptyList(), GnupgImport.keyboxKeyblocks(overlapping), "a keyblock inside the blob header is ignored")
    }

    @Test
    fun gnupg6ManyTinyKeyboxBlobsAreReadInLinearTime() {
        // 300k of the smallest blobs a keybox can hold. Joining them used to copy the whole
        // result once per blob; now it is one pass.
        val n = 300_000
        val blob = be32(17) + byteArrayOf(2, 1, 0, 0) + be32(16) + be32(1) + byteArrayOf(0x42)
        val kbx = ByteArray(32 + n * blob.size)
        System.arraycopy(keybox(), 0, kbx, 0, 32)
        for (i in 0 until n) System.arraycopy(blob, 0, kbx, 32 + i * blob.size, blob.size)
        val t0 = System.nanoTime()
        val stream = GnupgImport.keyboxPacketStream(kbx)
        val ms = (System.nanoTime() - t0) / 1_000_000
        assertEquals(n, stream.size)
        assertTrue(ms < 5_000, "took $ms ms")

        val dir = Files.createTempDirectory("pgpony-gnupg-big")
        Files.write(dir.resolve("pubring.kbx"), kbx)
        var cancelled = false
        val stopped = runCatching { GnupgImport.readPublicKeys(dir) { cancelled = true; true } }.exceptionOrNull()
        assertTrue(cancelled && stopped is java.util.concurrent.CancellationException, "the read stops when cancelled")
    }

    @Test
    fun gnupg6AChattyChildNeitherBlocksNorLosesItsLastError() {
        val sh = Path.of("/bin/sh")
        if (!Files.isExecutable(sh)) return
        // 1 MB on stderr: more than the old fixed read, which left the child blocked on a full pipe.
        val t0 = System.nanoTime()
        val out = GnupgImport.exec(listOf(sh.toString(), "-c", "head -c 1000000 /dev/zero | tr '\\0' x >&2; echo done"), 20)
        assertEquals("done", String(out).trim())
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 15_000, "the child was not left blocked")
        val failed = runCatching {
            GnupgImport.exec(listOf(sh.toString(), "-c", "head -c 200000 /dev/zero | tr '\\0' y >&2; echo >&2; echo 'the real error' >&2; exit 3"), 20)
        }.exceptionOrNull()
        assertEquals("the real error", failed?.message, "the end of stderr is kept")
    }

    @Test
    fun gpgMajorVersions() {
        assertEquals(2, GnupgImport.gpgMajor("gpg (GnuPG) 2.4.4"))
        assertEquals(2, GnupgImport.gpgMajor("gpg (GnuPG/MacGPG2) 2.2.41"))
        assertEquals(1, GnupgImport.gpgMajor("gpg (GnuPG) 1.4.23"))
        assertNull(GnupgImport.gpgMajor(""))
    }

    @Test
    fun trustRecordsAndTheOwnertrustExport() {
        val fp = "0123456789ABCDEF0123456789ABCDEF01234567"
        val db = ByteArray(40).also { it[0] = 1 } + trustRecord(fp, 0x26) + ByteArray(40).also { it[0] = 13 }
        val parsed = GnupgImport.trustdbOwnertrust(db)
        assertEquals(mapOf(fp to 0x26), parsed, "the whole byte is kept")
        assertEquals(6, GnupgImport.ownertrustLevel(parsed[fp]))
        assertFalse(GnupgImport.ownertrustDisabled(parsed[fp]))

        val export = """
            # List of assigned trustvalues, created Mon Sep 28 2026
            # (Use "gpg --import-ownertrust" to restore them)
            0123456789abcdef0123456789abcdef01234567:6:
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:4:
            BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:133:
            not a line
        """.trimIndent()
        val ot = GnupgImport.parseOwnertrustExport(export)
        assertEquals(mapOf(fp to 6, "A".repeat(40) to 4, "B".repeat(40) to 133), ot)
        assertTrue(GnupgImport.ownertrustDisabled(ot["B".repeat(40)]), "gnupg5: 133 is full ownertrust on a disabled key")
        assertEquals(5, GnupgImport.ownertrustLevel(ot["B".repeat(40)]))
    }

    @Test
    fun colonListingsKeepEveryUserIdAndItsValidity() {
        val listing = """
            tru::1:1727500000:0:3:1:5
            pub:u:255:22:1111111111111111:1727500000:::u:::scESC:::::ed25519:::0:
            fpr:::::::::AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111:
            uid:u::::1727500000::HASH::Alice \x3a Lovelace <alice@example.org>::::::::::0:
            sub:u:255:18:2222222222222222:1727500000::::::e:::::cv25519::
            fpr:::::::::BBBB2222BBBB2222BBBB2222BBBB2222BBBB2222:
            sec:f:255:22:3333333333333333:1727500000:::-:::scESC:::#:::ed25519:::0:
            fpr:::::::::CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333:
            uid:-::::1727500000::HASH::Carol <carol@corp.example>::::::::::0:
            uid:f::::1727500000::HASH::Bob <bob@example.org>::::::::::0:
            sec:-:255:22:4444444444444444:1727500000:::-:::scSCD:::D2760001240100000006:::ed25519:::0:
            fpr:::::::::DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444:
        """.trimIndent()
        val keys = GnupgImport.parseColons(listing)
        assertEquals(listOf("AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111", "CCCC3333CCCC3333CCCC3333CCCC3333CCCC3333", "DDDD4444DDDD4444DDDD4444DDDD4444DDDD4444"), keys.map { it.fingerprint }, "the primary's fingerprint, not the subkey's")
        assertEquals("Alice : Lovelace <alice@example.org>", keys[0].userId)
        assertEquals('u', keys[0].validity)
        assertEquals("#", keys[1].serial)
        assertEquals("D2760001240100000006", keys[2].serial)
        assertEquals(listOf("Carol <carol@corp.example>", "Bob <bob@example.org>"), keys[1].userIds)
        assertEquals(listOf<Char?>('-', 'f'), keys[1].uidValidity, "gnupg2: validity is per user ID")
        assertFalse(keys[0].disabled)
        assertTrue(keys[2].disabled, "gnupg5: D in the capabilities field")
    }

    @Test
    fun gnupg4AStaleTrustDatabaseIsNotUsed() {
        val now = 1_800_000_000L
        assertFalse(GnupgImport.trustdbStale("tru::1:1727500000:0:3:1:5\npub:f:", now))
        assertFalse(GnupgImport.trustdbStale("tru::1:1727500000:1900000000:3:1:5", now), "next check still ahead")
        assertTrue(GnupgImport.trustdbStale("tru:o:1:1727500000:1:3:1:5", now), "a check is pending")
        assertTrue(GnupgImport.trustdbStale("tru::1:1727500000:1:3:1:5", now), "next check already past")
        assertTrue(GnupgImport.trustdbStale("tru:t:1:1727500000:0:3:1:5", now), "built for another model")
        assertTrue(GnupgImport.trustdbStale("pub:f:255:22:1111", now), "no trust database at all")
    }

    @Test
    fun theTrustRules() {
        val fp = "A".repeat(40)
        fun k(vararg v: Char?, disabled: Boolean = false) =
            GnupgImport.HomeKey(fp, v.indices.map { "U$it <u$it@example.org>" }, v.toList(), disabled)

        // gnupg2: one certified user ID does not make another one Verified.
        val forged = GnupgImport.decideTrust(k('-', 'f'), 2, validityUsable = true, hasSecret = false)
        assertNull(forged.level)
        assertEquals(GnupgImport.TrustSkip.NOT_ALL_UIDS_VALID, forged.skip)
        assertNull(GnupgImport.decideTrust(k('f', 'r'), null, true, false).level, "a revoked user ID is not valid")
        assertEquals(TrustLevel.VERIFIED, GnupgImport.decideTrust(k('f', 'f'), null, true, false).level)
        assertEquals(TrustLevel.VERIFIED, GnupgImport.decideTrust(k('u'), null, true, false).level)
        assertNull(GnupgImport.decideTrust(k('m'), 4, true, false).level, "marginal is not carried over")

        // gnupg4: validity from a stale database counts for nothing.
        assertNull(GnupgImport.decideTrust(k('f'), null, validityUsable = false, hasSecret = false).level)

        // gnupg3: full ownertrust is about certifying others, not about this key.
        assertNull(GnupgImport.decideTrust(k(), 5, false, false).level)
        // gnupg3: Ultimate only with the secret in PGPony; without it, Verified.
        assertEquals(TrustLevel.ULTIMATE, GnupgImport.decideTrust(k(), 6, false, hasSecret = true).level)
        assertEquals(TrustLevel.VERIFIED, GnupgImport.decideTrust(k(), 6, false, hasSecret = false).level)

        // gnupg5: a disabled key gets nothing, whichever way GnuPG marks it.
        val off = GnupgImport.decideTrust(k('f'), 0x86, true, true)
        assertNull(off.level)
        assertEquals(GnupgImport.TrustSkip.DISABLED, off.skip)
        assertNull(GnupgImport.decideTrust(k('f', disabled = true), 5, true, true).level)
        assertNull(GnupgImport.decideTrust(k('-'), 0x83, true, false).skip, "no note for a disabled key nobody trusted")
    }

    @Test
    fun gnupg8FixedInstallLocationsComeBeforePath() {
        val unix = GnupgImport.gpgCandidates(false, "bin:/home/u/bin::/usr/local/sbin", { null }).map { it.toString() }
        assertEquals("/usr/bin/gpg", unix.first())
        assertTrue(unix.indexOf("/home/u/bin/gpg") > unix.indexOf("/opt/local/bin/gpg"), "PATH comes after the fixed places")
        assertTrue(unix.none { !it.startsWith("/") }, "relative PATH entries are skipped: $unix")
        assertTrue("/usr/local/sbin/gpg2" in unix)

        val env = mapOf("ProgramFiles" to "D:\\Apps", "ProgramFiles(x86)" to "D:\\Apps86")
        val win = GnupgImport.gpgCandidates(true, ".;C:\\tools;relative\\dir;\\\\host\\share", { env[it] }, listOf("E:\\GnuPG\\"))
            .map { it.toString() }
        assertEquals(
            listOf(
                "D:\\Apps86\\GnuPG\\bin\\gpg.exe", "D:\\Apps\\GnuPG\\bin\\gpg.exe",
                "C:\\Program Files (x86)\\GnuPG\\bin\\gpg.exe", "C:\\Program Files\\GnuPG\\bin\\gpg.exe",
                "E:\\GnuPG\\bin\\gpg.exe", "C:\\tools\\gpg.exe", "\\\\host\\share\\gpg.exe"
            ),
            win
        )
    }

    @Test
    fun gnupg1AFolderThatIsNotTheGnupgHomeNeverGetsGpg() {
        val dir = Files.createTempDirectory("pgpony-gnupg-other")
        Files.write(dir.resolve("pubring.kbx"), keybox(key("Someone").publicKeyData))
        val fake = GnupgImport.Gpg(Path.of("/bin/false"), "gpg (GnuPG) 2.4.4")
        val scan = GnupgImport.scan(dir, gpg = fake)
        assertFalse(scan.isDefault)
        assertNull(scan.gpg, "gpg is not offered for a picked folder")
        assertEquals(1, scan.publicKeys)
        // A Scan built by hand for the same folder still does not run gpg.
        val plan = GnupgImport.prepare(scan.copy(gpg = fake, isDefault = true))
        assertNull(plan.scan.gpg)
        assertEquals(1, plan.keys.size)
    }

    @Test
    fun keyringKeysGiveFingerprintsAndUserIds() {
        val a = key("Ann")
        val b = key("Ben")
        val keys = GnupgImport.keyringKeys(a.publicKeyData + b.publicKeyData)
        assertEquals(listOf(a.fingerprint.uppercase(), b.fingerprint.uppercase()), keys.map { it.fingerprint })
        assertEquals("Ann <ann@example.org>", keys[0].userId)
    }

    @Test
    fun aHomeWithoutGpgImportsPublicKeysAndRaisesTrustCarefully() = runBlocking {
        val dir = Files.createTempDirectory("pgpony-gnupg-test")
        val home = Files.createDirectories(dir.resolve("gnupg"))
        val mine = key("Mine")
        val ownSecret = key("Secret")
        val friend = key("Friend")
        val other = key("Other")
        val off = key("Off")
        val outsider = key("Outsider")
        Files.write(
            home.resolve("pubring.kbx"),
            keybox(mine.publicKeyData, ownSecret.publicKeyData, friend.publicKeyData, other.publicKeyData, off.publicKeyData)
        )
        Files.write(
            home.resolve("trustdb.gpg"),
            ByteArray(40).also { it[0] = 1 } +
                trustRecord(mine.fingerprint, 6) + trustRecord(ownSecret.fingerprint, 6) +
                trustRecord(friend.fingerprint, 5) + trustRecord(other.fingerprint, 3) +
                trustRecord(off.fingerprint, 0x86) + trustRecord(outsider.fingerprint, 6)
        )
        assertTrue(GnupgImport.looksLikeHome(home))
        assertFalse(GnupgImport.looksLikeHome(dir))

        val (db, repo) = repoIn(dir)
        // Already verified in PGPony: a lower GnuPG trust must not lower it.
        repo.importBytes(other.publicKeyData)
        repo.updateTrustLevel(other.fingerprint, TrustLevel.VERIFIED)
        // The secret of one own key is already in PGPony.
        repo.importBytes(ownSecret.privateKeyData)
        // gnupg3: a key PGPony holds that is not in this keyring is left alone.
        repo.importBytes(outsider.publicKeyData)

        val scan = GnupgImport.scan(home)
        assertEquals(5, scan.publicKeys)
        assertEquals(emptyList(), scan.secretKeys)
        assertNull(scan.gpg)

        val plan = GnupgImport.prepare(scan)
        val preview = GnupgImport.trustPreview(repo, plan, withSecrets = true)
        assertEquals(
            mapOf(mine.fingerprint.uppercase() to TrustLevel.VERIFIED, ownSecret.fingerprint.uppercase() to TrustLevel.ULTIMATE),
            preview.associate { it.fingerprint.uppercase() to it.to },
            "the preview lists exactly what will change"
        )
        assertTrue(plan.notes.any { it.contains("Off") || it == "d_gnupg_note_disabled" }, "gnupg5: the disabled key is named: ${plan.notes}")

        val result = GnupgImport.apply(repo, plan, withTrust = true, withSecrets = true)
        assertEquals(3, result.report.inserted)
        assertEquals(2, result.trustSet)
        assertEquals(0, result.secretsImported, "no gpg, no secret keys")
        assertEquals(TrustLevel.VERIFIED, repo.byFingerprint(mine.fingerprint)!!.trustLevel, "no secret, so not Ultimate")
        assertEquals(TrustLevel.ULTIMATE, repo.byFingerprint(ownSecret.fingerprint)!!.trustLevel)
        assertFalse(repo.byFingerprint(friend.fingerprint)!!.trustLevel.ordinal >= TrustLevel.VERIFIED.ordinal, "full ownertrust alone")
        assertEquals(TrustLevel.VERIFIED, repo.byFingerprint(other.fingerprint)!!.trustLevel)
        assertFalse(repo.byFingerprint(off.fingerprint)!!.trustLevel.ordinal >= TrustLevel.VERIFIED.ordinal, "disabled")
        assertFalse(repo.byFingerprint(outsider.fingerprint)!!.trustLevel.ordinal >= TrustLevel.VERIFIED.ordinal, "not in the keyring")
        assertEquals(2, result.trustChanges.size)

        val again = GnupgImport.import(repo, scan, withTrust = true, withSecrets = false)
        assertEquals(0, again.report.inserted)
        assertEquals(0, again.trustSet, "nothing to raise the second time")
        db.close()
    }

    @Test
    fun gnupg3UntickedTrustChangesAreNotApplied() = runBlocking {
        val dir = Files.createTempDirectory("pgpony-gnupg-pick")
        val home = Files.createDirectories(dir.resolve("gnupg"))
        val a = key("Keep")
        val b = key("Skip")
        Files.write(home.resolve("pubring.kbx"), keybox(a.publicKeyData, b.publicKeyData))
        Files.write(home.resolve("trustdb.gpg"), ByteArray(40).also { it[0] = 1 } + trustRecord(a.fingerprint, 6) + trustRecord(b.fingerprint, 6))
        val (db, repo) = repoIn(dir)
        val plan = GnupgImport.prepare(GnupgImport.scan(home))
        assertEquals(2, GnupgImport.trustPreview(repo, plan, false).size)
        val result = GnupgImport.apply(repo, plan, withTrust = true, withSecrets = false, selected = setOf(a.fingerprint))
        assertEquals(listOf(a.fingerprint.uppercase()), result.trustChanges.map { it.fingerprint.uppercase() })
        assertEquals(TrustLevel.VERIFIED, repo.byFingerprint(a.fingerprint)!!.trustLevel)
        assertFalse(repo.byFingerprint(b.fingerprint)!!.trustLevel.ordinal >= TrustLevel.VERIFIED.ordinal)

        val none = GnupgImport.apply(repo, plan, withTrust = false, withSecrets = false)
        assertEquals(0, none.trustSet)
        db.close()
    }
}
