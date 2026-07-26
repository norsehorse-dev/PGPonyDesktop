// BackupCodecTest.kt
// PGPony Android — 4.0.0 Phase 3
//
// Pure-JVM unit tests for the two dependency-free backup codecs
// (CrockfordBase32, UstarArchive). These carry no Android dependencies
// so they run under `./gradlew test`. The full BackupService round-trip
// (which needs a KeyRepository + Android context) is exercised on device.

package com.pgpony.android.backup

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupCodecTest {

    // ── CrockfordBase32 ──────────────────────────────────────────────

    @Test fun normalize_strips_separators_and_uppercases() {
        assertEquals(
            "F91Q0R2MH448QGAJMD7B2FSV",
            CrockfordBase32.normalize("f91q0r-2mh448-qgajmd-7b2fsv")
        )
        assertEquals(
            "F91Q0R2MH448QGAJMD7B2FSV",
            CrockfordBase32.normalize("  F91Q0R 2MH448\tQGAJMD\n7B2FSV ")
        )
    }

    @Test fun normalize_applies_crockford_typo_mapping() {
        // O → 0, I → 1, L → 1 (case-insensitive)
        assertEquals("0110", CrockfordBase32.normalize("O-i-L-0"))
        assertEquals("0110", CrockfordBase32.normalize("o1l0"))
    }

    @Test fun generate_is_valid_and_round_trips_through_grouping() {
        repeat(200) {
            val rec = CrockfordBase32.generate()
            assertEquals(24, rec.canonical.length)
            assertTrue(rec.canonical.all { it in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" })
            // grouped = 4×6 with 3 hyphens
            assertEquals(27, rec.grouped.length)
            assertEquals(3, rec.grouped.count { it == '-' })
            // normalizing the display form recovers the canonical passphrase
            assertEquals(rec.canonical, CrockfordBase32.normalize(rec.grouped))
            assertTrue(CrockfordBase32.isValid(rec.grouped))
        }
    }

    @Test fun isValid_rejects_wrong_length() {
        assertFalse(CrockfordBase32.isValid("ABC"))
        assertFalse(CrockfordBase32.isValid("F91Q0R-2MH448-QGAJMD")) // 18 symbols
    }

    // ── UstarArchive ─────────────────────────────────────────────────

    @Test fun ustar_round_trips_entries_in_order() {
        val meta = "{\"formatVersion\":1}".toByteArray()
        val key = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n" +
            "-----END PGP PUBLIC KEY BLOCK-----\n").toByteArray()
        val input = listOf(
            UstarArchive.Entry("pgpony-meta.json", meta),
            UstarArchive.Entry("keys/03dfcf198cf0d33e652dff1cd3d564b5bf4329fa.asc", key),
            UstarArchive.Entry("pgpony-settings.json", "{}".toByteArray())
        )
        val archive = UstarArchive.write(input)
        // ends with two zero blocks
        assertTrue(archive.size % 512 == 0)
        val out = UstarArchive.read(archive)

        assertEquals(3, out.size)
        assertEquals("pgpony-meta.json", out[0].name)          // meta first
        assertEquals("keys/03dfcf198cf0d33e652dff1cd3d564b5bf4329fa.asc", out[1].name)
        assertEquals("pgpony-settings.json", out[2].name)
        assertArrayEquals(meta, out[0].data)
        assertArrayEquals(key, out[1].data)
    }

    @Test fun ustar_handles_empty_and_block_aligned_payloads() {
        val exact = ByteArray(512) { 'x'.code.toByte() }   // exactly one block
        val input = listOf(
            UstarArchive.Entry("a", ByteArray(0)),
            UstarArchive.Entry("b", exact),
            UstarArchive.Entry("c", "tail".toByteArray())
        )
        val out = UstarArchive.read(UstarArchive.write(input))
        assertEquals(listOf("a", "b", "c"), out.map { it.name })
        assertEquals(0, out[0].data.size)
        assertArrayEquals(exact, out[1].data)
        assertArrayEquals("tail".toByteArray(), out[2].data)
    }

    @Test fun ustar_long_v6_fingerprint_name_fits() {
        // 64-hex v6 fingerprint filename = "keys/" + 64 + ".asc" = 73 chars ≤ 100
        val name = "keys/" + "a".repeat(64) + ".asc"
        val out = UstarArchive.read(
            UstarArchive.write(listOf(UstarArchive.Entry(name, "k".toByteArray())))
        )
        assertEquals(name, out[0].name)
    }
}
