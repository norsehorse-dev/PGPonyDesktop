// OpenRoutingTest.kt
// D14 validation — the two pure pieces of `pgpony open --op` routing: the CLI grammar
// (Main.parseOpenArgs) and the single-instance wire format (SingleInstance.parseForwarded).
// The router's forced-op decisions live in DesktopFileRouterTest; the end-to-end forwarding
// (two real processes, one socket) is the test matrix's manual "context menu" row, since a
// unit test that binds the real lock file would fight any PGPony the developer has open.

package com.pgpony.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OpenRoutingTest {

    // ── The CLI grammar ────────────────────────────────────────────────────

    private fun withTempFile(body: (Path) -> Unit) {
        val f = Files.createTempFile("pgpony-open", ".txt")
        try {
            body(f)
        } finally {
            Files.deleteIfExists(f)
        }
    }

    @Test
    fun parsesOpInBothSpellingsAndAbsolutizesPaths() {
        withTempFile { f ->
            val spaced = parseOpenArgs(listOf("--op", "encrypt", f.toString()))
            assertEquals(ForcedOp.ENCRYPT, spaced.op)
            assertEquals(listOf(f.toAbsolutePath()), spaced.paths)

            val equals = parseOpenArgs(listOf("--op=verify", f.toString()))
            assertEquals(ForcedOp.VERIFY, equals.op)
        }
    }

    @Test
    fun opIsOptionalAndDefaultsToClassification() {
        withTempFile { f ->
            assertNull(parseOpenArgs(listOf(f.toString())).op)
        }
    }

    @Test
    fun takesSeveralFilesInCommandLineOrder() {
        withTempFile { a ->
            withTempFile { b ->
                val r = parseOpenArgs(listOf("--op", "encrypt", a.toString(), b.toString()))
                assertEquals(listOf(a.toAbsolutePath(), b.toAbsolutePath()), r.paths)
            }
        }
    }

    @Test
    fun rejectsUnknownOpsMissingFilesAndNonFiles() {
        withTempFile { f ->
            // `sign` stays interactive (2.0.0 plan §3c's rule) — not a forced op today.
            assertFailsWith<IllegalArgumentException> {
                parseOpenArgs(listOf("--op", "sign", f.toString()))
            }
            assertFailsWith<IllegalArgumentException> { parseOpenArgs(listOf("--op", "encrypt")) }
            assertFailsWith<IllegalArgumentException> {
                parseOpenArgs(listOf("/no/such/pgpony-test-file.txt"))
            }
        }
    }

    // ── The wire format ────────────────────────────────────────────────────

    @Test
    fun wireCarriesTheOpHeaderThenPaths() {
        val r = SingleInstance.parseForwarded(
            sequenceOf("--op encrypt", "/a/b.txt", "/c d/with space.gpg")
        )
        assertEquals(ForcedOp.ENCRYPT, r.op)
        assertEquals(listOf(Path.of("/a/b.txt"), Path.of("/c d/with space.gpg")), r.paths)
    }

    @Test
    fun wireWithoutHeaderIsAnUnforcedOpen() {
        val r = SingleInstance.parseForwarded(sequenceOf("/a/b.txt"))
        assertNull(r.op)
        assertEquals(listOf(Path.of("/a/b.txt")), r.paths)
    }

    /** A newer secondary naming an op this build doesn't know must still deliver its files. */
    @Test
    fun wireUnknownOpDegradesToClassificationNotToDroppedFiles() {
        val r = SingleInstance.parseForwarded(sequenceOf("--op sign", "/a/b.txt"))
        assertNull(r.op)
        assertEquals(listOf(Path.of("/a/b.txt")), r.paths)
    }

    @Test
    fun wireSkipsBlankLinesAndABareConnectionIsEmpty() {
        val bare = SingleInstance.parseForwarded(emptySequence())
        assertTrue(bare.paths.isEmpty())
        assertNull(bare.op)
        val padded = SingleInstance.parseForwarded(sequenceOf("", "  ", "/a/b.txt", ""))
        assertEquals(1, padded.paths.size)
    }
}
