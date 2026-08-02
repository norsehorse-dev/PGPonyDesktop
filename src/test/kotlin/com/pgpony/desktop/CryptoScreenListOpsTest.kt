// CryptoScreenListOpsTest.kt
// 1.1.0 — pins PathListOps (CryptoScreen.kt) against the Path/Iterable overload trap.
//
// `java.nio.file.Path` implements `Iterable<Path>` over its own name components, so the stdlib
// gives every `List<Path> ± Path` expression TWO applicable overloads and resolution picks the
// Iterable one: `list - path` subtracts the path's components (a silent no-op), `list + path`
// appends the components as separate elements. That shipped as the 1.0.x "Remove does nothing"
// field report, a matching attachment-Remove no-op, and single-file opens (double-click /
// CLI / forwarded instance) filling the Files tab with path fragments. Pure list logic on
// purpose — no Compose — so the semantics stay testable without a UI harness.
//
// If one of these ever fails after an edit that "simplified" PathListOps back to the operators,
// the failure IS the bug report. See CLAUDE.md's working conventions.

package com.pgpony.desktop

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CryptoScreenListOpsTest {

    // Multi-component absolute paths, like every real queue entry: the trap only bites when
    // the path has components to iterate.
    private val report = Path.of("/Users/kevin/Docs/report.txt")
    private val notes = Path.of("/Users/kevin/Docs/notes.txt")
    private val photo = Path.of("/Users/kevin/Pictures/photo.jpg")

    // ── The reported bug: Files-tab Remove ─────────────────────────────────

    @Test
    fun removeOneOfTwoQueuedPaths() {
        val list = listOf(report, notes)
        assertEquals(listOf(notes), PathListOps.remove(list, report))
    }

    @Test
    fun removeMiddleOfThreeKeepsOrder() {
        val list = listOf(report, notes, photo)
        assertEquals(listOf(report, photo), PathListOps.remove(list, notes))
    }

    @Test
    fun removeAllOneAtATimeReachesEmpty() {
        var list = listOf(report, notes)
        list = PathListOps.remove(list, notes)
        list = PathListOps.remove(list, report)
        assertTrue(list.isEmpty())
    }

    @Test
    fun removeAbsentPathIsANoOp() {
        val list = listOf(report)
        assertEquals(list, PathListOps.remove(list, photo))
    }

    // ── The unreported sibling: bundle-attachment Remove ───────────────────
    // Same helper, but pinned separately because CryptoScreen has two independent call sites
    // (fileList and attachments) and both were broken the same way.

    @Test
    fun removeOneOfTwoAttachments() {
        val attachments = listOf(report, photo)
        assertEquals(listOf(report), PathListOps.remove(attachments, photo))
    }

    // ── The sibling that mattered most: the single-path add ────────────────
    // `listOf(a) + b` under the trap yields [report.txt, Users, kevin, Docs, notes.txt]:
    // size 5, the original demoted, fragments queued. The assertions below are written
    // against exactly that failure shape.

    @Test
    fun addSinglePathAddsOneElementIntact() {
        val list = PathListOps.add(emptyList(), report)
        assertEquals(1, list.size)
        assertEquals(report, list.single())
    }

    @Test
    fun addToNonEmptyListAppendsThePathNotItsComponents() {
        val list = PathListOps.add(listOf(report), notes)
        assertEquals(listOf(report, notes), list)
    }

    @Test
    fun addAlreadyQueuedPathIsANoOp() {
        val list = listOf(report, notes)
        assertEquals(list, PathListOps.add(list, notes))
    }

    // ── The batch add (drop / picker path — was never broken; pinned so it stays that way) ──

    @Test
    fun addAllAppendsInOrderAndDeduplicates() {
        val list = PathListOps.addAll(listOf(report), listOf(notes, report, photo))
        assertEquals(listOf(report, notes, photo), list)
    }

    @Test
    fun addAllOfNothingIsANoOp() {
        val list = listOf(report)
        assertEquals(list, PathListOps.addAll(list, emptyList()))
    }
}
