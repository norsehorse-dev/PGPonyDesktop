// WatchRuleTest.kt
// D18 validation — the pure pieces of the watch-folder feature (src/main/kotlin/com/pgpony/
// desktop/WatchRule.kt): the glob matcher, the quiesce heuristic, and JSON round-trip of the
// rule set. The WatchService thread itself (WatchFolderService) is exercised by the manual
// matrix (§8: copy 3 files in slowly → 3 outputs after quiesce; restart with rules present →
// resume, nothing double-encrypted), since a deterministic filesystem-event test is flaky by
// nature; what's pinned here is the logic those outcomes depend on.

package com.pgpony.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WatchRuleTest {

    // ── Glob matching ───────────────────────────────────────────────────────

    @Test
    fun globMatchesByExtensionAndWildcards() {
        assertTrue(WatchRule.globMatches("*", "anything.txt"))
        assertTrue(WatchRule.globMatches("*.pdf", "report.pdf"))
        assertFalse(WatchRule.globMatches("*.pdf", "report.txt"))
        assertTrue(WatchRule.globMatches("invoice-*.csv", "invoice-2026.csv"))
        assertTrue(WatchRule.globMatches("{jpg,png}", "png"))
        assertTrue(WatchRule.globMatches("*.{jpg,png}", "photo.png"))
    }

    @Test
    fun globMatchesAFilenameNotAPathAndAMalformedGlobIsInert() {
        // Rules glob a bare filename; a pattern with a slash can't match one, by design.
        assertFalse(WatchRule.globMatches("sub/*.txt", "a.txt"))
        // A malformed pattern matches nothing rather than throwing — a bad rule is inert.
        assertFalse(WatchRule.globMatches("[", "a.txt"))
    }

    @Test
    fun ruleMatchesDelegatesToGlob() {
        val rule = WatchRule(id = "r1", folder = "/tmp/in", glob = "*.log")
        assertTrue(rule.matches("server.log"))
        assertFalse(rule.matches("server.txt"))
    }

    // ── Quiesce ─────────────────────────────────────────────────────────────

    @Test
    fun quiesceFiresOnlyAfterTwoStableObservations() {
        val q = QuiesceTracker(stableTicksRequired = 2)
        val p = Path.of("/tmp/growing.dat")
        assertFalse(q.observe(p, 100), "first sighting is never stable")
        assertTrue(q.observe(p, 100), "same size twice → stable, fire")
        assertFalse(q.observe(p, 100), "already fired — never fires twice")
    }

    @Test
    fun quiesceResetsWhenTheFileKeepsGrowing() {
        val q = QuiesceTracker(stableTicksRequired = 2)
        val p = Path.of("/tmp/copy.dat")
        assertFalse(q.observe(p, 100))
        assertFalse(q.observe(p, 200), "grew → not stable")
        assertFalse(q.observe(p, 300), "grew again — establishes 300 at one tick")
        assertTrue(q.observe(p, 300), "same size a second time → stable, fire")
    }

    @Test
    fun quiesceForgetLetsAFileBeSeenFresh() {
        val q = QuiesceTracker(stableTicksRequired = 2)
        val p = Path.of("/tmp/again.dat")
        q.observe(p, 10); q.observe(p, 10) // fires
        q.forget(p)
        assertFalse(q.observe(p, 20), "after forget, it's a fresh first sighting")
        assertTrue(q.observe(p, 20))
    }

    // ── Persistence ─────────────────────────────────────────────────────────

    private var tmpFile: Path? = null
    @AfterTest fun cleanup() { tmpFile?.let { Files.deleteIfExists(it) }; WatchRulesStore.fileOverride = null }

    @Test
    fun rulesRoundTripThroughJson() {
        val f = Files.createTempFile("watch-rules", ".json").also { tmpFile = it }
        WatchRulesStore.fileOverride = f
        val rule = WatchRule(
            id = "abc", folder = "/home/me/Backups", glob = "*.pdf",
            recipients = listOf("AAAA1111", "BBBB2222"), outputDir = "/home/me/Encrypted",
            deleteOriginal = true, armor = true, enabled = false
        )
        WatchRulesStore.save(WatchRules(rules = listOf(rule)))
        val back = WatchRulesStore.load()
        assertEquals(1, back.rules.size)
        assertEquals(rule, back.rules.first(), "every field survives the round trip")
    }

    @Test
    fun addRemoveAndToggleMutateAndPersist() {
        val f = Files.createTempFile("watch-rules", ".json").also { tmpFile = it }
        Files.deleteIfExists(f) // start from no file at all
        WatchRulesStore.fileOverride = f

        WatchRulesStore.add(WatchRule(id = "r1", folder = "/a"))
        WatchRulesStore.add(WatchRule(id = "r2", folder = "/b"))
        assertEquals(2, WatchRulesStore.load().rules.size)

        val toggled = WatchRulesStore.setRuleEnabled("r1", false)
        assertFalse(toggled.rules.first { it.id == "r1" }.enabled)

        val afterRemove = WatchRulesStore.remove("r2")
        assertEquals(listOf("r1"), afterRemove.rules.map { it.id })
    }

    @Test
    fun aMissingRulesFileLoadsAsEmptyNotAnError() {
        WatchRulesStore.fileOverride = Path.of("/tmp/does-not-exist-pgpony-watch.json")
        assertTrue(WatchRulesStore.load().rules.isEmpty())
    }
}
