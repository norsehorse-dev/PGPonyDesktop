// PcscDiagnosticsTest.kt
// 1.0.2 validation — causeChain(), the function that makes an intermittent PC/SC fault legible.
//
// It exists because the JDK wraps every PC/SC failure: sun.security.smartcardio.PCSCTerminals
// catches a PCSCException and rethrows CardException("list() failed", cause). 1.0.1 shipped a
// diagnostic that printed only `e.message`, so a real Windows report came back reading
// "list() failed" and identified nothing. These cases pin the behaviour that fixes that.

package com.pgpony.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PcscDiagnosticsTest {

    @Test
    fun singleThrowableRendersTypeAndMessage() {
        assertEquals("IllegalStateException: boom", causeChain(IllegalStateException("boom")))
    }

    /** The case that motivated the function: the useful code lives one level down. */
    @Test
    fun theWrappedScardCodeSurvives() {
        val real = IllegalStateException("SCARD_E_NO_SERVICE")
        val wrapped = RuntimeException("list() failed", real)
        val line = causeChain(wrapped)
        assertTrue(line.contains("list() failed"), "wrapper text should remain: $line")
        assertTrue(line.contains("SCARD_E_NO_SERVICE"), "the SCARD code is the point: $line")
        assertTrue(
            line.indexOf("list() failed") < line.indexOf("SCARD_E_NO_SERVICE"),
            "outermost first, cause after: $line"
        )
    }

    @Test
    fun deepChainsKeepEveryLink() {
        val e = RuntimeException("a", IllegalArgumentException("b", IllegalStateException("c")))
        val line = causeChain(e)
        listOf("a", "b", "c").forEach { assertTrue(line.contains(it), "missing $it in: $line") }
    }

    /** A throwable with no message must still name itself rather than render as blank. */
    @Test
    fun blankMessagesFallBackToTheClassName() {
        assertEquals("RuntimeException", causeChain(RuntimeException()))
        assertEquals("RuntimeException", causeChain(RuntimeException("   ")))
    }

    /**
     * A cycle between two throwables. Without the seen-set this loops forever, and it would hang
     * inside a card operation triggered by a button press — a worse failure than the one the
     * function exists to report.
     *
     * Note this is the two-throwable form, not self-causation: Throwable.initCause REJECTS being
     * passed the throwable itself (IllegalArgumentException, "Self-causation not permitted"), so
     * a self-referential cause cannot be constructed in Java and needs no test. An earlier version
     * of this file asserted against exactly that impossible state and failed.
     */
    @Test
    fun aCycleBetweenTwoThrowablesTerminates() {
        val a = RuntimeException("a")
        val b = RuntimeException("b", a)
        a.initCause(b)
        val line = causeChain(b)
        assertTrue(line.contains("a") && line.contains("b"), line)
        assertEquals(2, line.split(" <- ").size, "each throwable exactly once: $line")
    }
}
