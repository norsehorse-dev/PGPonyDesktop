// GpgShimTest.kt
// D15 validation — the git-shim dispatch (GpgShim.run): which invocation maps to which mode,
// and where the machine-readable status lines go. The sign/verify crypto rides SigningService
// and VerifyService (their own suites) and, end-to-end, `git commit -S` + `git verify-commit`
// in the manual matrix (2.0.0 §8); what's new and worth pinning here is the argv parsing.

package com.pgpony.desktop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class GpgShimTest {

    private class Run(val code: Int, val out: String, val err: String)

    private fun run(args: List<String>, stdin: ByteArray = ByteArray(0)): Run {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = GpgShim.run(args, ByteArrayInputStream(stdin), out, PrintStream(err, true))
        return Run(code, out.toString(Charsets.UTF_8), err.toString(Charsets.UTF_8))
    }

    @Test
    fun versionProbeSucceedsWithoutAKeyring() {
        // git calls `gpg --version` while validating gpg.program; it must answer without
        // touching the database (this test runs with no PGPony data dir set up).
        val r = run(listOf("--version"))
        assertEquals(0, r.code)
        assertTrue(r.out.contains("PGPony shim"), "banner on stdout: '${r.out}'")
    }

    @Test
    fun anUnsupportedInvocationExitsNonZeroAndDoesNotTouchTheKeyring() {
        val r = run(listOf("--decrypt"))
        assertEquals(2, r.code)
        assertTrue(r.err.contains("unsupported"), "explains itself on stderr: '${r.err}'")
    }

    @Test
    fun signWithoutAUserSelectorIsARejection() {
        // -bsau with no key name (and no positional) is a usage error, caught before any
        // keyring access — so it's hermetic and pins the "no -u" branch.
        val r = run(listOf("--status-fd=2", "-b", "-s", "-a"))
        assertEquals(2, r.code)
        assertTrue(r.err.contains("no signing key"), "got: '${r.err}'")
    }

    @Test
    fun verifyWithMissingFilesReportsCleanlyOnStderrNotStatus() {
        // --status-fd=1 routes status to stdout; a file-read failure is a human error on
        // stderr and must not emit a GOODSIG/BADSIG line (that would fool git).
        val r = run(listOf("--keyid-format=long", "--status-fd=1", "--verify"))
        assertEquals(2, r.code)
        assertTrue(r.err.contains("no signature file"), "got err: '${r.err}'")
        assertTrue(!r.out.contains("GNUPG"), "no status line should reach stdout: '${r.out}'")
    }
}
