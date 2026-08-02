// SshWireTest.kt
// D15 validation — the ssh-agent wire (src/main/kotlin/com/pgpony/desktop/SshWire.kt), the pure
// half. Byte layouts are checked against the fixed constants in draft-miller-ssh-agent and
// RFC 4251/4253 rather than against a live ssh, which the CI box has no way to drive; the
// end-to-end `ssh-add -L` / `ssh` rows stay in the manual test matrix (2.0.0 §8).

package com.pgpony.desktop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SshWireTest {

    // ── Primitive encoders ─────────────────────────────────────────────────

    @Test
    fun uint32IsBigEndian() {
        assertContentEquals(byteArrayOf(0, 0, 1, 0), SshWire.uint32(256))
        assertContentEquals(byteArrayOf(-1, -1, -1, -1), SshWire.uint32(-1))
    }

    @Test
    fun stringIsLengthPrefixed() {
        assertContentEquals(
            byteArrayOf(0, 0, 0, 3, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte()),
            SshWire.string("abc")
        )
    }

    /**
     * The mpint sign edge: a value whose top byte is ≥ 0x80 gets a leading zero so it can't
     * read as negative. This is exactly BigInteger.toByteArray()'s own behavior, which is why
     * the encoder delegates to it — this test is what proves that delegation is correct.
     */
    @Test
    fun mpintPadsWhenHighBitSet() {
        // 0xFF → needs the padding zero: length 2, bytes 00 FF.
        assertContentEquals(byteArrayOf(0, 0, 0, 2, 0x00, 0xFF.toByte()), SshWire.mpint(BigInteger.valueOf(255)))
        // 0x7F → high bit clear, no pad: length 1.
        assertContentEquals(byteArrayOf(0, 0, 0, 1, 0x7F), SshWire.mpint(BigInteger.valueOf(127)))
        // Zero → empty body.
        assertContentEquals(byteArrayOf(0, 0, 0, 0), SshWire.mpint(BigInteger.ZERO))
    }

    // ── Public blobs ───────────────────────────────────────────────────────

    @Test
    fun ed25519BlobIsTypeThenPoint() {
        val point = ByteArray(32) { it.toByte() }
        val blob = SshWire.ed25519PublicBlob(point)
        val r = SshWire.Reader(blob)
        assertContentEquals("ssh-ed25519".toByteArray(), r.string())
        assertContentEquals(point, r.string())
    }

    @Test
    fun rsaBlobIsTypeThenEThenN() {
        val e = BigInteger.valueOf(65537)
        val n = BigInteger(1, ByteArray(256) { 0xAB.toByte() }) // high bit set → will pad
        val blob = SshWire.rsaPublicBlob(e, n)
        val r = SshWire.Reader(blob)
        assertContentEquals("ssh-rsa".toByteArray(), r.string())
        assertEquals(e, BigInteger(1, r.string()))
        assertEquals(n, BigInteger(1, r.string()))
    }

    // ── Framing round-trip ─────────────────────────────────────────────────

    @Test
    fun frameRoundTrips() {
        val payload = byteArrayOf(11, 1, 2, 3)
        val out = ByteArrayOutputStream()
        SshWire.writeFrame(out, payload)
        val back = SshWire.readFrame(ByteArrayInputStream(out.toByteArray()))
        assertContentEquals(payload, back)
    }

    @Test
    fun readFrameReturnsNullAtCleanEof() {
        assertNull(SshWire.readFrame(ByteArrayInputStream(ByteArray(0))))
    }

    // ── Request handling ───────────────────────────────────────────────────

    private fun frame(vararg parts: ByteArray): ByteArray = parts.fold(ByteArray(0)) { a, b -> a + b }

    @Test
    fun requestIdentitiesListsEveryKey() {
        val ids = listOf(
            SshIdentity(SshWire.ed25519PublicBlob(ByteArray(32) { 1 }), "alice (PGPony)"),
            SshIdentity(SshWire.ed25519PublicBlob(ByteArray(32) { 2 }), "bob (PGPony)")
        )
        val resp = SshWire.handleRequest(
            byteArrayOf(SshWire.SSH_AGENTC_REQUEST_IDENTITIES.toByte()),
            identities = { ids },
            sign = { _, _, _ -> null }
        )
        val r = SshWire.Reader(resp)
        assertEquals(SshWire.SSH_AGENT_IDENTITIES_ANSWER, r.byte())
        assertEquals(2, r.uint32())
        assertContentEquals(ids[0].blob, r.string()); assertEquals("alice (PGPony)", String(r.string()))
        assertContentEquals(ids[1].blob, r.string()); assertEquals("bob (PGPony)", String(r.string()))
    }

    @Test
    fun signRequestPassesBlobDataAndFlagsThroughAndWrapsTheResult() {
        val keyBlob = SshWire.ed25519PublicBlob(ByteArray(32) { 7 })
        val data = "commit payload".toByteArray()
        var sawFlags = -1
        val resp = SshWire.handleRequest(
            frame(
                byteArrayOf(SshWire.SSH_AGENTC_SIGN_REQUEST.toByte()),
                SshWire.string(keyBlob), SshWire.string(data), SshWire.uint32(SshWire.SSH_AGENT_RSA_SHA2_512)
            ),
            identities = { emptyList() },
            sign = { blob, payload, flags ->
                assertContentEquals(keyBlob, blob)
                assertContentEquals(data, payload)
                sawFlags = flags
                SshWire.signatureBlob("ssh-ed25519", byteArrayOf(9, 9))
            }
        )
        assertEquals(SshWire.SSH_AGENT_RSA_SHA2_512, sawFlags)
        val r = SshWire.Reader(resp)
        assertEquals(SshWire.SSH_AGENT_SIGN_RESPONSE, r.byte())
        val inner = SshWire.Reader(r.string())
        assertEquals("ssh-ed25519", String(inner.string()))
        assertContentEquals(byteArrayOf(9, 9), inner.string())
    }

    @Test
    fun signRefusalBecomesFailure() {
        val resp = SshWire.handleRequest(
            frame(byteArrayOf(SshWire.SSH_AGENTC_SIGN_REQUEST.toByte()),
                SshWire.string(ByteArray(4)), SshWire.string(ByteArray(4)), SshWire.uint32(0)),
            identities = { emptyList() },
            sign = { _, _, _ -> null }   // no such key / locked
        )
        assertContentEquals(byteArrayOf(SshWire.SSH_AGENT_FAILURE.toByte()), resp)
    }

    @Test
    fun unknownRequestTypeIsFailureNotACrash() {
        val resp = SshWire.handleRequest(byteArrayOf(99), { emptyList() }, { _, _, _ -> null })
        assertContentEquals(SshWire.failure(), resp)
    }

    @Test
    fun truncatedSignRequestIsFailureNotACrash() {
        // A SIGN_REQUEST byte with no key blob following: the Reader throws EOF, handler catches.
        val resp = SshWire.handleRequest(
            byteArrayOf(SshWire.SSH_AGENTC_SIGN_REQUEST.toByte()),
            { emptyList() }, { _, _, _ -> error("must not be called") }
        )
        assertContentEquals(SshWire.failure(), resp)
    }

    @Test
    fun readerRejectsAnOverlongStringLength() {
        // length field claims 2 GiB; the Reader must refuse rather than allocate.
        val hostile = SshWire.uint32(Int.MAX_VALUE) + byteArrayOf(1, 2, 3)
        val r = SshWire.Reader(hostile)
        assertTrue(runCatching { r.string() }.isFailure)
    }
}
