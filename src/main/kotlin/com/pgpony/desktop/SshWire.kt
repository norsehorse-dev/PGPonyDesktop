// SshWire.kt
// PGPony Desktop — D15 (2.0.0 §1a): the ssh-agent wire, pure half.
//
// The ExpirationNotifier split: everything in this file is bytes-in/bytes-out with no I/O, no
// threads and no keyring, so the protocol is unit-testable without a socket; SshAgentService
// owns the plumbing. The protocol is draft-miller-ssh-agent, and deliberately only the slice
// the plan commits to: REQUEST_IDENTITIES, SIGN_REQUEST, and the failure code. EVERYTHING else
// — add/remove identities, locking, extensions — answers SSH_AGENT_FAILURE, which is the
// spec's own instruction for unrecognized requests. An agent whose keys arrive from anywhere
// but the PGPony keyring is not this agent.
//
// Byte conventions (RFC 4251 §5): uint32 big-endian; `string` is uint32 length + bytes;
// `mpint` is two's complement with the minimal length — which for the non-negative integers
// SSH keys use is exactly what BigInteger.toByteArray() produces, including the leading zero
// byte when the high bit is set. No hand-rolled sign fiddling: the test pins the 0x80 edge.

package com.pgpony.desktop

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger

/** One key the agent offers: the SSH public-key blob and the comment `ssh-add -L` shows. */
class SshIdentity(val blob: ByteArray, val comment: String)

object SshWire {

    // Message numbers (draft-miller-ssh-agent §5.1).
    const val SSH_AGENT_FAILURE = 5
    const val SSH_AGENTC_REQUEST_IDENTITIES = 11
    const val SSH_AGENT_IDENTITIES_ANSWER = 12
    const val SSH_AGENTC_SIGN_REQUEST = 13
    const val SSH_AGENT_SIGN_RESPONSE = 14

    // SIGN_REQUEST flags (§4.5.1). No flag means the key type's default algorithm — for RSA
    // that is SHA-1 "ssh-rsa", which modern OpenSSH never asks for but the spec still names.
    const val SSH_AGENT_RSA_SHA2_256 = 2
    const val SSH_AGENT_RSA_SHA2_512 = 4

    /** Agent messages are a key list or one signature — 1 MiB shuts down a hostile peer. */
    const val MAX_MESSAGE = 1 shl 20

    // ── Building ───────────────────────────────────────────────────────────

    fun uint32(v: Int): ByteArray = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )

    fun string(bytes: ByteArray): ByteArray = uint32(bytes.size) + bytes

    fun string(s: String): ByteArray = string(s.toByteArray(Charsets.UTF_8))

    /** RFC 4251 mpint for a non-negative value (SSH keys have no negative parameters). */
    fun mpint(v: BigInteger): ByteArray {
        require(v.signum() >= 0) { "mpint: negative values have no place in a public key" }
        return string(if (v.signum() == 0) ByteArray(0) else v.toByteArray())
    }

    /** `ssh-ed25519` public blob from the bare 32-byte point. */
    fun ed25519PublicBlob(raw: ByteArray): ByteArray {
        require(raw.size == 32) { "ssh-ed25519 wants exactly 32 bytes, got ${raw.size}" }
        return string("ssh-ed25519") + string(raw)
    }

    /** `ssh-rsa` public blob. Wire order is e then n — the reverse of most textbook habits. */
    fun rsaPublicBlob(e: BigInteger, n: BigInteger): ByteArray =
        string("ssh-rsa") + mpint(e) + mpint(n)

    /** The signature container: algorithm name + raw signature bytes, both as strings. */
    fun signatureBlob(algorithm: String, signature: ByteArray): ByteArray =
        string(algorithm) + string(signature)

    // ── Parsing ────────────────────────────────────────────────────────────

    /** A bounds-checked cursor over one message payload. Throws EOFException on truncation —
     *  the caller answers FAILURE rather than crashing on a malformed peer. */
    class Reader(private val buf: ByteArray) {
        private var pos = 0

        fun byte(): Int {
            if (pos >= buf.size) throw EOFException("truncated agent message")
            return buf[pos++].toInt() and 0xFF
        }

        fun uint32(): Int {
            if (pos + 4 > buf.size) throw EOFException("truncated agent message")
            val v = ((buf[pos].toInt() and 0xFF) shl 24) or
                ((buf[pos + 1].toInt() and 0xFF) shl 16) or
                ((buf[pos + 2].toInt() and 0xFF) shl 8) or
                (buf[pos + 3].toInt() and 0xFF)
            pos += 4
            return v
        }

        fun string(): ByteArray {
            val len = uint32()
            if (len < 0 || len > MAX_MESSAGE || pos + len > buf.size) {
                throw EOFException("truncated agent string")
            }
            return buf.copyOfRange(pos, pos + len).also { pos += len }
        }
    }

    // ── Framing ────────────────────────────────────────────────────────────

    /** One length-prefixed frame, or null on orderly EOF before a length arrives. */
    fun readFrame(input: InputStream): ByteArray? {
        val head = ByteArray(4)
        var got = 0
        while (got < 4) {
            val n = input.read(head, got, 4 - got)
            if (n < 0) {
                if (got == 0) return null
                throw EOFException("connection closed mid-length")
            }
            got += n
        }
        val len = ((head[0].toInt() and 0xFF) shl 24) or ((head[1].toInt() and 0xFF) shl 16) or
            ((head[2].toInt() and 0xFF) shl 8) or (head[3].toInt() and 0xFF)
        if (len <= 0 || len > MAX_MESSAGE) throw EOFException("unreasonable frame length $len")
        val payload = ByteArray(len)
        got = 0
        while (got < len) {
            val n = input.read(payload, got, len - got)
            if (n < 0) throw EOFException("connection closed mid-frame")
            got += n
        }
        return payload
    }

    fun writeFrame(output: OutputStream, payload: ByteArray) {
        output.write(uint32(payload.size))
        output.write(payload)
        output.flush()
    }

    // ── The request handler ────────────────────────────────────────────────

    /**
     * Answer one agent request. [identities] is called per request so `ssh-add -L` always sees
     * the keyring as it is now, not as it was at toggle-time. [sign] returns the complete
     * signature blob, or null for any refusal — no key, no unlock, unsupported flags — which
     * all map to the same SSH_AGENT_FAILURE; the protocol has no channel for reasons, and an
     * agent that explains its keyring to an unauthenticated socket peer would be a bug.
     */
    fun handleRequest(
        payload: ByteArray,
        identities: () -> List<SshIdentity>,
        sign: (keyBlob: ByteArray, data: ByteArray, flags: Int) -> ByteArray?
    ): ByteArray = try {
        val reader = Reader(payload)
        when (reader.byte()) {
            SSH_AGENTC_REQUEST_IDENTITIES -> {
                val ids = identities()
                var answer = byteArrayOf(SSH_AGENT_IDENTITIES_ANSWER.toByte()) + uint32(ids.size)
                for (id in ids) answer += string(id.blob) + string(id.comment)
                answer
            }
            SSH_AGENTC_SIGN_REQUEST -> {
                val keyBlob = reader.string()
                val data = reader.string()
                val flags = reader.uint32()
                val sig = sign(keyBlob, data, flags)
                if (sig == null) failure()
                else byteArrayOf(SSH_AGENT_SIGN_RESPONSE.toByte()) + string(sig)
            }
            else -> failure()
        }
    } catch (_: Exception) {
        failure()
    }

    fun failure(): ByteArray = byteArrayOf(SSH_AGENT_FAILURE.toByte())
}
