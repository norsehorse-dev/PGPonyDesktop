// ProgressStream.kt
// PGPony Desktop — D17 (2.0.0 §3b): multi-gigabyte honesty.
//
// The vendored engine already streams (encryptStream / decryptStream read an InputStream in
// chunks and never buffer the whole file); the UI just never said so, and there was no way to
// stop a 10 GB encrypt once started. Both are fixed from OUTSIDE the vendored code — which we
// never edit — by decorating the InputStream we hand the engine:
//
//   • bytes read = work done, so a counter on read() is the progress signal (for encrypt, the
//     plaintext source; for decrypt, the ciphertext; for a folder, the tar pipe);
//   • the engine's read loop is the one place it checks in with us every few KiB, so a cancel
//     flag tested there interrupts a blocking crypto pass promptly, no thread.interrupt needed.
//
// A cancel throws [CancelledException], which propagates out of the engine call; the file op's
// catch deletes the half-written output. That is the §3b acceptance bar's third clause — the
// never-overwrite rule extended to never-leave-partials.

package com.pgpony.desktop

import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream

/** Thrown by [ProgressInputStream] when the operation's cancel flag is set mid-read. */
class CancelledException(message: String = "cancelled") : IOException(message)

/**
 * Wraps [inner], counting bytes read and reporting progress no more than once per [tick] bytes
 * (plus a final report on [finish]) so a fast stream doesn't flood the UI with snapshot writes.
 * [total] is the best-known size (the source file's length; 0 or negative means "unknown", and
 * the UI shows an indeterminate bar). [isCancelled] is polled on every read — the engine reads
 * in 8–64 KiB chunks, so cancellation lands within one chunk, not one file.
 */
class ProgressInputStream(
    inner: InputStream,
    private val total: Long,
    private val isCancelled: () -> Boolean,
    private val onProgress: (done: Long, total: Long) -> Unit,
    private val tick: Long = 1L shl 20   // 1 MiB
) : FilterInputStream(inner) {

    private var done = 0L
    private var lastReported = 0L

    override fun read(): Int {
        checkCancel()
        val b = super.read()
        if (b >= 0) advance(1)
        return b
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        checkCancel()
        val n = super.read(b, off, len)
        if (n > 0) advance(n.toLong())
        return n
    }

    private fun advance(n: Long) {
        done += n
        if (done - lastReported >= tick) {
            lastReported = done
            onProgress(done, total)
        }
    }

    private fun checkCancel() {
        if (isCancelled()) throw CancelledException()
    }

    /** Emit a final progress report (call after the stream is fully consumed). */
    fun finish() = onProgress(done, total)

    val bytesRead: Long get() = done
}
