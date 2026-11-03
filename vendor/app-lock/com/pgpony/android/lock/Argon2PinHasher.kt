// Argon2PinHasher.kt
// PGPony Android 4.7.0 (item 32): Argon2id for the app lock PIN, through Bouncy
// Castle's lightweight API (no Android in it). Slow by design: callers run it
// off the main thread.

package com.pgpony.android.lock

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

object Argon2PinHasher : PinHasher {
    override fun hash(pin: ByteArray, salt: ByteArray, params: PinHashParams): ByteArray {
        val p = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withIterations(params.iterations)
            .withMemoryAsKB(params.memoryKiB)
            .withParallelism(params.parallelism)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(p)
        val out = ByteArray(params.outputLength)
        generator.generateBytes(pin, out)
        return out
    }
}
