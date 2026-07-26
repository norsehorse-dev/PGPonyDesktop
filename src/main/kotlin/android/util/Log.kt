// Log.kt — PGPony Desktop D4 vendor shim.
// `android.util.Log` stand-in so vendored files with diagnostic Log.d/w/e calls compile on the
// JVM (first consumer: network/KeyServerRepository.kt). Debug lines route to stdout only when
// -Dpgpony.debug=true; return values mirror the Android signatures.
// Inventory: vendor/README.md. Superseded if upstream ever adopts a logger seam.

package android.util

object Log {
    private val enabled = System.getProperty("pgpony.debug") == "true"

    @JvmStatic fun d(tag: String, msg: String): Int { if (enabled) println("D/$tag: $msg"); return 0 }
    @JvmStatic fun i(tag: String, msg: String): Int { if (enabled) println("I/$tag: $msg"); return 0 }
    @JvmStatic fun w(tag: String, msg: String): Int { if (enabled) println("W/$tag: $msg"); return 0 }
    @JvmStatic fun e(tag: String, msg: String): Int { if (enabled) println("E/$tag: $msg"); return 0 }
    @JvmStatic fun e(tag: String, msg: String, tr: Throwable): Int {
        if (enabled) println("E/$tag: $msg — ${tr.message}"); return 0
    }
}
