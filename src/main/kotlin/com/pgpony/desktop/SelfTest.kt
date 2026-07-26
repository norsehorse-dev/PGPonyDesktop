// SelfTest.kt
// PGPony Desktop — `pgpony selftest`: proves the vendored Android engine runs on this JVM.
// Mirrors RelayPony's selftest verb. Returns a process exit code (0 pass / 1 fail).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.security.Security

object SelfTest {

    fun run(): Int {
        println("PGPony Desktop ${AppVersion.VERSION} — engine selftest")
        var failures = 0

        failures += step("Bouncy Castle provider registered") {
            PGPCryptoService.shared // companion init registers the provider
            checkNotNull(Security.getProvider("BC")) { "BC provider missing" }
            "bcprov ${Security.getProvider("BC").versionStr}"
        }

        failures += step("v4 Ed25519+Cv25519: generate → export → import round-trip") {
            roundTrip(KeyAlgorithm.ED25519_CV25519)
        }

        failures += step("v6 Ed25519 (RFC 9580): generate → export → import round-trip") {
            roundTrip(KeyAlgorithm.V6_ED25519)
        }

        failures += step("Room keyring: import → reopen → read round-trip") {
            val dir = Files.createTempDirectory("pgpony-selftest")
            val gen = PGPCryptoService.shared.generateKeyPair(
                name = "PGPony Selftest", email = "selftest@pgpony.app",
                algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "pgpony-selftest"
            )
            runBlocking {
                val db1 = Db.open(dir.resolve("pgpony.db"))
                val repo1 = DesktopKeyRepository(db1, KeyMaterialStore(dir.resolve("keys")))
                val report = repo1.importArmoredText(gen.armoredPublicKey)
                check(report.inserted == 1) { "expected 1 inserted, got ${report.summary()}" }
                db1.close()

                val db2 = Db.open(dir.resolve("pgpony.db"))
                val repo2 = DesktopKeyRepository(db2, KeyMaterialStore(dir.resolve("keys")))
                val keys = repo2.allKeys()
                check(keys.size == 1) { "expected 1 key after reopen" }
                check(keys[0].fingerprint.equals(gen.fingerprint, ignoreCase = true)) {
                    "fingerprint drift across reopen"
                }
                db2.close()
            }
            "1 key persisted through Room + reopened"
        }

        println(if (failures == 0) "PASS — engine + store healthy" else "FAIL — $failures step(s) failed")
        return if (failures == 0) 0 else 1
    }

    private fun roundTrip(algorithm: KeyAlgorithm): String {
        val service = PGPCryptoService.shared
        val gen = service.generateKeyPair(
            name = "PGPony Selftest", email = "selftest@pgpony.app",
            algorithm = algorithm, passphrase = "pgpony-selftest"
        )
        val pub = service.importArmoredKey(gen.armoredPublicKey)
        check(pub.fingerprint.equals(gen.fingerprint, ignoreCase = true)) { "public fingerprint mismatch" }
        check(!pub.hasPrivateKey) { "public import claims a secret" }
        val sec = service.importArmoredKey(gen.armoredPrivateKey)
        check(sec.fingerprint.equals(gen.fingerprint, ignoreCase = true)) { "secret fingerprint mismatch" }
        check(sec.hasPrivateKey) { "secret import lost the secret" }
        return "fp ${gen.fingerprint.take(16)}… ok"
    }

    /** Runs [body], prints ✓/✗, returns 0 on success and 1 on failure. */
    private fun step(label: String, body: () -> String): Int = try {
        val detail = body()
        println("  ✓ $label — $detail")
        0
    } catch (t: Throwable) {
        println("  ✗ $label — ${t.message ?: t::class.simpleName}")
        1
    }
}
