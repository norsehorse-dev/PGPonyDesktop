// ChangePassphraseTest.kt
// PGPony Android — 4.3.0 §1.1 (#26, change a key's passphrase)
//
// Proves PGPCryptoService.changePassphrase re-protects a ring so the NEW
// passphrase unlocks it and the OLD one no longer recovers the plaintext,
// across every stored format: v4 (RSA and Ed25519+Cv25519), v6, and both
// composite forms at 768 and 1024 (v6 IETF and v5 LibrePGP). An
// encrypt -> decrypt round-trip is the proof, exactly as CompositeKeyGenTest
// uses it: decrypt has to unlock the (re-protected) secret key to recover
// the exact plaintext, so a correct round-trip means the re-encryption kept
// the key valid. Both empty directions (add protection, strip protection)
// are covered too.
//
// The composite cases are the load-bearing ones: they exercise the unlock
// direction (a real decryptor on an algo-35/36/8 subkey) that exists nowhere
// else in the tree (Option A in the changePassphrase KDoc).

package com.pgpony.android.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class ChangePassphraseTest {

    private val svc = PGPCryptoService.shared

    private fun nullIfEmpty(s: String): String? = if (s.isEmpty()) null else s

    private fun keyUsages(ring: PGPSecretKeyRing): String =
        ring.secretKeys.asSequence().joinToString(",") {
            "algo${it.publicKey.algorithm}/v${it.publicKey.version}:s2k${it.s2KUsage}"
        }

    /**
     * Generate [algo] under [oldPass], change it to [newPass], then assert the
     * new passphrase decrypts and (when they differ and old is non-empty) the
     * old one does not.
     */
    private fun changeAndProve(algo: KeyAlgorithm, oldPass: String, newPass: String) {
        val gen = svc.generateKeyPair("Change PP", "change@test.local", algo, nullIfEmpty(oldPass))
        val secRing = PGPSecretKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(gen.privateKeyData)),
            JcaKeyFingerprintCalculator()
        )
        val pubRing = PGPPublicKeyRing(
            PGPUtil.getDecoderStream(ByteArrayInputStream(gen.publicKeyData)),
            JcaKeyFingerprintCalculator()
        )

        val changed = svc.changePassphrase(secRing, oldPass, newPass)

        val pt = "change-passphrase ${algo.shortName} [$oldPass]->[$newPass]".toByteArray()

        // New passphrase must decrypt. Report per-key algorithm and S2K usage
        // on failure so a strip that did not fully unprotect is visible.
        val enc = svc.encrypt(pt, listOf(pubRing))
        val out = try {
            svc.decrypt(enc, listOf(changed), passphrase = nullIfEmpty(newPass))
        } catch (e: Exception) {
            throw AssertionError(
                "decrypt(new) threw for ${algo.shortName} old=[$oldPass] new=[$newPass]; " +
                    "keys=${keyUsages(changed)}; ${e::class.java.simpleName}: ${e.message}"
            )
        }
        if (!out.data.contentEquals(pt)) {
            throw AssertionError(
                "decrypt(new) wrong data for ${algo.shortName} old=[$oldPass] new=[$newPass]; " +
                    "keys=${keyUsages(changed)}; got ${out.data.size} bytes"
            )
        }

        // Strip removes protection entirely, so the key decrypts with any
        // passphrase and "old must fail" is meaningless; assert instead that
        // protection is actually gone (every key S2K usage back to 0).
        if (newPass.isEmpty()) {
            changed.secretKeys.asSequence().forEach { sk ->
                assertEquals(
                    "stripped key algo${sk.publicKey.algorithm} must be unprotected",
                    0, sk.s2KUsage
                )
            }
            return
        }

        // Old passphrase must no longer recover the plaintext (throw or garble).
        if (oldPass.isNotEmpty() && oldPass != newPass) {
            val enc2 = svc.encrypt(pt, listOf(pubRing))
            val failedToRecover = try {
                val r = svc.decrypt(enc2, listOf(changed), passphrase = oldPass)
                !r.data.contentEquals(pt)
            } catch (_: Exception) {
                true
            }
            assertTrue("old passphrase must not recover plaintext (${algo.shortName})", failedToRecover)
        }
    }

    // ── Re-key (old set -> new set) across every format ──────────────────

    @Test fun `v4 RSA re-keys`() =
        changeAndProve(KeyAlgorithm.RSA_2048, "old-pw", "new-pw")

    @Test fun `v4 Ed25519 re-keys`() =
        changeAndProve(KeyAlgorithm.ED25519_CV25519, "old-pw", "new-pw")

    @Test fun `v6 Ed25519 re-keys`() =
        changeAndProve(KeyAlgorithm.V6_ED25519, "old-pw", "new-pw")

    @Test fun `composite 768 v6 re-keys`() =
        changeAndProve(KeyAlgorithm.MLKEM768_X25519_V6, "old-pw", "new-pw")

    @Test fun `composite 768 LibrePGP re-keys`() =
        changeAndProve(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, "old-pw", "new-pw")

    @Test fun `composite 1024 v6 re-keys`() =
        changeAndProve(KeyAlgorithm.MLKEM1024_X448_V6, "old-pw", "new-pw")

    @Test fun `composite 1024 LibrePGP re-keys`() =
        changeAndProve(KeyAlgorithm.MLKEM1024_X448_LIBREPGP, "old-pw", "new-pw")

    // ── Empty directions ────────────────────────────────────────────────

    @Test fun `v6 add protection to an unprotected key`() =
        changeAndProve(KeyAlgorithm.V6_ED25519, "", "set-pw")

    @Test fun `v6 strip protection`() =
        changeAndProve(KeyAlgorithm.V6_ED25519, "had-pw", "")

    @Test fun `composite 768 v6 add protection`() =
        changeAndProve(KeyAlgorithm.MLKEM768_X25519_V6, "", "set-pw")

    @Test fun `composite 768 v6 strip protection`() =
        changeAndProve(KeyAlgorithm.MLKEM768_X25519_V6, "had-pw", "")

    @Test fun `v4 Ed25519 strip protection`() =
        changeAndProve(KeyAlgorithm.ED25519_CV25519, "had-pw", "")

    @Test fun `composite 768 LibrePGP strip protection`() =
        changeAndProve(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, "had-pw", "")

    @Test fun `composite 1024 v6 strip protection`() =
        changeAndProve(KeyAlgorithm.MLKEM1024_X448_V6, "had-pw", "")
}
