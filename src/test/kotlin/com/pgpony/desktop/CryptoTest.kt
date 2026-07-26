// CryptoTest.kt
// D3a validation: the four text surfaces on the vendored engine — signed encrypt→decrypt with
// verification, symmetric round-trip, clear-sign verify (+ tamper detection), detached sign
// verify (+ wrong-content detection), unknown-signer classification.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.SigningService
import com.pgpony.android.crypto.VerificationResult
import com.pgpony.android.crypto.VerifyService
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CryptoTest {

    private fun repo(): Pair<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository> {
        val dir = Files.createTempDirectory("pgpony-crypto-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    private suspend fun DesktopKeyRepository.gen(name: String, email: String) =
        generateKey(name, email, KeyAlgorithm.ED25519_CV25519, "test-passphrase")

    @Test
    fun signedEncryptDecryptRoundTripWithVerification() = runBlocking {
        val (db, repo) = repo()
        val signer = repo.gen("Signer", "signer@pgpony.app")
        val recipient = repo.gen("Recipient", "recipient@pgpony.app")

        val armored = repo.encryptText(
            "the pact stands",
            recipientRings = listOf(repo.loadPublicKeyRing(recipient.fingerprint)!!),
            signerRing = repo.loadSecretKeyRing(signer.fingerprint),
            signerPassphrase = "test-passphrase"
        )
        assertTrue(armored.contains("BEGIN PGP MESSAGE"))

        val result = repo.decryptText(armored, "test-passphrase")
        assertEquals("the pact stands", result.plaintext)
        assertTrue(result.signatureVerified, "signature should verify against the held signer key")
        assertNotNull(result.signerKeyID)
        db.close()
    }

    @Test
    fun symmetricRoundTrip() = runBlocking {
        val (db, repo) = repo()
        val armored = repo.encryptTextSymmetric("shared-secret message", "horse-battery-staple")
        val result = repo.decryptText(armored, "horse-battery-staple")
        assertEquals("shared-secret message", result.plaintext)
        db.close()
    }

    @Test
    fun clearSignVerifiesAndTamperFails() = runBlocking {
        val (db, repo) = repo()
        val signer = repo.gen("Clear Signer", "clear@pgpony.app")
        val ring = repo.loadSecretKeyRing(signer.fingerprint)!!
        val pubRings = listOf(repo.loadPublicKeyRing(signer.fingerprint)!!)

        val clearSigned = SigningService.shared.signClear("statement of record", ring, "test-passphrase")
        val ok = VerifyService.shared.verifyClearSigned(clearSigned, pubRings)
        assertTrue(ok is VerificationResult.Verified, "clean clear-signed should verify, got $ok")
        assertEquals("statement of record", (ok as VerificationResult.Verified).signedContent?.trim())

        val tampered = clearSigned.replace("statement of record", "statement of rewrite")
        val bad = VerifyService.shared.verifyClearSigned(tampered, pubRings)
        assertTrue(bad is VerificationResult.Invalid, "tampered content must be INVALID, got $bad")
        db.close()
    }

    @Test
    fun detachedSignVerifiesAndWrongContentFails() = runBlocking {
        val (db, repo) = repo()
        val signer = repo.gen("Detached Signer", "detached@pgpony.app")
        val ring = repo.loadSecretKeyRing(signer.fingerprint)!!
        val pubRings = listOf(repo.loadPublicKeyRing(signer.fingerprint)!!)
        val content = "artifact-bytes-v1".toByteArray(Charsets.UTF_8)

        val sig = SigningService.shared.signDetached(content, ring, "test-passphrase")
            .toString(Charsets.UTF_8)
        val ok = VerifyService.shared.verifyDetached(sig, content, pubRings)
        assertTrue(ok is VerificationResult.Verified, "detached should verify, got $ok")

        val bad = VerifyService.shared.verifyDetached(
            sig, "artifact-bytes-v2".toByteArray(Charsets.UTF_8), pubRings
        )
        assertTrue(bad is VerificationResult.Invalid, "wrong content must be INVALID, got $bad")
        db.close()
    }

    // ── Field-report reproduction (desktop→phone "not signed") ──────────
    // Theory: messages TO a composite (or v6/SEIPDv2) recipient decrypt through a path that
    // drops the signature state. These tests sign-encrypt to each recipient type and assert the
    // signature survives OUR OWN decrypt — the same engine the phone runs.

    private suspend fun signedRoundTripTo(recipientAlgo: KeyAlgorithm, label: String) {
        val (db, repo) = repo()
        val signer = repo.gen("RT Signer", "rtsigner@pgpony.app")
        val recipient = repo.generateKey("RT $label", "rt-$label@pgpony.app", recipientAlgo, "test-passphrase")

        val armored = repo.encryptText(
            "signed to $label",
            recipientRings = listOf(repo.loadPublicKeyRing(recipient.fingerprint)!!),
            signerRing = repo.loadSecretKeyRing(signer.fingerprint)
                ?: error("signer ring failed to load"),
            signerPassphrase = "test-passphrase"
        )
        val result = repo.decryptText(armored, "test-passphrase")
        assertEquals("signed to $label", result.plaintext, "[$label] plaintext")
        assertTrue(result.hasSignature, "[$label] decrypt must surface the signature packets")
        assertTrue(result.signatureVerified, "[$label] signature must verify against the held signer")
        db.close()
    }

    @Test
    fun signedEncryptToV6RecipientVerifies() = runBlocking {
        signedRoundTripTo(KeyAlgorithm.V6_ED25519, "v6")
    }

    @Test
    fun signedEncryptToCompositeIetfRecipientVerifies() = runBlocking {
        signedRoundTripTo(KeyAlgorithm.MLKEM768_X25519_V6, "mlkem-ietf")
    }

    @Test
    fun signedEncryptToCompositeLibrePgpRecipientVerifies() = runBlocking {
        signedRoundTripTo(KeyAlgorithm.MLKEM768_X25519_LIBREPGP, "mlkem-librepgp")
    }

    @Test
    fun unknownSignerClassifiedWhenKeyAbsent() = runBlocking {
        val (dbA, repoA) = repo()
        val signer = repoA.gen("Stranger", "stranger@pgpony.app")
        val clearSigned = SigningService.shared.signClear(
            "hello from a stranger", repoA.loadSecretKeyRing(signer.fingerprint)!!, "test-passphrase"
        )

        val (dbB, repoB) = repo()
        val other = repoB.gen("Local", "local@pgpony.app")  // keyring without the stranger
        val rings = listOf(repoB.loadPublicKeyRing(other.fingerprint)!!)
        val result = VerifyService.shared.verifyClearSigned(clearSigned, rings)
        assertTrue(result is VerificationResult.UnknownSigner, "expected UnknownSigner, got $result")
        dbA.close(); dbB.close()
    }
}
