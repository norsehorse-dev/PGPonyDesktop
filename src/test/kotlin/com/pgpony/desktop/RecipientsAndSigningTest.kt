// RecipientsAndSigningTest.kt
// PGPony Desktop 3.0.0, stage 1: raw-octet key import (v4 algo-35, composite ML-DSA), the one
// recipient loader with its fail-closed rule, ML-DSA encrypt-and-sign through EncryptOps, the
// composite inline signature read back on decrypt, and the expired-key rule.

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.pqc.CompositeKeyGen
import com.pgpony.android.crypto.pqc.CompositeSigPacket
import com.pgpony.android.data.PGPDatabase
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RecipientsAndSigningTest {

    private val crypto = PGPCryptoService.shared

    @BeforeTest
    fun hookPrefs() {
        KeyUsePolicy.prefsOverride = MemoryPreferences()
    }

    @AfterTest
    fun unhookPrefs() {
        KeyUsePolicy.prefsOverride = null
    }

    private fun temp(): Pair<PGPDatabase, DesktopKeyRepository> {
        val dir = Files.createTempDirectory("pgpony-recipients-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    private fun v4Algo35Key(): CompositeKeyGen.V4Algo35Rings {
        val base = crypto.importKeyData(
            crypto.generateKeyPair("V4 Desk", "v4@pgpony.app", KeyAlgorithm.ED25519_CV25519, null).privateKeyData
        ).secretKeyRing!!
        return CompositeKeyGen.addV4Algo35SubkeyRings(base)
    }

    private fun armorPrivate(raw: ByteArray) =
        CompositeSigPacket.armor("-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----", raw)

    private fun armorPublic(raw: ByteArray) =
        CompositeSigPacket.armor("-----BEGIN PGP PUBLIC KEY BLOCK-----", "-----END PGP PUBLIC KEY BLOCK-----", raw)

    @Test
    fun v4Algo35KeyImportsWholeAndEncryptsPostQuantum() = runBlocking {
        val (db, repo) = temp()
        val rings = v4Algo35Key()
        assertEquals(ImportResolution.INSERTED, repo.importArmoredKeyDetailed(armorPublic(rings.publicRaw)))
        val fp = rings.primaryFingerprintHex.uppercase()
        val row = repo.byFingerprint(fp)
        assertNotNull(row)
        assertEquals(KeyAlgorithm.MLKEM768_X25519_V4, row.algorithm)

        // The algo-35 subkey survived storage: it is a recipient on its own channel.
        assertNotNull(repo.loadV4Algo35Recipient(fp), "algo-35 subkey kept")
        val loaded = repo.loadRecipients(listOf(fp))
        assertTrue(loaded.isComplete)
        assertEquals(1, loaded.v4Algo35.size)

        // Secret half upgrades the row; a message to the key decrypts through the raw path.
        assertEquals(ImportResolution.UPGRADED_TO_KEY_PAIR, repo.importArmoredKeyDetailed(armorPrivate(rings.secretRaw)))
        val ops = EncryptOps(repo)
        val plan = ops.plan(listOf(fp), signer = null, signerPassphrase = null)
        val armored = String(ops.encryptBytes(plan, "post-quantum hello".toByteArray(), null, armor = true))
        val result = repo.decryptText(armored, null)
        assertEquals("post-quantum hello", result.plaintext)

        // A refresh-style merge with a BouncyCastle copy (which cannot carry the algo-35 subkey)
        // must not drop it from storage.
        val bcCopy = repo.loadPublicKeyRing(fp)
        if (bcCopy != null) repo.mergeFetchedPublicMaterial(repo.byFingerprint(fp)!!, bcCopy)
        assertNotNull(repo.loadV4Algo35Recipient(fp), "algo-35 subkey survives a merge")
        db.close()
    }

    @Test
    fun compositeKeyImportsIntoAnotherKeyringAndSignsWhileEncrypting() = runBlocking {
        val (dbA, repoA) = temp()
        val (dbB, repoB) = temp()
        val signer = repoA.generateKey("ML Sender", "mlsender@pgpony.app", KeyAlgorithm.MLDSA65_ED25519_V6, null)
        val publicArmor = repoA.exportArmoredPublicKey(signer.fingerprint)!!

        // Before 3.0.0 this import failed on desktop: BouncyCastle rejects the algo-30 primary.
        assertEquals(ImportResolution.INSERTED, repoB.importArmoredKeyDetailed(publicArmor))
        val imported = repoB.byFingerprint(signer.fingerprint)
        assertNotNull(imported)
        assertEquals(KeyAlgorithm.MLDSA65_ED25519_V6, imported.algorithm)
        assertTrue(repoB.loadRecipients(listOf(signer.fingerprint)).isComplete, "reachable through its ML-KEM subkey")

        // Encrypt-and-sign with the ML-DSA key to itself (a v6 recipient: SEIPDv2, no prompt).
        val ops = EncryptOps(repoA)
        val plan = ops.plan(listOf(signer.fingerprint), signer, null)
        assertTrue(plan.signs)
        val armored = String(ops.encryptBytes(plan, "signed and sealed".toByteArray(), null, armor = true))
        val structured = MimeOps(repoA).decryptStructured(armored, null)
        assertEquals("signed and sealed", structured.body)
        val sig = structured.signature
        assertNotNull(sig)
        // Own key, trust never set: valid, but unconfirmed (Android 4.5.3 semantics).
        assertEquals(SignatureSummary.State.UNCONFIRMED, sig.state, "composite inline signature verified")
        dbA.close(); dbB.close()
    }

    @Test
    fun unknownRecipientStopsTheOperation() = runBlocking {
        val (db, repo) = temp()
        val g = crypto.generateKeyPair("Known", "known@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        repo.importArmoredKeyDetailed(g.armoredPublicKey)
        val e = assertFailsWith<RecipientLoadException> {
            repo.requireRecipients(listOf(g.fingerprint, "00".repeat(20)))
        }
        assertEquals(1, e.keys.size, "only the unusable one is named")
        db.close()
    }

    @Test
    fun expiredRecipientIsRefusedUnlessAllowed() = runBlocking {
        val (db, repo) = temp()
        val g = crypto.generateKeyPair("Old", "old@pgpony.app", KeyAlgorithm.ED25519_CV25519, null)
        repo.importArmoredKeyDetailed(g.armoredPublicKey)
        val row = repo.byFingerprint(g.fingerprint)!!
        db.keyDao().update(row.copy(expiresAt = System.currentTimeMillis() - 1000))
        val ops = EncryptOps(repo)
        assertFailsWith<ExpiredKeyException> { ops.plan(listOf(g.fingerprint), null, null) }
        KeyUsePolicy.setAllowExpiredKeys(true)
        ops.plan(listOf(g.fingerprint), null, null)
        db.close()
    }
}
