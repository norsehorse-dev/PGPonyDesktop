// MutationsTest.kt
// D2c validation: trust/notes/default round-trips, the revocation flow (cert generated, ring
// carries the revocation self-sig, entity stamped), expiration editing via the vendored
// KeyExpirationService, and the merge-new-material import path (a revoked re-import folds into
// the stored ring and flips isRevoked).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.data.TrustLevel
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.math.abs
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MutationsTest {

    private fun repo(): Pair<com.pgpony.android.data.PGPDatabase, DesktopKeyRepository> {
        val dir = Files.createTempDirectory("pgpony-mut-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return db to DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys")))
    }

    private suspend fun DesktopKeyRepository.gen(name: String, email: String) =
        generateKey(name, email, KeyAlgorithm.ED25519_CV25519, "test-passphrase")

    @Test
    fun trustNotesAndDefaultRoundTrip() = runBlocking {
        val (db, repo) = repo()
        val a = repo.gen("Trust A", "a@pgpony.app")
        val b = repo.gen("Trust B", "b@pgpony.app")

        repo.updateTrustLevel(a.fingerprint, TrustLevel.VERIFIED)
        assertEquals(TrustLevel.VERIFIED, repo.byFingerprint(a.fingerprint)!!.trustLevel)

        repo.updateNotes(a.fingerprint, "met at the conference")
        assertEquals("met at the conference", repo.byFingerprint(a.fingerprint)!!.notes)
        repo.updateNotes(a.fingerprint, null)
        assertNull(repo.byFingerprint(a.fingerprint)!!.notes)

        repo.setDefaultKey(a.fingerprint)
        assertTrue(repo.byFingerprint(a.fingerprint)!!.isDefault)
        repo.setDefaultKey(b.fingerprint)
        assertFalse(repo.byFingerprint(a.fingerprint)!!.isDefault, "old default cleared")
        assertTrue(repo.byFingerprint(b.fingerprint)!!.isDefault)
        db.close()
    }

    @Test
    fun revocationFlowStampsEntityAndRing() = runBlocking {
        val (db, repo) = repo()
        val key = repo.gen("Revoke Me", "revoke@pgpony.app")

        val cert = repo.applyRevocation(
            key.fingerprint, RevocationReason.SUPERSEDED, comment = "moved on", passphrase = "test-passphrase"
        )
        assertTrue(cert.contains("BEGIN PGP"), "cert is armored")

        val row = repo.byFingerprint(key.fingerprint)!!
        assertTrue(row.isRevoked)
        assertEquals(RevocationReason.SUPERSEDED, row.revocationReason)
        assertNotNull(row.revokedAt)
        assertEquals(cert, repo.exportRevocationCertificate(key.fingerprint))

        val ring = repo.loadPublicKeyRing(key.fingerprint)
        assertNotNull(ring)
        assertTrue(ring.publicKey.hasRevocation(), "primary carries the revocation self-sig")
        db.close()
    }

    @Test
    fun expirationEditAndRemoval() = runBlocking {
        val (db, repo) = repo()
        val key = repo.gen("Expire Me", "expire@pgpony.app")
        assertNull(repo.byFingerprint(key.fingerprint)!!.expiresAt, "generated without expiry")

        val oneYear = System.currentTimeMillis() / 1000 + 365L * 24 * 3600
        repo.setKeyExpirationSoftware(key.fingerprint, oneYear, "test-passphrase")
        val expires = repo.byFingerprint(key.fingerprint)!!.expiresAt
        assertNotNull(expires)
        assertTrue(abs(expires - oneYear * 1000) < 1000, "entity stamps the requested expiry")

        repo.setKeyExpirationSoftware(key.fingerprint, null, "test-passphrase")
        assertNull(repo.byFingerprint(key.fingerprint)!!.expiresAt, "expiry removable")
        db.close()
    }

    @Test
    fun mergeNewMaterialFoldsRevocationIntoStoredRing() = runBlocking {
        val (dbA, repoA) = repo()
        val key = repoA.gen("Merge Source", "merge@pgpony.app")
        val cleanPublic = repoA.exportArmoredPublicKey(key.fingerprint)!!
        repoA.applyRevocation(key.fingerprint, RevocationReason.COMPROMISED, null, "test-passphrase")
        val revokedPublic = repoA.exportArmoredPublicKey(key.fingerprint)!!

        val (dbB, repoB) = repo()
        assertEquals(ImportResolution.INSERTED, repoB.importArmoredKeyDetailed(cleanPublic))
        assertFalse(repoB.byFingerprint(key.fingerprint)!!.isRevoked)

        assertEquals(
            ImportResolution.MERGED_NEW_MATERIAL,
            repoB.importArmoredKeyDetailed(revokedPublic),
            "differing public material should merge, not skip"
        )
        val merged = repoB.byFingerprint(key.fingerprint)!!
        assertTrue(merged.isRevoked, "merge detected the revocation on the incoming material")
        assertTrue(repoB.loadPublicKeyRing(key.fingerprint)!!.publicKey.hasRevocation())

        assertEquals(
            ImportResolution.ALREADY_IN_KEYRING,
            repoB.importArmoredKeyDetailed(revokedPublic),
            "re-import of identical material reports already-in-keyring"
        )
        dbA.close(); dbB.close()
    }
}
