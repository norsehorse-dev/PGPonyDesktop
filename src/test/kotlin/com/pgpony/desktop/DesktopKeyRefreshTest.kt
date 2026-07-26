// DesktopKeyRefreshTest.kt
// D4 validation, pipeline half: processFetchedArmored exercises the full Android refresh
// sequence (mandatory fingerprint verification → merge → revocation scan → stamp) against a
// real Room DB with locally-manufactured "keyserver responses" — no transport, so the suite
// stays offline and deterministic. Transport lives in NetworkLiveTest (gated -DrunNetwork).

package com.pgpony.desktop

import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.crypto.KeyExpirationService
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.crypto.RevocationService
import com.pgpony.android.data.PGPDatabase
import com.pgpony.android.data.RevocationReason
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopKeyRefreshTest {

    private val crypto = PGPCryptoService.shared

    private fun temp(): Triple<PGPDatabase, DesktopKeyRepository, Path> {
        val dir = Files.createTempDirectory("pgpony-refresh-test")
        val db = Db.open(dir.resolve("pgpony.db"))
        return Triple(db, DesktopKeyRepository(db, KeyMaterialStore(dir.resolve("keys"))), dir)
    }

    private fun generate(email: String) = crypto.generateKeyPair(
        name = "Refresh Test", email = email,
        algorithm = KeyAlgorithm.ED25519_CV25519, passphrase = "test-passphrase"
    )

    @Test
    fun identicalServerCopyIsUpToDateAndStampsTheAttempt() = runBlocking {
        val (db, repo, _) = temp()
        val refresh = DesktopKeyRefresh(repo)
        val gen = generate("uptodate@pgpony.app")
        repo.importArmoredKeyDetailed(gen.armoredPublicKey)
        val row = repo.byFingerprint(gen.fingerprint)!!
        assertNull(row.lastCheckedAt)

        // The "server" returns exactly what we hold.
        val served = repo.exportArmoredPublicKey(gen.fingerprint)!!
        val result = refresh.processFetchedArmored(row, served)

        val upToDate = result as? KeyRefreshResult.UpToDate ?: error("got $result")
        assertNotNull(upToDate.entity.lastCheckedAt, "attempt stamped (KS1 precedent)")
        db.close()
    }

    @Test
    fun mismatchedFingerprintChangesNothing() = runBlocking {
        val (db, repo, _) = temp()
        val refresh = DesktopKeyRefresh(repo)
        val mine = generate("mine@pgpony.app")
        val other = generate("other@pgpony.app")
        repo.importArmoredKeyDetailed(mine.armoredPublicKey)
        val row = repo.byFingerprint(mine.fingerprint)!!
        val armorBefore = repo.exportArmoredPublicKey(mine.fingerprint)

        // A poisoned/confused server returns a DIFFERENT key for our fingerprint.
        val result = refresh.processFetchedArmored(row, other.armoredPublicKey)

        val mismatch = result as? KeyRefreshResult.FingerprintMismatch ?: error("got $result")
        assertEquals(armorBefore, repo.exportArmoredPublicKey(mine.fingerprint), "material untouched")
        assertNotNull(mismatch.entity.lastCheckedAt, "attempt still stamped")
        db.close()
    }

    @Test
    fun upstreamRevocationAppliesFlagAndReason() = runBlocking {
        val (db, repo, _) = temp()
        val refresh = DesktopKeyRefresh(repo)
        val gen = generate("revoked-upstream@pgpony.app")
        // Local row holds the PUBLIC half only — like a correspondent's key.
        repo.importArmoredKeyDetailed(gen.armoredPublicKey)

        // Manufacture the upstream copy: the owner revoked (COMPROMISED) and republished.
        val parsed = crypto.importArmoredKey(gen.armoredPrivateKey)
        val cert = RevocationService.shared.generateRevocationCertificate(
            secretKeyRing = parsed.secretKeyRing!!,
            reason = RevocationReason.COMPROMISED,
            comment = "test revocation",
            passphrase = "test-passphrase"
        )
        val revokedRing = RevocationService.shared.applyRevocation(parsed.publicKeyRing!!, cert)
        val servedArmor = RevocationService.shared.armorPublicKeyRing(revokedRing)

        val row = repo.byFingerprint(gen.fingerprint)!!
        assertTrue(!row.isRevoked)
        val result = refresh.processFetchedArmored(row, servedArmor)

        val revoked = result as? KeyRefreshResult.RevokedUpstream ?: error("got $result")
        assertTrue(revoked.alsoMerged, "revocation signature is new material")
        val after = repo.byFingerprint(gen.fingerprint)!!
        assertTrue(after.isRevoked)
        assertEquals(RevocationReason.COMPROMISED, after.revocationReason, "reason read from the sig")
        assertNotNull(after.revokedAt)
        assertNotNull(after.lastCheckedAt)

        // Idempotent: refreshing the already-revoked row against the same copy is UpToDate —
        // and the local stamps survive (a locally revoked key keeps its own reason).
        val again = refresh.processFetchedArmored(after, servedArmor)
        assertTrue(again is KeyRefreshResult.UpToDate, "got $again")
        assertEquals(RevocationReason.COMPROMISED, repo.byFingerprint(gen.fingerprint)!!.revocationReason)
        db.close()
    }

    @Test
    fun upstreamExpirationExtensionMergesAndRestamps() = runBlocking {
        val (db, repo, _) = temp()
        val refresh = DesktopKeyRefresh(repo)
        val gen = generate("extended@pgpony.app")
        repo.importArmoredKeyDetailed(gen.armoredPublicKey)
        assertNull(repo.byFingerprint(gen.fingerprint)!!.expiresAt, "generated with no expiry")

        // The owner set an expiration and republished — re-sign locally to fake the fetch.
        val parsed = crypto.importArmoredKey(gen.armoredPrivateKey)
        val newExpiry = Instant.now().plus(365, ChronoUnit.DAYS).epochSecond
        val updated = KeyExpirationService.shared.setExpirationSoftware(
            secretRing = parsed.secretKeyRing!!,
            publicRing = parsed.publicKeyRing!!,
            expiresAtEpochSeconds = newExpiry,
            passphrase = "test-passphrase"
        )
        val servedArmor = crypto.exportArmoredPublicKey(updated.publicRing)

        val row = repo.byFingerprint(gen.fingerprint)!!
        val result = refresh.processFetchedArmored(row, servedArmor)

        assertTrue(result is KeyRefreshResult.Merged, "got $result")
        val after = repo.byFingerprint(gen.fingerprint)!!
        assertNotNull(after.expiresAt, "merge recomputed expiry from the newest self-sig")
        // Within a day of the requested moment (self-sig granularity is seconds).
        assertTrue(
            Math.abs(after.expiresAt!! - newExpiry * 1000L) < 24 * 60 * 60 * 1000L,
            "expiresAt=${after.expiresAt} vs requested ${newExpiry * 1000L}"
        )
        db.close()
    }
}
