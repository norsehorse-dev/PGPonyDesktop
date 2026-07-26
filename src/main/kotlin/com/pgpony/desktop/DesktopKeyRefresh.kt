// DesktopKeyRefresh.kt
// PGPony Desktop — D4: the keyserver refresh pipeline. Mirror of the Android
// KeyRefreshService (data/KeyRefreshService.kt, Gradle-excluded: imports the Android
// KeyRepository), rebuilt on DesktopKeyRepository with the same five steps and the same
// result vocabulary:
//   fetch → mandatory fingerprint verification → merge (trust/notes/secrets/card backing
//   preserved; keyservers only return public material, so secrets are safe by construction)
//   → primary-key revocation scan → stamp lastCheckedAt on the attempt.
// One shape difference, deliberate: Android 4.0.x's detail screen refreshes against
// keys.openpgp.org and leaves multi-server fetching to the Phase 5/7 background worker.
// Desktop ships the directory from day one, so [refreshAcrossDirectory] IS the entry point —
// it fetches from every lookup-enabled server (the worker's per-copy pipeline), re-reading
// the row between servers so each merge builds on the last and a revocation published on ANY
// server propagates. There is no single-server refresh entry to keep the class dead-code-free
// (PLANNING_4_1_0 §12 discipline).
//
// D11b — KeyRefreshResult.Failed.detail is shown to the user verbatim by the detail screen
// and the status line, so the detail strings here are keys. The server LABEL inside them is
// an argument, and even the "label: detail" glue is a key, because French puts a space
// before the colon.

package com.pgpony.desktop

import com.pgpony.android.PGPonyApp
import com.pgpony.android.crypto.PGPCryptoService
import com.pgpony.android.data.PGPKeyEntity
import com.pgpony.android.data.RevocationReason
import com.pgpony.android.keyserver.KeyServerDirectory
import com.pgpony.android.keyserver.MultiKeyServerService
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import java.util.prefs.Preferences

/**
 * Outcome of one refresh attempt — the Android KeyRefreshResult cases, verbatim, so the two
 * UIs report in the same vocabulary. RevokedUpstream wins over Merged when both happened.
 */
sealed class KeyRefreshResult {
    /** Fetched material is byte-identical to what's stored (on every server that had it). */
    data class UpToDate(val entity: PGPKeyEntity) : KeyRefreshResult()

    /** Newer material was merged into the stored row. */
    data class Merged(val entity: PGPKeyEntity) : KeyRefreshResult()

    /** A keyserver copy carries a key-revocation signature; the revocation has been applied.
     *  [alsoMerged] reports whether material changed too. */
    data class RevokedUpstream(val entity: PGPKeyEntity, val alsoMerged: Boolean) : KeyRefreshResult()

    /** Every enabled server answered and none has this fingerprint. */
    data class NotFound(val entity: PGPKeyEntity) : KeyRefreshResult()

    /** A server returned key material whose computed fingerprint does not match this key.
     *  Nothing was changed. */
    data class FingerprintMismatch(val entity: PGPKeyEntity) : KeyRefreshResult()

    /** Transport or parse failure (and no server produced a clean result). lastCheckedAt is
     *  still stamped — the attempt is recorded (KS1 precedent). */
    data class Failed(val entity: PGPKeyEntity, val detail: String) : KeyRefreshResult()

    /** The fingerprint has no keyring row. */
    object KeyMissing : KeyRefreshResult()
}

class DesktopKeyRefresh(
    private val repo: DesktopKeyRepository,
    private val crypto: PGPCryptoService = PGPCryptoService.shared
) {

    /**
     * Refresh [fingerprint] from every lookup-enabled server in the directory. Never throws —
     * every failure mode maps to a [KeyRefreshResult]. Result precedence across servers:
     * RevokedUpstream > Merged > UpToDate > FingerprintMismatch > Failed > NotFound
     * (transport failure beats NotFound so "no network" never reads as "not published").
     */
    suspend fun refreshAcrossDirectory(fingerprint: String): KeyRefreshResult {
        var current = repo.byFingerprint(fingerprint) ?: return KeyRefreshResult.KeyMissing
        val servers = runCatching {
            KeyServerDirectory.get(PGPonyApp.instance).readOnce()
        }.getOrDefault(KeyServerDirectory.DEFAULTS)
            .filter { it.lookupEnabled }
        if (servers.isEmpty()) {
            repo.markKeyServerChecked(current.fingerprint)
            return KeyRefreshResult.Failed(reload(current), tr("d_refresh_err_no_servers"))
        }

        var cleanHit = false
        var mergedAny = false
        var revokedAny = false
        var mismatch = false
        var firstFailure: String? = null

        for (server in servers) {
            val armored = try {
                MultiKeyServerService.shared.fetchByFingerprint(server, current.fingerprint)
            } catch (e: Exception) {
                if (firstFailure == null) {
                    firstFailure =
                        tr("d_refresh_err_server_prefix", server.label, e.message ?: e.javaClass.simpleName)
                }
                continue
            }
            if (armored.isNullOrBlank()) continue // this server answered: not published there
            when (val r = processFetchedArmored(current, armored)) {
                is KeyRefreshResult.UpToDate -> cleanHit = true
                is KeyRefreshResult.Merged -> { cleanHit = true; mergedAny = true }
                is KeyRefreshResult.RevokedUpstream -> {
                    cleanHit = true; revokedAny = true
                    mergedAny = mergedAny || r.alsoMerged
                }
                is KeyRefreshResult.FingerprintMismatch -> mismatch = true
                is KeyRefreshResult.Failed -> if (firstFailure == null) {
                    firstFailure = tr("d_refresh_err_server_prefix", server.label, r.detail)
                }
                else -> Unit
            }
            // Re-read between servers so each merge builds on the last (the worker pattern).
            current = repo.byFingerprint(fingerprint) ?: current
        }

        repo.markKeyServerChecked(fingerprint) // stamp even the all-miss / all-fail attempt
        val final = reload(current)
        return when {
            revokedAny -> KeyRefreshResult.RevokedUpstream(final, alsoMerged = mergedAny)
            mergedAny -> KeyRefreshResult.Merged(final)
            cleanHit -> KeyRefreshResult.UpToDate(final)
            mismatch -> KeyRefreshResult.FingerprintMismatch(final)
            firstFailure != null -> KeyRefreshResult.Failed(final, firstFailure)
            else -> KeyRefreshResult.NotFound(final)
        }
    }

    /**
     * Process an ALREADY-FETCHED armored copy through the verify → merge → revocation-scan →
     * stamp pipeline (Android's processFetchedArmored, on the desktop repo). Public so tests
     * exercise the whole pipeline without transport.
     */
    suspend fun processFetchedArmored(
        existing: PGPKeyEntity,
        armored: String
    ): KeyRefreshResult {
        // Guard the revocation scan with the PRE-merge state: the desktop merge path itself
        // flags isRevoked off the joined ring, and a locally revoked key must keep its own
        // revokedAt / reason regardless of what the keyserver says.
        val wasRevokedLocally = existing.isRevoked

        // 2. Parse + mandatory fingerprint verification — never trust the response blindly.
        val parsed = try {
            crypto.importArmoredKey(armored)
        } catch (e: Exception) {
            repo.markKeyServerChecked(existing.fingerprint)
            return KeyRefreshResult.Failed(
                reload(existing),
                tr("d_refresh_err_parse", e.message.orEmpty())
            )
        }
        val fetchedRing = parsed.publicKeyRing
        if (fetchedRing == null ||
            normalize(parsed.fingerprint) != normalize(existing.fingerprint)
        ) {
            repo.markKeyServerChecked(existing.fingerprint)
            return KeyRefreshResult.FingerprintMismatch(reload(existing))
        }

        // 3. Merge (expiry recomputed from the merged primary inside the repo).
        val (merged, changed) = repo.mergeFetchedPublicMaterial(existing, fetchedRing)

        // 4. Revocation scan on the fetched primary.
        var revocationApplied = false
        if (!wasRevokedLocally) {
            val revSig = findKeyRevocationSignature(fetchedRing)
            if (revSig != null) {
                val reason = revocationReasonCode(revSig)?.let { code ->
                    RevocationReason.entries.firstOrNull { it.rfcCode == code }
                }
                repo.markRevokedFromUpstream(
                    fingerprint = merged.fingerprint,
                    revokedAtMs = revSig.creationTime?.time ?: System.currentTimeMillis(),
                    reason = reason
                )
                revocationApplied = true
            }
        }

        // 5. Stamp the attempt and report.
        repo.markKeyServerChecked(existing.fingerprint)
        val finalEntity = reload(merged)
        return when {
            revocationApplied -> KeyRefreshResult.RevokedUpstream(finalEntity, alsoMerged = changed)
            changed -> KeyRefreshResult.Merged(finalEntity)
            else -> KeyRefreshResult.UpToDate(finalEntity)
        }
    }

    // ── Internals (mirroring the Android service) ───────────────────────

    private suspend fun reload(entity: PGPKeyEntity): PGPKeyEntity =
        repo.byFingerprint(entity.fingerprint) ?: entity

    /** KeyDeduplicationService.normalize semantics (that service is excluded until its D2b
     *  port): lowercase, whitespace stripped. */
    private fun normalize(fingerprint: String): String =
        fingerprint.lowercase().filter { !it.isWhitespace() }

    /** First key-revocation signature (tag 2, type 0x20) on the fetched ring's primary. */
    private fun findKeyRevocationSignature(ring: PGPPublicKeyRing): PGPSignature? {
        val primary = ring.publicKey ?: return null
        val sigs = primary.getSignaturesOfType(PGPSignature.KEY_REVOCATION) ?: return null
        while (sigs.hasNext()) {
            (sigs.next() as? PGPSignature)?.let { return it }
        }
        return null
    }

    /** RFC 4880 §5.2.3.23 reason code (hashed preferred, unhashed fallback), or null. */
    private fun revocationReasonCode(sig: PGPSignature): Int? {
        val packet = sig.hashedSubPackets
            ?.getSubpacket(SignatureSubpacketTags.REVOCATION_REASON)
            ?: sig.unhashedSubPackets
                ?.getSubpacket(SignatureSubpacketTags.REVOCATION_REASON)
        return (packet as? org.bouncycastle.bcpg.sig.RevocationReason)
            ?.revocationReason?.toInt()
    }
}

/**
 * Desktop-only network toggles that are NOT part of a twin (twins stay verbatim). Currently
 * just the auto-refresh switch for the DesktopState ticker.
 */
object DesktopNetworkPrefs {
    private const val KEY_AUTO_REFRESH = "auto_refresh_keys"

    /** Test hook — same pattern as DesktopProxyPrefs. */
    internal var prefsOverride: Preferences? = null

    private fun prefs(): Preferences =
        prefsOverride ?: Preferences.userRoot().node("app/pgpony/desktop")

    fun autoRefresh(): Boolean = prefs().getBoolean(KEY_AUTO_REFRESH, true)
    fun setAutoRefresh(enabled: Boolean) = prefs().putBoolean(KEY_AUTO_REFRESH, enabled)
}
