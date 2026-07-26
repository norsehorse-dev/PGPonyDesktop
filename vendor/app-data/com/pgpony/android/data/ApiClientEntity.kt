// ApiClientEntity.kt
// PGPony Android — 4.0.0 Succession Phase 1 (OpenPGP API provider)
//
// Per-package allow-list for OpenPGP API client apps (Thunderbird for
// Android, K-9 Mail, Password Store, Conversations, …). Mirrors
// OpenKeychain's authorization model, which client apps assume: a
// client is identified by its package name AND the SHA-256 of its
// signing certificate. The signature pin is what makes the allow-list
// meaningful — a sideloaded impostor with a stolen package name gets
// SIGNATURE_MISMATCH, not access.
//
// Rows are written exclusively by the first-use consent flow
// (ApiConsentActivity → ApiClientAuthorizer.grant) and deleted from
// the Settings → Connected apps screen. There is no default-allow
// path anywhere (see §5 of the 4.0.0 plan: "Signature-pinned client
// authorization, no default-allow, and a revocation UI are
// non-negotiable").

package com.pgpony.android.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query

// ── Entity ─────────────────────────────────────────────────────────────

@Entity(tableName = "allowed_api_clients")
data class ApiClientEntity(
    /** The client app's package name, e.g. "net.thunderbird.android". */
    @PrimaryKey
    val packageName: String,

    /**
     * Lowercase hex SHA-256 of the client's signing certificate
     * (first signer, `GET_SIGNING_CERTIFICATES`). Checked on every
     * provider call; a mismatch is treated as a different app.
     */
    val signatureSha256: String,

    /** When the user granted access (epoch ms). Shown in Settings. */
    val grantedAt: Long
)

// ── DAO ────────────────────────────────────────────────────────────────

@Dao
interface ApiClientDao {
    @Query("SELECT * FROM allowed_api_clients ORDER BY grantedAt DESC")
    suspend fun getAll(): List<ApiClientEntity>

    @Query("SELECT * FROM allowed_api_clients WHERE packageName = :packageName LIMIT 1")
    suspend fun getByPackage(packageName: String): ApiClientEntity?

    /**
     * REPLACE so re-consent after an app re-install (new signing key —
     * rare but real for debug↔release switches) simply overwrites the
     * stale pin once the user has explicitly re-approved.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(client: ApiClientEntity)

    @Query("DELETE FROM allowed_api_clients WHERE packageName = :packageName")
    suspend fun deleteByPackage(packageName: String)

    @Query("SELECT COUNT(*) FROM allowed_api_clients")
    suspend fun count(): Int
}
