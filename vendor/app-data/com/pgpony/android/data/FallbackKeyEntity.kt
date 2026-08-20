// FallbackKeyEntity.kt
// PGPony Android - 4.2.0 RC3 workstream N (issue #34)
//
// Two small per-key configuration tables, added together in
// MIGRATION_7_8 (see RoomMigrations.kt):
//
//   fallback_keys - the one-to-many decryption-fallback list. A row's
//   PRESENCE means "enabled": fallbacks are off by default (issue #34's
//   rule), so an unconfigured key simply has no rows. position is the
//   user's chosen trial order. The decrypt cascade (EncryptDecryptViewModel)
//   tries the primary ring alone, then each enabled fallback ring in
//   position order, then the pre-#34 all-keys list as the final safety
//   net - so unconfigured users keep exactly the old behavior.
//
//   signing_defaults - the three backwards-compatible signing pickers,
//   one row per private key, all nullable: null means "sign as myself",
//   which is the pre-#34 behavior and the issue's specified default
//   ("each defaulting to the key whose Key Detail view is open"). The
//   row consulted at sign time belongs to the key that would OTHERWISE
//   sign (the resolved signingKey), and the substitution only applies
//   when the substitute is a software key pair - swapping a card key in
//   silently would break the UI's already-made card-vs-software routing.
//
// New table over columns on pgp_keys per the 8 August leaning: the
// fallback list is one-to-many and ordered, which is exactly what a
// table models and flat columns don't.

package com.pgpony.android.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Entity(tableName = "fallback_keys", primaryKeys = ["primaryFingerprint", "fallbackFingerprint"])
data class FallbackKeyEntity(
    val primaryFingerprint: String,
    val fallbackFingerprint: String,
    val position: Int
)

@Entity(tableName = "signing_defaults")
data class SigningDefaultsEntity(
    @androidx.room.PrimaryKey val fingerprint: String,
    /** Signer when encrypting and EVERY recipient is PQC/composite. */
    val pqcSignerFingerprint: String? = null,
    /** Signer when encrypting and ANY recipient is classical. */
    val classicalSignerFingerprint: String? = null,
    /** Signer for sign-only (no encryption). */
    val signOnlySignerFingerprint: String? = null
)

@Dao
interface FallbackKeyDao {
    @Query("SELECT * FROM fallback_keys WHERE primaryFingerprint = :primary ORDER BY position ASC")
    suspend fun fallbacksFor(primary: String): List<FallbackKeyEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(rows: List<FallbackKeyEntity>)

    @Query("DELETE FROM fallback_keys WHERE primaryFingerprint = :primary")
    suspend fun clearFor(primary: String)

    /** Key deletion cleanup: the key can appear on either side. */
    @Query("DELETE FROM fallback_keys WHERE primaryFingerprint = :fp OR fallbackFingerprint = :fp")
    suspend fun deleteAllReferencing(fp: String)
}

@Dao
interface SigningDefaultsDao {
    @Query("SELECT * FROM signing_defaults WHERE fingerprint = :fp")
    suspend fun forKey(fp: String): SigningDefaultsEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(row: SigningDefaultsEntity)

    @Query("DELETE FROM signing_defaults WHERE fingerprint = :fp")
    suspend fun deleteFor(fp: String)
}
