// AutocryptPeerEntity.kt
// PGPony Android — 4.0.0 Phase 4 (Autocrypt)
//
// Per-peer Autocrypt state, populated via the OpenPGP API's
// ACTION_UPDATE_AUTOCRYPT_PEER (email clients parse Autocrypt/-Gossip
// headers and hand the parsed update to the provider). Drives the
// encryption RECOMMENDATION returned by ACTION_QUERY_AUTOCRYPT_STATUS —
// the "available / mutual / discourage" hint Thunderbird & co. show in
// the composer.
//
// Fields track the Autocrypt Level 1 peer state model:
//   • lastSeen             — newest message effective date seen from peer
//   • autocryptTimestamp   — effective date of the newest message that
//                            carried an Autocrypt header with a key
//   • autocryptKeyFingerprint — the imported key from that header
//   • isMutual             — that header's prefer-encrypt=mutual
//   • gossip*              — the lower-priority Autocrypt-Gossip key
//
// The key MATERIAL itself lives in the normal keyring (imported on
// update, resolved by email at encrypt time); this table stores only the
// per-peer timestamps + the fingerprint pointer + the mutual flag.

package com.pgpony.android.data

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query

@Entity(tableName = "autocrypt_peers")
data class AutocryptPeerEntity(
    /** Peer email address, lowercased. */
    @PrimaryKey val identifier: String,

    /** Newest message effective date seen from this peer (epoch ms). */
    val lastSeen: Long = 0,

    /** Effective date of the newest Autocrypt-header-with-key (epoch ms). */
    val autocryptTimestamp: Long = 0,

    /** Fingerprint of the imported Autocrypt key, or null if none. */
    val autocryptKeyFingerprint: String? = null,

    /** The Autocrypt header's prefer-encrypt=mutual flag. */
    val isMutual: Boolean = false,

    /** Effective date of the newest Autocrypt-Gossip key (epoch ms). */
    val gossipTimestamp: Long = 0,

    /** Fingerprint of the imported gossip key, or null if none. */
    val gossipKeyFingerprint: String? = null
)

@Dao
interface AutocryptPeerDao {
    @Query("SELECT * FROM autocrypt_peers WHERE identifier = :id LIMIT 1")
    suspend fun get(id: String): AutocryptPeerEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(peer: AutocryptPeerEntity)

    @Query("SELECT * FROM autocrypt_peers ORDER BY lastSeen DESC")
    suspend fun getAll(): List<AutocryptPeerEntity>

    @Query("DELETE FROM autocrypt_peers WHERE identifier = :id")
    suspend fun delete(id: String)

    @Query("DELETE FROM autocrypt_peers")
    suspend fun clear()
}
