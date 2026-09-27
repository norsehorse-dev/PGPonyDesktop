// DbUpgradeTest.kt
// PGPony Desktop 3.0.0: the full Room open-and-validate path for the schema 9 -> 12 upgrade,
// and for a 2.0.0 database going 7 -> 12 in one open. Issue #3 was exactly a database that a
// fresh install never exercises, so this test builds the OLD shape and lets Room upgrade it.
//
// How the old shape is made without the old build: create a current database through Db.open
// with one key and one allowed-app row in it, then hand-downgrade it with the raw driver by
// dropping what the later migrations add and setting user_version back. Reopening through
// Db.open runs the desktop migrations and Room's schema validation, which fails the open if
// any migration leaves a column or table different from the compiled entities.

package com.pgpony.desktop

import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import androidx.sqlite.execSQL
import com.pgpony.android.crypto.KeyAlgorithm
import com.pgpony.android.data.ApiClientEntity
import com.pgpony.android.data.PGPKeyEntity
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DbUpgradeTest {

    private val fp = "0123456789ABCDEF0123456789ABCDEF01234567"

    private fun seed(file: Path) {
        val db = Db.open(file)
        try {
            runBlocking {
                db.keyDao().insert(
                    PGPKeyEntity(
                        id = "upgrade-test",
                        fingerprint = fp,
                        userID = "Upgrade <upgrade@pgpony.app>",
                        userName = "Upgrade",
                        userEmail = "upgrade@pgpony.app",
                        algorithm = KeyAlgorithm.ED25519_CV25519,
                        isKeyPair = true,
                        createdAt = 1_700_000_000_000L
                    )
                )
            }
        } finally {
            db.close()
        }
    }

    private fun downgrade(file: Path, to: Int) {
        val c = BundledSQLiteDriver().open(file.toAbsolutePath().toString())
        try {
            c.execSQL("ALTER TABLE `allowed_api_clients` DROP COLUMN `sshKeyFingerprint`")
            c.execSQL("ALTER TABLE `allowed_api_clients` DROP COLUMN `scopes`")
            c.execSQL("ALTER TABLE `pgp_keys` DROP COLUMN `lastLocalEditAt`")
            c.execSQL("ALTER TABLE `pgp_keys` DROP COLUMN `autocryptImportedAt`")
            if (to == 7) {
                c.execSQL("ALTER TABLE `pgp_keys` DROP COLUMN `lastBackedUpAt`")
                c.execSQL("ALTER TABLE `pgp_keys` DROP COLUMN `deletedAt`")
                c.execSQL("DROP TABLE `signing_defaults`")
                c.execSQL("DROP TABLE `fallback_keys`")
            }
            c.execSQL("PRAGMA user_version = $to")
        } finally {
            c.close()
        }
    }

    private fun upgradeFrom(version: Int) {
        val file = Files.createTempDirectory("pgpony-upgrade-$version").resolve("pgpony.db")
        seed(file)
        downgrade(file, version)

        val db = Db.open(file)
        try {
            runBlocking {
                val keys = db.keyDao().getAllKeys()
                assertEquals(1, keys.size, "the key survives the $version -> 12 upgrade")
                val k = keys.single()
                assertEquals(fp, k.fingerprint)
                assertEquals("Upgrade <upgrade@pgpony.app>", k.userID)
                assertNull(k.lastLocalEditAt, "no edit is known to be unpublished after upgrade")
                assertNull(k.autocryptImportedAt, "a key pair is never Autocrypt-origin")
                assertEquals(0, db.apiClientDao().count())
            }
        } finally {
            db.close()
        }
    }

    @Test
    fun v9DatabaseFrom2_1UpgradesTo12() = upgradeFrom(9)

    @Test
    fun v7DatabaseFrom2_0UpgradesTo12() = upgradeFrom(7)

    @Test
    fun scopesDefaultsToOpenPgpOnUpgradedRows() {
        val file = Files.createTempDirectory("pgpony-upgrade-scopes").resolve("pgpony.db")
        seed(file)
        val c = BundledSQLiteDriver().open(file.toAbsolutePath().toString())
        try {
            c.execSQL(
                "INSERT INTO `allowed_api_clients` (`packageName`, `signatureSha256`, `grantedAt`, `scopes`) " +
                    "VALUES ('org.example.mail', 'aa', 1, 1)"
            )
        } finally {
            c.close()
        }
        downgrade(file, 9)
        val db = Db.open(file)
        try {
            runBlocking {
                val row = db.apiClientDao().getAll().single()
                assertEquals(ApiClientEntity.SCOPE_OPENPGP, row.scopes)
            }
        } finally {
            db.close()
        }
    }
}
