// Db.kt
// PGPony Desktop — Room database bootstrap (D2a).
//
// Opens the SAME PGPDatabase the Android app ships (vendored data/PGPKeyEntity.kt: entities,
// DAOs, schema v12 since 3.0.0) on the JVM via Room KMP + the bundled SQLite driver. Fresh
// desktop databases create directly at the current version. Existing v7 (2.0.0) and v9 (2.1.x)
// databases upgrade through the KMP-form migrations in DbMigrations.kt: the Android chain in data/RoomMigrations.kt uses the Android-only
// SupportSQLiteDatabase API and cannot run here, so DESKTOP_MIGRATION_7_8 / _8_9 run the identical
// SQL (issue #3: "A migration from 7 to 9 was required but not found").
//
// 3.0.0: the database file is created owner-only (0600) before SQLite opens it, and an existing
// one is set so at every open. SQLite gives its -wal, -shm and -journal files the mode of the
// database file, and any left from an older version are set owner-only here as well. Deleted
// rows are overwritten in place (secure_delete) and [compact] rewrites the file after a purge,
// so removed keys, notes and revocation certificates do not linger in free pages.

package com.pgpony.desktop

import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.useWriterConnection
import androidx.sqlite.SQLiteConnection
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import androidx.sqlite.execSQL
import com.pgpony.android.data.PGPDatabase
import kotlinx.coroutines.Dispatchers
import java.nio.file.Path

object Db {

    /** SQLite's companion files beside the database. */
    private val SIDE_FILES = listOf("-wal", "-shm", "-journal")

    fun open(dbFile: Path): PGPDatabase {
        secureFiles(dbFile)
        return Room.databaseBuilder<PGPDatabase>(name = dbFile.toAbsolutePath().toString())
            .setDriver(BundledSQLiteDriver())
            .setQueryCoroutineContext(Dispatchers.IO)
            .addMigrations(
                DESKTOP_MIGRATION_7_8, DESKTOP_MIGRATION_8_9,
                // 3.0.0: Android 4.6.0's 9 -> 12.
                DESKTOP_MIGRATION_9_10, DESKTOP_MIGRATION_10_11, DESKTOP_MIGRATION_11_12
            )
            .addCallback(object : RoomDatabase.Callback() {
                override fun onOpen(connection: SQLiteConnection) {
                    runCatching { connection.execSQL("PRAGMA secure_delete = ON") }
                }
            })
            .build()
    }

    /** The database and its companion files owner-only; the database created so when new. */
    internal fun secureFiles(dbFile: Path) {
        OwnerOnlyPaths.ensureFile(dbFile)
        for (suffix in SIDE_FILES) {
            OwnerOnlyPaths.restrict(dbFile.resolveSibling(dbFile.fileName.toString() + suffix))
        }
    }

    /**
     * After keys were purged: overwrite freed content (secure_delete on the writer connection),
     * rewrite the file without free pages, and fold the write-ahead log back in and truncate it.
     * Best effort: a failure leaves the database as it was.
     */
    suspend fun compact(db: PGPDatabase) {
        runCatching {
            db.useWriterConnection { conn ->
                conn.usePrepared("PRAGMA secure_delete = ON") { it.step() }
                conn.usePrepared("VACUUM") { it.step() }
                conn.usePrepared("PRAGMA wal_checkpoint(TRUNCATE)") { it.step() }
            }
        }
    }
}
