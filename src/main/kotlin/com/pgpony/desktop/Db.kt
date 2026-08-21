// Db.kt
// PGPony Desktop — Room database bootstrap (D2a).
//
// Opens the SAME PGPDatabase the Android app ships (vendored data/PGPKeyEntity.kt: entities,
// DAOs, schema v9) on the JVM via Room KMP + the bundled SQLite driver. Fresh desktop databases
// create directly at v9. Existing v7 databases (desktop 2.0.0) upgrade through the KMP-form
// migrations in DbMigrations.kt: the Android chain in data/RoomMigrations.kt uses the Android-only
// SupportSQLiteDatabase API and cannot run here, so DESKTOP_MIGRATION_7_8 / _8_9 run the identical
// SQL (issue #3: "A migration from 7 to 9 was required but not found").

package com.pgpony.desktop

import androidx.room.Room
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import com.pgpony.android.data.PGPDatabase
import kotlinx.coroutines.Dispatchers
import java.nio.file.Path

object Db {
    fun open(dbFile: Path): PGPDatabase =
        Room.databaseBuilder<PGPDatabase>(name = dbFile.toAbsolutePath().toString())
            .setDriver(BundledSQLiteDriver())
            .setQueryCoroutineContext(Dispatchers.IO)
            .addMigrations(DESKTOP_MIGRATION_7_8, DESKTOP_MIGRATION_8_9)
            .build()
}
