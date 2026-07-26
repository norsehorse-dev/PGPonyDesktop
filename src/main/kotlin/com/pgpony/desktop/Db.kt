// Db.kt
// PGPony Desktop — Room database bootstrap (D2a).
//
// Opens the SAME PGPDatabase the Android app ships (vendored data/PGPKeyEntity.kt: entities,
// DAOs, schema v7) on the JVM via Room KMP + the bundled SQLite driver. Fresh desktop databases
// create directly at v7, so the Android migration chain (data/RoomMigrations.kt, an Android-only
// API surface) is not registered here; future desktop schema bumps join the shared chain with
// KMP-style migrations.

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
            .build()
}
