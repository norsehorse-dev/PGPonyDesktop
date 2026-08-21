// DbMigrations.kt
// PGPony Desktop — issue #3: 2.0.0 -> 2.1.0 upgrade crash
// ("A migration from 7 to 9 was required but not found").
//
// Desktop 2.0.0 created its database at schema v7. 2.1.0 vendored the Android 4.3.0 data
// layer, which bumped @Database(version = 9) by adding the fallback-keys / signing-defaults
// tables (7 -> 8) and the recycle-bin columns deletedAt / lastBackedUpAt on pgp_keys (8 -> 9).
// The Android migrations in data/RoomMigrations.kt use migrate(db: SupportSQLiteDatabase), the
// Android-only Room API, so they cannot run under the desktop's KMP Room (which calls
// migrate(connection: SQLiteConnection)). Db.kt therefore registered no migrations, and a fresh
// v9 install worked while any existing v7 database failed to open.
//
// These KMP-form migrations run the identical SQL as the Android originals, so an existing v7
// desktop database upgrades cleanly to v9. Every desktop database ever created is v7 (see Db.kt),
// so the 7 -> 8 -> 9 pair is the whole chain the desktop can encounter.

package com.pgpony.desktop

import androidx.room.migration.Migration
import androidx.sqlite.SQLiteConnection
import androidx.sqlite.execSQL

val DESKTOP_MIGRATION_7_8 = object : Migration(7, 8) {
    override fun migrate(connection: SQLiteConnection) {
        connection.execSQL(
            "CREATE TABLE IF NOT EXISTS `fallback_keys` (" +
                "`primaryFingerprint` TEXT NOT NULL, " +
                "`fallbackFingerprint` TEXT NOT NULL, " +
                "`position` INTEGER NOT NULL, " +
                "PRIMARY KEY(`primaryFingerprint`, `fallbackFingerprint`))"
        )
        connection.execSQL(
            "CREATE TABLE IF NOT EXISTS `signing_defaults` (" +
                "`fingerprint` TEXT NOT NULL, " +
                "`pqcSignerFingerprint` TEXT, " +
                "`classicalSignerFingerprint` TEXT, " +
                "`signOnlySignerFingerprint` TEXT, " +
                "PRIMARY KEY(`fingerprint`))"
        )
    }
}

val DESKTOP_MIGRATION_8_9 = object : Migration(8, 9) {
    override fun migrate(connection: SQLiteConnection) {
        connection.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `deletedAt` INTEGER")
        connection.execSQL("ALTER TABLE `pgp_keys` ADD COLUMN `lastBackedUpAt` INTEGER")
    }
}
