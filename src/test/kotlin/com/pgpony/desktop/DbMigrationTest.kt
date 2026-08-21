// DbMigrationTest.kt
// PGPony Desktop — issue #3: prove the v7 -> v9 desktop migrations run the expected SQL.
// Applies DESKTOP_MIGRATION_7_8 / _8_9 to a stand-in v7 database and checks the new tables and
// columns appear. The full Room open-and-validate path is exercised by upgrading a real 2.0.0
// database, kept in the manual release checklist.

package com.pgpony.desktop

import androidx.sqlite.SQLiteConnection
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import androidx.sqlite.execSQL
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertTrue

class DbMigrationTest {

    private fun tableExists(c: SQLiteConnection, name: String): Boolean {
        val st = c.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
        st.bindText(1, name)
        val found = st.step()
        st.close()
        return found
    }

    private fun columnExists(c: SQLiteConnection, table: String, col: String): Boolean {
        val st = c.prepare("PRAGMA table_info(`$table`)")
        var found = false
        while (st.step()) { if (st.getText(1) == col) { found = true; break } }
        st.close()
        return found
    }

    @Test
    fun migration7to9AddsTablesAndColumns() {
        val dir = Files.createTempDirectory("pgpony-mig")
        val conn = BundledSQLiteDriver().open(dir.resolve("v7.db").toAbsolutePath().toString())
        try {
            // Minimal stand-in for the v7 pgp_keys table; the 8->9 migration only ALTERs it.
            conn.execSQL("CREATE TABLE `pgp_keys` (`id` TEXT NOT NULL, `fingerprint` TEXT NOT NULL, PRIMARY KEY(`id`))")
            conn.execSQL("PRAGMA user_version = 7")

            DESKTOP_MIGRATION_7_8.migrate(conn)
            DESKTOP_MIGRATION_8_9.migrate(conn)

            assertTrue(tableExists(conn, "fallback_keys"), "fallback_keys created")
            assertTrue(tableExists(conn, "signing_defaults"), "signing_defaults created")
            assertTrue(columnExists(conn, "pgp_keys", "deletedAt"), "deletedAt added")
            assertTrue(columnExists(conn, "pgp_keys", "lastBackedUpAt"), "lastBackedUpAt added")
        } finally {
            conn.close()
        }
    }
}
